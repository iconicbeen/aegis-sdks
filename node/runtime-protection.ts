/**
 * Runtime protection policy.
 *
 * Decides what an in-app firewall does with a request: allow, log, or block.
 * Pure, so the decision can be tested exhaustively — an in-path component that
 * blocks wrongly takes a production application down, which is a worse outcome
 * than the attack it prevented.
 *
 * Three principles run through this. Blocking is opt-in per rule and per
 * endpoint. Anything uncertain logs rather than blocks. And every decision
 * carries why, because an engineer looking at a blocked request at 3am needs
 * to know in seconds whether to disable the rule.
 */

export type ProtectionMode = "off" | "monitor" | "block";

export type EndpointOverride = {
  /** Glob against the request path. */
  pattern: string;
  mode: ProtectionMode;
  /** Rules exempted on this endpoint, by id. */
  exemptRules?: string[];
  reason: string;
};

export type ProtectionPolicy = {
  /** What happens when no override matches. */
  defaultMode: ProtectionMode;
  overrides: EndpointOverride[];
  /** Rules that may block, when the mode permits it. */
  blockingRules: string[];
  /** Requests per minute per client before rate limiting applies. */
  rateLimitPerMinute: number | null;
  /** Bot categories to block outright. */
  blockedBotCategories: string[];
  /**
   * Whether the application can issue a proof-of-work challenge.
   *
   * Off by default: an SDK that starts challenging visitors because a flag
   * defaulted to true would be a change in what the customer's users see,
   * made by us. The host application opts in by mounting the challenge
   * endpoints, and says so here.
   */
  challengeAvailable?: boolean;
};

export const DEFAULT_PROTECTION_POLICY: ProtectionPolicy = {
  // Monitor, never block, until an operator decides otherwise. Shipping a
  // default that blocks means the first thing an in-app firewall does is
  // break somebody's checkout.
  defaultMode: "monitor",
  overrides: [],
  blockingRules: [],
  rateLimitPerMinute: null,
  blockedBotCategories: [],
  challengeAvailable: false,
};

export type RequestContext = {
  method: string;
  path: string;
  /** Truncated to a network prefix upstream; never a full address. */
  clientPrefix: string;
  userAgent: string;
  /** Present once the application has authenticated the request. */
  userId: string | null;
  /** Rule ids that matched, from the detection engine. */
  matchedRules: { id: string; severity: string; category: string }[];
  botCategory: string | null;
  /** Requests seen from this client in the current minute. */
  requestsThisMinute: number;
};

export type ProtectionDecision = {
  /**
   * `challenge` sits between log and block: the request is not served, but
   * the client is offered a proof of work it can solve to continue.
   *
   * It exists because the rate-limit branch had only two honest options for a
   * client that is probably a scraper and possibly a customer: serve it, or
   * refuse a paying visitor. A challenge costs an automated client CPU per
   * request and a person one imperceptible pause.
   */
  action: "allow" | "log" | "block" | "challenge";
  /** Phrased so an engineer can decide in seconds whether to disable a rule. */
  reason: string;
  /** The rule that drove the decision. */
  ruleId: string | null;
  /** The override that applied, when one did. */
  appliedOverride: string | null;
};

/** Anchored glob. Only `*` is supported, so a pattern cannot backtrack. */
export function pathMatches(path: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(path);
}

/** The mode in force for a path, and why. */
export function modeForPath(
  policy: ProtectionPolicy,
  path: string,
): { mode: ProtectionMode; override: EndpointOverride | null } {
  // The most specific override wins, measured by pattern length, so a rule
  // for `/api/webhooks/stripe` beats one for `/api/*`.
  const matching = policy.overrides
    .filter((o) => pathMatches(path, o.pattern))
    .sort((a, b) => b.pattern.length - a.pattern.length);

  return matching.length > 0
    ? { mode: matching[0]!.mode, override: matching[0]! }
    : { mode: policy.defaultMode, override: null };
}

/**
 * Decides what to do with a request.
 *
 * Every path that could block is explicit, and everything else falls through
 * to allow. An in-path component whose default branch blocks is one outage
 * away from being removed entirely.
 */
export function decide(policy: ProtectionPolicy, request: RequestContext): ProtectionDecision {
  const { mode, override } = modeForPath(policy, request.path);

  if (mode === "off") {
    return {
      action: "allow",
      reason: override
        ? `Protection is disabled for ${override.pattern}: ${override.reason}`
        : "Protection is disabled.",
      ruleId: null,
      appliedOverride: override?.pattern ?? null,
    };
  }

  const exempt = new Set(override?.exemptRules ?? []);
  const applicable = request.matchedRules.filter((r) => !exempt.has(r.id));

  // Rate limiting is checked before rules: a client sending thousands of
  // requests is a problem regardless of whether any of them match a pattern.
  if (
    policy.rateLimitPerMinute !== null &&
    request.requestsThisMinute > policy.rateLimitPerMinute
  ) {
    return {
      /**
       * Challenge rather than block, when a challenge is available.
       *
       * A rate limit catches a scraper and a customer refreshing a page in
       * the same net, and blocking the second to stop the first is the
       * expensive mistake. Blocking still happens above the limit when no
       * challenge is configured, because the alternative is serving traffic
       * the operator asked to stop.
       */
      action: mode === "block" ? (policy.challengeAvailable ? "challenge" : "block") : "log",
      reason: `${request.requestsThisMinute} requests in the last minute from ${request.clientPrefix}, over the limit of ${policy.rateLimitPerMinute}.`,
      ruleId: "rate-limit",
      appliedOverride: override?.pattern ?? null,
    };
  }

  if (request.botCategory && policy.blockedBotCategories.includes(request.botCategory)) {
    return {
      action: mode === "block" ? "block" : "log",
      reason: `Client identifies as ${request.botCategory}, which policy blocks.`,
      ruleId: "bot-policy",
      appliedOverride: override?.pattern ?? null,
    };
  }

  if (applicable.length === 0) {
    return {
      action: "allow",
      reason:
        request.matchedRules.length > 0
          ? `${request.matchedRules.length} rule(s) matched but are exempted on this endpoint.`
          : "No rule matched.",
      ruleId: null,
      appliedOverride: override?.pattern ?? null,
    };
  }

  // Highest severity first, so the reason names the worst thing found.
  const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const worst = [...applicable].sort(
    (a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0),
  )[0]!;

  // Blocking requires both the endpoint mode and the rule being on the
  // blocking list: a rule is never enabled to block by being severe.
  const mayBlock = mode === "block" && policy.blockingRules.includes(worst.id);

  return {
    action: mayBlock ? "block" : "log",
    reason: mayBlock
      ? `Blocked: ${worst.id} (${worst.severity} ${worst.category}) matched and is enabled for blocking.`
      : `${worst.id} (${worst.severity} ${worst.category}) matched. ${
          mode === "block"
            ? "Not blocked: the rule is not on the blocking list."
            : "Endpoint is in monitor mode, so the request was allowed."
        }`,
    ruleId: worst.id,
    appliedOverride: override?.pattern ?? null,
  };
}

// ---------------------------------------------------------------------------
// User-level attribution
// ---------------------------------------------------------------------------

export type AttackAttribution = {
  subject: string;
  subjectKind: "user" | "client";
  events: number;
  distinctRules: string[];
  distinctPaths: number;
  firstSeen: string;
  lastSeen: string;
  /** Whether the pattern justifies action against the subject. */
  confident: boolean;
  assessment: string;
};

/**
 * Attributes attack activity to a user or client.
 *
 * Deliberately conservative about confidence. Blocking a signed-in user is a
 * serious action, and a single matched rule is far more likely to be a scanner
 * someone pointed at the site, or a false positive, than a hostile account.
 */
export function attribute(
  events: {
    userId: string | null;
    clientPrefix: string;
    ruleId: string;
    path: string;
    at: string;
  }[],
): AttackAttribution[] {
  const groups = new Map<string, typeof events>();

  for (const event of events) {
    // Attributed to the user when known, since an address is shared by a
    // whole office behind NAT and blocking it blocks everyone.
    const key = event.userId ? `user:${event.userId}` : `client:${event.clientPrefix}`;
    groups.set(key, [...(groups.get(key) ?? []), event]);
  }

  return [...groups.entries()]
    .map(([key, group]) => {
      const [kind, subject] = key.split(":") as ["user" | "client", string];
      const rules = [...new Set(group.map((e) => e.ruleId))];
      const paths = new Set(group.map((e) => e.path)).size;
      const times = group.map((e) => e.at).sort();

      // Several distinct rules across several paths is probing. One rule on
      // one path is far more likely to be noise.
      const confident = rules.length >= 3 && paths >= 3;

      return {
        subject,
        subjectKind: kind,
        events: group.length,
        distinctRules: rules,
        distinctPaths: paths,
        firstSeen: times[0]!,
        lastSeen: times.at(-1)!,
        confident,
        assessment: confident
          ? `${group.length} event(s) across ${rules.length} distinct rule(s) and ${paths} path(s): a deliberate probe rather than a single mistake.`
          : `${group.length} event(s) across ${rules.length} rule(s) and ${paths} path(s). Too narrow to act on: this pattern is as consistent with a scanner or a false positive as with an attacker.`,
      };
    })
    .sort((a, b) => b.events - a.events);
}

// ---------------------------------------------------------------------------
// Anomaly baselining
// ---------------------------------------------------------------------------

export type Baseline = {
  metric: string;
  /** Mean over the observation window. */
  mean: number;
  /** Population standard deviation. */
  stdDev: number;
  samples: number;
  /** Whether the baseline rests on enough data to compare against. */
  established: boolean;
};

/**
 * Builds a baseline from historical samples.
 *
 * Refuses to establish one from too few points. An alert threshold derived
 * from three samples fires constantly, and a monitoring system that cries wolf
 * is turned off within a week.
 */
export function buildBaseline(metric: string, samples: number[]): Baseline {
  if (samples.length === 0) {
    return { metric, mean: 0, stdDev: 0, samples: 0, established: false };
  }

  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  const variance = samples.reduce((sum, s) => sum + (s - mean) ** 2, 0) / samples.length;

  return {
    metric,
    mean: Math.round(mean * 100) / 100,
    stdDev: Math.round(Math.sqrt(variance) * 100) / 100,
    samples: samples.length,
    // Two weeks of daily samples is the minimum that captures a weekly cycle.
    established: samples.length >= 14,
  };
}

export type AnomalyResult = {
  anomalous: boolean;
  /** How many standard deviations from the mean. */
  zScore: number;
  explanation: string;
};

/**
 * Compares an observation against a baseline.
 *
 * Three sigma rather than two: at two sigma roughly one observation in twenty
 * is flagged, which for a metric sampled hourly is an alert every day from
 * normal variation alone.
 */
export function detectAnomaly(baseline: Baseline, observed: number, threshold = 3): AnomalyResult {
  if (!baseline.established) {
    return {
      anomalous: false,
      zScore: 0,
      explanation: `No baseline for ${baseline.metric} yet (${baseline.samples} of 14 samples). Nothing can be called anomalous without one.`,
    };
  }

  if (baseline.stdDev === 0) {
    // A perfectly flat metric makes every deviation infinitely significant,
    // which is arithmetically true and operationally useless.
    const changed = observed !== baseline.mean;
    return {
      anomalous: changed,
      zScore: changed ? Infinity : 0,
      explanation: changed
        ? `${baseline.metric} has been exactly ${baseline.mean} for ${baseline.samples} samples and is now ${observed}.`
        : `${baseline.metric} is unchanged at ${baseline.mean}.`,
    };
  }

  const zScore = Math.round(((observed - baseline.mean) / baseline.stdDev) * 100) / 100;
  const anomalous = Math.abs(zScore) >= threshold;

  return {
    anomalous,
    zScore,
    explanation: anomalous
      ? `${baseline.metric} is ${observed}, ${Math.abs(zScore)} standard deviations ${zScore > 0 ? "above" : "below"} the mean of ${baseline.mean}.`
      : `${baseline.metric} is ${observed}, within normal variation (mean ${baseline.mean}, ${Math.abs(zScore)} sigma).`,
  };
}

// ---------------------------------------------------------------------------
// Agent health
// ---------------------------------------------------------------------------

export type AgentHealth = {
  status: "healthy" | "stale" | "never_reported";
  /** True when the agent is running an old build. */
  outdated: boolean;
  message: string;
};

/**
 * Assesses whether an agent is actually protecting anything.
 *
 * An agent that stopped reporting is the case that matters: the dashboard
 * still lists it, so the application looks protected while nothing is
 * inspecting its traffic.
 */
export function assessAgentHealth(input: {
  lastSeen: string | null;
  version: string;
  latestVersion: string;
  staleAfterMinutes?: number;
  now?: Date;
}): AgentHealth {
  const now = input.now ?? new Date();
  const staleAfter = (input.staleAfterMinutes ?? 15) * 60_000;
  const outdated = input.version !== input.latestVersion;

  if (!input.lastSeen) {
    return {
      status: "never_reported",
      outdated,
      message:
        "This agent has never reported. The application it was installed in is not being inspected.",
    };
  }

  const age = now.getTime() - Date.parse(input.lastSeen);
  if (age > staleAfter) {
    const minutes = Math.round(age / 60_000);
    return {
      status: "stale",
      outdated,
      // Stated plainly: a listed-but-silent agent is worse than no agent,
      // because it creates the appearance of coverage.
      message: `No report for ${minutes} minute(s). Traffic to this application is not being inspected, even though the agent is still listed.`,
    };
  }

  return {
    status: "healthy",
    outdated,
    message: outdated
      ? `Reporting normally, but running ${input.version} rather than ${input.latestVersion}. Newer detection rules are not in effect.`
      : `Reporting normally on ${input.version}.`,
  };
}
