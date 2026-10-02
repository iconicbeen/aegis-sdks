/**
 * Aegis in-app firewall for Node.
 *
 * Express-compatible middleware that inspects requests, reports what it saw,
 * and optionally blocks. Deliberately small: it sits in the request path of
 * somebody's production application, and every line here is a line that can
 * take that application down.
 *
 * Four properties follow from that. It never blocks unless explicitly
 * configured to. It never throws into the request path — an error inside the
 * firewall passes the request through rather than returning a 500. It reports
 * asynchronously so latency is unaffected. And it holds no unbounded state.
 */

import { issueChallenge, verifyChallenge } from "./bot-challenge";
import { DEFAULT_PROTECTION_POLICY, decide, type ProtectionPolicy } from "./runtime-protection";

export type AegisConfig = {
  /** Control plane base URL. */
  url: string;
  /** API token with `runtime:report`. */
  token: string;
  /** Identifies this application in the console. */
  appName: string;
  /**
   * Blocking is opt-in. The default reports without interfering, so
   * installing the SDK cannot itself cause an outage.
   */
  mode?: "monitor" | "block";
  /**
   * Per-endpoint protection policy. Only consulted when `mode` is `"block"`;
   * in monitor mode nothing blocks regardless of what this says.
   */
  policy?: ProtectionPolicy;
  /** Paths never inspected, e.g. health checks. */
  exclude?: string[];
  /** Seconds between report flushes. */
  flushIntervalSeconds?: number;
  /** Called instead of throwing, so failures are visible but harmless. */
  onError?: (error: Error) => void;
  /**
   * Secret for signing proof-of-work challenges.
   *
   * Supplying it is what turns a rate-limit block into a challenge: a client
   * over the limit is offered work it can do to continue, rather than a 403
   * that also refuses the customer who was refreshing a page. Without it the
   * behaviour is unchanged, because a challenge nobody can verify is worse
   * than none.
   *
   * Any random string the application keeps to itself. It never leaves the
   * process; only the signature does.
   */
  challengeSecret?: string;
};

type MinimalRequest = {
  method?: string;
  url?: string;
  path?: string;
  headers?: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  body?: unknown;
  user?: { id?: string };
};

type MinimalResponse = {
  statusCode?: number;
  setHeader?: (name: string, value: string) => void;
  end?: (body?: string) => void;
};

export type DetectionEvent = {
  at: string;
  method: string;
  path: string;
  ruleId: string;
  severity: string;
  clientPrefix: string;
  userAgent: string;
  userId: string | null;
  blocked: boolean;
  /** Why the decision went the way it did, recorded at the time. */
  reason: string;
};

/**
 * Patterns matched against request input.
 *
 * Deliberately conservative. A false positive here blocks a real user, so
 * each pattern targets syntax that has no legitimate reason to appear in a
 * parameter value, rather than merely suspicious words.
 */
const RULES: { id: string; severity: string; pattern: RegExp }[] = [
  {
    id: "sqli-union",
    severity: "critical",
    // UNION followed by SELECT is not something a search box sends.
    pattern: /\bunion\b[\s\S]{0,40}\bselect\b/i,
  },
  {
    id: "sqli-tautology",
    severity: "high",
    // `' OR '1'='1` and its variants, requiring the quote structure so that
    // the phrase "1=1" in ordinary text does not match.
    pattern: /['"]\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  },
  {
    id: "path-traversal",
    severity: "high",
    // Encoded and literal forms of ../
    pattern: /(\.\.[/\\]){2,}|%2e%2e[/\\%]/i,
  },
  {
    id: "command-injection",
    severity: "critical",
    // A shell metacharacter immediately followed by a known binary.
    pattern: /[;|&`$]\s*(cat|curl|wget|nc|bash|sh|python|perl)\b/i,
  },
  {
    id: "xss-script",
    severity: "high",
    pattern: /<script[\s>]|javascript:\s*[a-z]|\bonerror\s*=/i,
  },
  {
    id: "ssrf-metadata",
    severity: "critical",
    // The cloud metadata endpoints, which a user parameter never needs.
    pattern: /169\.254\.169\.254|metadata\.google\.internal/i,
  },
];

/** Truncates an address, so the SDK never reports a full client IP. */
function clientPrefix(address: string | undefined): string {
  if (!address) return "unknown";
  const clean = address.replace(/^::ffff:/, "");
  if (clean.includes(":")) return `${clean.split(":").slice(0, 3).join(":")}::`;
  const octets = clean.split(".");
  return octets.length === 4 ? `${octets.slice(0, 3).join(".")}.0` : "unknown";
}

/** Flattens request input into the strings worth inspecting. */
function inspectable(request: MinimalRequest): string[] {
  const parts: string[] = [];
  if (request.url) parts.push(decodeSafely(request.url));

  const body = request.body;
  if (typeof body === "string") parts.push(body.slice(0, 10_000));
  else if (body && typeof body === "object") {
    // Bounded: a deeply nested body must not turn inspection into a stack
    // overflow inside somebody's request path.
    parts.push(JSON.stringify(body).slice(0, 10_000));
  }

  // Headers an attacker controls and applications commonly trust.
  for (const header of ["referer", "x-forwarded-for", "user-agent"]) {
    const value = request.headers?.[header];
    if (typeof value === "string") parts.push(value.slice(0, 2000));
  }
  return parts;
}

/** Decoding can throw on malformed input; the raw value is still worth checking. */
function decodeSafely(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export type AegisMiddleware = {
  /**
   * Returns a promise, which Express and Connect ignore.
   *
   * It became async when challenges arrived: issuing and verifying a proof of
   * work are both crypto operations. Frameworks call this and move on, which
   * is fine because the middleware either calls `next()` or answers the
   * request itself in every path, including its error handler.
   */
  (request: MinimalRequest, response: MinimalResponse, next: () => void): void | Promise<void>;
  /** Flushes pending events and stops the timer. */
  close: () => Promise<void>;
};

/**
 * Creates the middleware.
 *
 * Every failure mode inside is caught and passed to `onError`, then the
 * request continues. A security control that turns a working application into
 * a 500 is worse than the attack it was inspecting for.
 */
export function aegis(config: AegisConfig): AegisMiddleware {
  const mode = config.mode ?? "monitor";

  // The `mode` flag sets the floor and the policy refines it. `monitor` can
  // never be escalated to blocking by a policy, so the two opt-ins that
  // blocking requires stay two.
  const policy: ProtectionPolicy =
    mode === "block"
      ? (config.policy ?? {
          ...DEFAULT_PROTECTION_POLICY,
          defaultMode: "block",
          // Without this, `mode: "block"` would quietly block nothing: the
          // shared default carries no blocking rules on purpose, since a
          // policy stored server-side must not block until someone enables
          // a rule. Here the caller has already asked for blocking, so every
          // rule the SDK can detect is eligible.
          blockingRules: RUNTIME_RULES.map((rule) => rule.id),
        })
      : { ...DEFAULT_PROTECTION_POLICY, defaultMode: "monitor", overrides: [] };
  const exclude = config.exclude ?? ["/health", "/healthz", "/readyz", "/metrics"];
  const challengeSecret = config.challengeSecret ?? null;

  // The policy learns whether a challenge is possible from the same fact the
  // middleware uses, so the decision and the enforcement cannot disagree.
  if (challengeSecret) policy.challengeAvailable = true;
  const onError = config.onError ?? (() => {});

  // Bounded, so a sustained attack cannot exhaust memory in the host
  // application while the control plane is unreachable.
  const MAX_QUEUE = 1000;
  let queue: DetectionEvent[] = [];

  /**
   * Requests per client prefix in the current minute.
   *
   * This existed as policy and not as fact: `decide()` compares
   * `requestsThisMinute` against `rateLimitPerMinute`, and the SDK passed a
   * hardcoded 0 -- measured with 200 requests from one address, the limit
   * branch never fired. A policy field that reads as "rate limiting: 100/min"
   * while nothing counts is worse than no field, because an operator relies
   * on it.
   *
   * Keyed by the same truncated prefix the events report, for the same
   * reason: the SDK holds no full client addresses. Bounded and reset each
   * minute, so a scan across many prefixes cannot grow memory without limit.
   * Identity-based limiting stays out deliberately: inside the application
   * the framework already knows the caller, but `request.user` is populated
   * by upstream middleware this SDK cannot vouch for, and a limit keyed to an
   * attacker-controlled field is a free rotation. The WAF, which owns a
   * trusted-proxy boundary, is where per-user limits live.
   */
  const MAX_TRACKED_PREFIXES = 10_000;
  let counts = new Map<string, number>();
  let windowStartedAt = Date.now();

  function requestsThisMinute(prefix: string): number {
    const now = Date.now();
    if (now - windowStartedAt >= 60_000) {
      counts = new Map();
      windowStartedAt = now;
    }
    const seen = (counts.get(prefix) ?? 0) + 1;
    if (counts.size < MAX_TRACKED_PREFIXES || counts.has(prefix)) counts.set(prefix, seen);
    return seen;
  }

  const flush = async (): Promise<void> => {
    if (queue.length === 0) return;
    const batch = queue;
    queue = [];
    try {
      await fetch(`${config.url.replace(/\/+$/, "")}/api/public/runtime/events`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${config.token}`,
        },
        body: JSON.stringify({ app: config.appName, events: batch }),
        signal: AbortSignal.timeout(10_000),
      });
    } catch (error) {
      // Dropped rather than retried indefinitely: the application's memory
      // matters more than these events.
      onError(error as Error);
    }
  };

  const timer = setInterval(() => void flush(), (config.flushIntervalSeconds ?? 30) * 1000);
  // Never hold the process open on the SDK's account.
  if (typeof timer === "object" && "unref" in timer) timer.unref();

  const middleware = (async (request, response, next) => {
    try {
      const path = request.path ?? (request.url ?? "").split("?")[0] ?? "/";
      if (exclude.some((p) => path === p || path.startsWith(`${p}/`))) {
        next();
        return;
      }

      // Counted for every request past the exclusions, not only for matches:
      // a flood of clean requests is exactly what a rate limit is for.
      const prefix = clientPrefix(request.socket?.remoteAddress);
      const minuteCount = requestsThisMinute(prefix);

      const inputs = inspectable(request);
      const matched = RULES.filter((rule) => inputs.some((input) => rule.pattern.test(input)));

      const limit = policy.rateLimitPerMinute;
      if (matched.length === 0 && (limit === null || minuteCount <= limit)) {
        next();
        return;
      }

      // With no pattern match this request is here because the limit tripped,
      // and the event should say so rather than crash on matched[0].
      const worst = matched.find((r) => r.severity === "critical") ??
        matched[0] ?? { id: "rate-limit", severity: "medium" };

      // The policy decides, not the mode flag alone. A single global switch
      // means the only way to stop blocking one endpoint that misfires is to
      // stop blocking everywhere, which is how a firewall ends up disabled.
      const decision = decide(policy, {
        method: request.method ?? "GET",
        path,
        clientPrefix: clientPrefix(request.socket?.remoteAddress),
        userAgent: String(request.headers?.["user-agent"] ?? "").slice(0, 300),
        userId: request.user?.id ?? null,
        matchedRules: matched.map((r) => ({
          id: r.id,
          severity: r.severity,
          category: r.id.split("-")[0] ?? "unknown",
        })),
        botCategory: null,
        requestsThisMinute: minuteCount,
      });
      const shouldBlock = decision.action === "block";
      const shouldChallenge = decision.action === "challenge";

      if (queue.length < MAX_QUEUE) {
        queue.push({
          at: new Date().toISOString(),
          method: request.method ?? "GET",
          path,
          ruleId: worst.id,
          severity: worst.severity,
          clientPrefix: clientPrefix(request.socket?.remoteAddress),
          userAgent: String(request.headers?.["user-agent"] ?? "").slice(0, 300),
          userId: request.user?.id ?? null,
          blocked: shouldBlock,
          // Why, in the record itself. Reconstructing a decision from policy
          // after the fact is guesswork once the policy has changed.
          reason: decision.reason,
        });
      }

      if (shouldBlock) {
        response.statusCode = 403;
        response.setHeader?.("content-type", "application/json");
        // Deliberately terse: naming the rule would tell an attacker exactly
        // what to change.
        response.end?.(JSON.stringify({ error: "Request rejected." }));
        return;
      }

      /**
       * A solved challenge lets the request through.
       *
       * Checked here rather than before the decision so the request is still
       * scored and reported: a client that solved a challenge is still worth
       * recording, and skipping the decision would hide it from the console.
       *
       * The solution proves work against a challenge this process signed. It
       * proves nothing about who is sending it, which is why it only lifts a
       * rate-limit challenge and never a block.
       */
      if (shouldChallenge && challengeSecret) {
        const header = request.headers?.["x-aegis-solution"];
        const raw = Array.isArray(header) ? header[0] : header;

        if (typeof raw === "string" && raw.length > 0 && raw.length < 4_000) {
          try {
            const [encoded, solution] = raw.split(".");
            const claimed = JSON.parse(
              Buffer.from(String(encoded), "base64url").toString("utf8"),
            ) as Parameters<typeof verifyChallenge>[1];

            const verdict = await verifyChallenge(challengeSecret, claimed, String(solution));
            if (verdict.ok) {
              next();
              return;
            }
          } catch {
            // A malformed header is treated as no header: the client gets a
            // fresh challenge rather than an error explaining how to format
            // one correctly.
          }
        }
      }

      if (shouldChallenge && challengeSecret) {
        /**
         * 429 with a challenge, not 403.
         *
         * The client is over a rate limit and may well be a customer
         * refreshing a page. 429 says "slow down and try again", which is
         * true, and carries the work that lets an honest client continue
         * immediately rather than waiting out a window.
         *
         * The proof of work is issued inline so the SDK needs no storage: the
         * challenge is signed, so verifying it later requires only the
         * secret.
         */
        const challenge = await issueChallenge(challengeSecret);

        // The whole challenge, encoded, so the client returns it verbatim
        // rather than reassembling it. The server keeps nothing: the
        // signature is what makes the returned copy trustworthy.
        const token = Buffer.from(JSON.stringify(challenge), "utf8").toString("base64url");

        response.statusCode = 429;
        response.setHeader?.("content-type", "application/json");
        response.setHeader?.("retry-after", "1");
        response.end?.(
          JSON.stringify({
            error: "Additional verification is required before this request can continue.",
            challenge: {
              token,
              nonce: challenge.nonce,
              difficulty: challenge.difficulty,
              ttlMs: challenge.ttlMs,
            },
            // Said plainly: this is a cost, not a test of humanity, and an
            // integrator who believes otherwise will deploy it wrongly.
            hint: "Find a value whose SHA-256 of `nonce:value` starts with `difficulty` zero bits, then resend with header `x-aegis-solution: <token>.<value>`.",
          }),
        );
        return;
      }

      next();
    } catch (error) {
      // The request continues regardless.
      onError(error as Error);
      next();
    }
  }) as AegisMiddleware;

  middleware.close = async () => {
    clearInterval(timer);
    await flush();
  };

  return middleware;
}

/** Exposed so the rule set can be tested and audited. */
export const RUNTIME_RULES = RULES;

/**
 * The default policy and its type, so a consumer can override one field
 * (`{ ...DEFAULT_PROTECTION_POLICY, overrides: [...] }`) without restating the
 * rest. The README's blocking example is written that way and type-checked
 * against the built package.
 */
export { DEFAULT_PROTECTION_POLICY };
export type { ProtectionPolicy, EndpointOverride } from "./runtime-protection";
