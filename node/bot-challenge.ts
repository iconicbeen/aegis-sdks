/**
 * A challenge that costs the client something and the site nothing.
 *
 * `bot-defence.ts` has always been able to reach a `challenge` verdict and
 * has always downgraded it to a throttle, because nothing existed to
 * challenge with. Throttling is the honest fallback and a poor substitute: it
 * slows a scraper that does not care and annoys a customer who does.
 *
 * The mechanism is a hashcash-style proof of work. The reasons for choosing
 * it over a CAPTCHA:
 *
 * - No third party. A CAPTCHA sends every suspected visitor's IP, headers and
 *   often behavioural telemetry to a vendor. A security product that quietly
 *   introduces a tracker to the customer's checkout page has made their
 *   privacy posture worse to improve their bot posture.
 * - No accessibility failure. Image and audio challenges exclude real people,
 *   and the excluded ones cannot complain through the flow they are stuck in.
 * - It is honest about what it does. It does not detect humanity, which no
 *   challenge does. It makes each request cost measurable CPU time, which
 *   changes the economics for someone making a million of them and is
 *   imperceptible for someone making one.
 *
 * What it is not: protection against a determined attacker with a GPU, or
 * against a headless browser solving it once per session. It raises the cost
 * of volume, and the interface says so rather than implying more.
 */

/** A challenge as issued to a client. */
export type Challenge = {
  /** Random, so a solution cannot be precomputed. */
  nonce: string;
  /** Leading zero bits the solution's hash must have. */
  difficulty: number;
  /** Milliseconds since epoch when this was issued. */
  issuedAt: number;
  /** How long the solution is accepted for. */
  ttlMs: number;
  /** Keyed HMAC over the fields above, so the client cannot forge one. */
  signature: string;
};

export type ChallengeVerdict =
  { ok: true; attempts: number } | { ok: false; reason: string; retryable: boolean };

/**
 * Difficulty in leading zero bits.
 *
 * Measured here, single-threaded in Bun, five runs each (median, and the
 * worst of the five, because the worst case is what a real visitor
 * experiences and proof of work has a long tail by construction):
 *
 *   12 bits:   30ms median,   40ms worst
 *   16 bits:  289ms median, 1725ms worst
 *   18 bits:  645ms median, 2798ms worst
 *   20 bits: 6478ms median,   10s worst
 *
 * The default is 12, not 16. The first draft of this file guessed 16 at
 * "roughly 40ms" and the measurement came back seven times higher, with a
 * worst case near two seconds -- on a development machine, which is faster
 * than the phone the customer is holding. A challenge that costs a real
 * visitor two seconds to load a page is a worse outcome than the scraping it
 * prevents.
 *
 * 12 bits is about 4,000 hashes. Imperceptible once; at a million requests it
 * is hours of CPU, which is the economics this is meant to change. The
 * maximum stays well below 20: past that the tail runs into tens of seconds
 * and the control starts costing the customer more than the attacker.
 */
export const DEFAULT_DIFFICULTY = 12;
export const MAX_DIFFICULTY = 18;

/** How long a solution is accepted. Short, because a challenge is per-request. */
export const DEFAULT_TTL_MS = 2 * 60_000;

async function hmac(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return Buffer.from(new Uint8Array(signature)).toString("base64url");
}

function canonical(challenge: Omit<Challenge, "signature">): string {
  return `${challenge.nonce}.${challenge.difficulty}.${challenge.issuedAt}.${challenge.ttlMs}`;
}

/**
 * Issues a challenge.
 *
 * Signed rather than stored. A table of outstanding challenges would need a
 * write on every suspicious request, which is the traffic least worth
 * spending a database write on, and a cleanup job for the ones nobody solves.
 * The HMAC makes the challenge self-describing: the server can verify what it
 * issued without having kept it.
 */
export async function issueChallenge(
  secret: string,
  options: { difficulty?: number; ttlMs?: number; now?: number } = {},
): Promise<Challenge> {
  const difficulty = Math.max(
    1,
    Math.min(options.difficulty ?? DEFAULT_DIFFICULTY, MAX_DIFFICULTY),
  );
  const issuedAt = options.now ?? Date.now();
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;

  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64url");
  const unsigned = { nonce, difficulty, issuedAt, ttlMs };

  return { ...unsigned, signature: await hmac(secret, canonical(unsigned)) };
}

/** Counts leading zero bits of a digest. */
export function leadingZeroBits(digest: Uint8Array): number {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

/** Whether a solution satisfies the difficulty. */
export async function solutionMeetsDifficulty(
  nonce: string,
  solution: string,
  difficulty: number,
): Promise<boolean> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${nonce}:${solution}`)),
  );
  return leadingZeroBits(digest) >= difficulty;
}

/**
 * Verifies a solved challenge.
 *
 * Order matters. The signature is checked before anything else, so an
 * attacker cannot make the server do proof-of-work verification for a
 * challenge it never issued; expiry is checked before the hash, so a stale
 * solution costs a comparison rather than a digest.
 */
export async function verifyChallenge(
  secret: string,
  challenge: Challenge,
  solution: string,
  now = Date.now(),
): Promise<ChallengeVerdict> {
  const expected = await hmac(secret, canonical(challenge));

  // Constant-time comparison: the signature is the only thing standing
  // between a client and a challenge of its own choosing.
  if (!timingSafeEqual(expected, challenge.signature)) {
    return { ok: false, reason: "This challenge was not issued here.", retryable: false };
  }

  if (challenge.difficulty < 1 || challenge.difficulty > MAX_DIFFICULTY) {
    // A signed challenge with an absurd difficulty would be a denial of
    // service against the client, and one with zero is no challenge at all.
    return { ok: false, reason: "This challenge is malformed.", retryable: false };
  }

  if (now > challenge.issuedAt + challenge.ttlMs) {
    return { ok: false, reason: "This challenge has expired. Request another.", retryable: true };
  }

  if (now + 60_000 < challenge.issuedAt) {
    // Issued in the future: either a forged timestamp or a badly skewed
    // clock, and neither should be accepted silently.
    return { ok: false, reason: "This challenge is not yet valid.", retryable: false };
  }

  if (typeof solution !== "string" || solution.length === 0 || solution.length > 64) {
    return { ok: false, reason: "The solution is missing or malformed.", retryable: true };
  }

  if (!(await solutionMeetsDifficulty(challenge.nonce, solution, challenge.difficulty))) {
    return { ok: false, reason: "The solution does not satisfy the challenge.", retryable: true };
  }

  return { ok: true, attempts: Number(solution) || 0 };
}

/** Length-safe constant-time string comparison. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

/**
 * Solves a challenge, for tests and for the browser client.
 *
 * The same function both sides use, so a client that cannot solve what the
 * server issues is a test failure rather than a production incident.
 */
export async function solveChallenge(
  challenge: Pick<Challenge, "nonce" | "difficulty">,
  limit = 5_000_000,
): Promise<string | null> {
  for (let attempt = 0; attempt < limit; attempt += 1) {
    const candidate = String(attempt);
    if (await solutionMeetsDifficulty(challenge.nonce, candidate, challenge.difficulty)) {
      return candidate;
    }
  }
  // Bounded rather than infinite: a client that cannot solve it should give
  // up and say so, not spin forever on a phone.
  return null;
}
