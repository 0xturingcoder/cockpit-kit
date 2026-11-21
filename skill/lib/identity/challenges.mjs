// Server-side WebAuthn challenges: random, single use, short-lived, bound to
// one ceremony (and, for registration and invitations, to the user being
// registered), and bounded in number per ceremony. In memory only: a restart drops every
// pending ceremony.
import crypto from 'node:crypto';

export const CHALLENGE_BYTES = 32;
export const DEFAULT_CHALLENGE_TTL_MS = 2 * 60 * 1000;
// Per ceremony, so anonymous sign-in or invite traffic cannot use up the
// slots that operator registration needs.
export const DEFAULT_MAX_CHALLENGES = 64;
// "invitation" is a registration through an invite link (invites.mjs).
export const CEREMONIES = Object.freeze(['registration', 'authentication', 'invitation']);

const MESSAGES = Object.freeze({
  challenge_unknown: 'The challenge is unknown or was already used.',
  challenge_expired: 'The challenge expired.',
  wrong_ceremony: 'The challenge was issued for a different ceremony.',
  too_many_challenges: 'Too many pending sign-in ceremonies; retry shortly.',
});

export class ChallengeError extends Error {
  constructor(code) {
    super(MESSAGES[code]);
    this.name = 'ChallengeError';
    this.code = code;
  }
}

const HANDLE_RE = /^[A-Za-z0-9_-]{43}$/;

/**
 * Create an in-memory challenge store.
 *
 * `issue()` returns an opaque handle (`id`) for the client to send back and
 * the challenge bytes for the browser. `consume()` removes the entry on the
 * first attempt, whatever the outcome, so a challenge can be used at most
 * once. Expired entries are swept on every call; when `max` entries for the
 * same ceremony are still pending, `issue()` refuses with
 * "too_many_challenges" rather than evicting a live ceremony. Each ceremony
 * has its own `max`, so a full sign-in ceremony never blocks registration.
 *
 * @param {{ ttlMs?: number, max?: number, now?: () => number }} [options]
 */
export const createChallengeStore = ({ ttlMs = DEFAULT_CHALLENGE_TTL_MS, max = DEFAULT_MAX_CHALLENGES, now = Date.now } = {}) => {
  if (!Number.isInteger(ttlMs) || ttlMs < 1 || !Number.isInteger(max) || max < 1) throw new TypeError('invalid challenge store limits');
  const pending = new Map();

  const sweep = (at) => {
    for (const [id, entry] of pending) if (entry.expiresAt <= at) pending.delete(id);
  };

  const pendingFor = (ceremony) => {
    let count = 0;
    for (const entry of pending.values()) if (entry.ceremony === ceremony) count += 1;
    return count;
  };

  /**
   * @param {{ ceremony: 'registration' | 'authentication' | 'invitation', binding?: object }} input
   *   `binding` is stored with the challenge and returned by consume(), e.g.
   *   the user a registration is for.
   */
  const issue = ({ ceremony, binding = null }) => {
    if (!CEREMONIES.includes(ceremony)) throw new TypeError('unknown ceremony');
    const at = now();
    sweep(at);
    if (pendingFor(ceremony) >= max) throw new ChallengeError('too_many_challenges');
    const id = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.randomBytes(CHALLENGE_BYTES);
    const entry = Object.freeze({ ceremony, challenge, binding: binding && Object.freeze({ ...binding }), expiresAt: at + ttlMs });
    pending.set(id, entry);
    return Object.freeze({ id, challenge: Buffer.from(challenge), expiresAt: entry.expiresAt });
  };

  /**
   * Take a challenge for `ceremony`. The entry is deleted before any check,
   * so a failed attempt also uses it up.
   */
  const consume = (id, ceremony) => {
    const at = now();
    const entry = typeof id === 'string' && HANDLE_RE.test(id) ? pending.get(id) : undefined;
    if (entry) pending.delete(id);
    sweep(at);
    if (!entry) throw new ChallengeError('challenge_unknown');
    if (entry.expiresAt <= at) throw new ChallengeError('challenge_expired');
    if (entry.ceremony !== ceremony) throw new ChallengeError('wrong_ceremony');
    return Object.freeze({ challenge: Buffer.from(entry.challenge), binding: entry.binding });
  };

  return Object.freeze({ issue, consume, ttlMs, size: (ceremony) => (ceremony === undefined ? pending.size : pendingFor(ceremony)) });
};
