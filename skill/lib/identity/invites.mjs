// One-time invites to enroll a member's first passkey, stored as a private
// JSON file outside the served root, next to the identity store. Schema and
// API: docs/invites.md.
//
// Guarantees:
// - An invite token is 32 random bytes. Only its SHA-256 hash is stored, so
//   the file never holds a value that could be used as an invite link. The
//   token is returned once, by create(), and never listed.
// - An invite is bound to a user that does not exist yet: a pre-generated
//   user id, a display name, and the member role. The user is created only
//   at enrollment, so an unused invite leaves nothing behind.
// - Invites expire at a fixed time (created + lifetime, 24 hours by default).
//   Revoking or completing an invite deletes it, and expired invites are
//   ignored on read and pruned on every write, so a spent, revoked, or
//   expired invite looks exactly like one that never existed.
// - spend() claims the invite under the file lock after re-reading the
//   file, so of any number of concurrent spends (in any process) exactly one
//   gets the invite. A claimed invite is hidden from find, list, and spend,
//   exactly like a deleted one. complete() deletes it after the member is
//   created; restore() clears the claim after a retryable failure.
// - Revoke always wins: revoke() deletes a claimed invite too, and restore()
//   only clears a claim on a record that still exists, so an invite revoked
//   while an enrollment holds its claim never comes back.
// - A claim lasts at most CLAIM_LEASE_MS. A claim left by a process that
//   died is pruned (the invite is gone, not restored) on the next write once
//   the lease runs out, and expiry prunes it in any case.
// - File safety (0600, atomic rename, lock file, size cap, fail closed) is
//   shared with the identity and sessions stores through private-file.mjs.
import crypto from 'node:crypto';
import path from 'node:path';
import { createPrivateFile } from './private-file.mjs';
import { hashToken } from './sessions.mjs';
import { assertOutsideRoot, isSafeDisplayName } from './store.mjs';

export const INVITES_SCHEMA_VERSION = 1;
export const INVITES_FILE = 'invites.json';
const MINUTE_MS = 60 * 1000;
const DAY_MS = 24 * 60 * MINUTE_MS;
export const DEFAULT_INVITE_LIFETIME_MS = DAY_MS;
export const MIN_INVITE_LIFETIME_MS = 5 * MINUTE_MS;
export const MAX_INVITE_LIFETIME_MS = 7 * DAY_MS;
export const MAX_PENDING_INVITES = 32;
export const CLAIM_LEASE_MS = 5 * MINUTE_MS;
const DEFAULT_LOCK_WAIT_MS = 1000;
const DEFAULT_LOCK_STALE_MS = 30000;

const TOKEN_BYTES = 32;
export const INVITE_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
export const INVITE_ID_RE = /^inv_[A-Za-z0-9_-]{22}$/;
const HASH_RE = /^[A-Za-z0-9_-]{43}$/;
const USER_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const STORE_KEYS = ['schema_version', 'invites'];
const INVITE_KEYS = ['id', 'token_hash', 'user_id', 'display_name', 'role', 'created_by', 'created_at', 'expires_at'];
// Present only while an enrollment holds the invite (spend to complete or restore).
const OPTIONAL_INVITE_KEYS = ['claimed_at'];

export class InviteStoreError extends Error {
  constructor(message, code = 'invalid_store') {
    super(message);
    this.name = 'InviteStoreError';
    this.code = code;
  }
}

const fail = (message, code) => { throw new InviteStoreError(message, code); };

const invitesFile = createPrivateFile({
  label: 'Invites store',
  fail,
  isError: (error) => error instanceof InviteStoreError,
  fullHint: 'revoke unused invites first',
});

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const checkTimestamp = (value, at) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail(`${at} must be an ISO 8601 UTC timestamp`);
  }
};

const checkInvite = (invite, at) => {
  if (!isPlainObject(invite)) fail(`${at} must be an object`);
  for (const key of INVITE_KEYS) if (!Object.hasOwn(invite, key)) fail(`${at} is missing ${key}`);
  for (const key of Object.keys(invite)) if (!INVITE_KEYS.includes(key) && !OPTIONAL_INVITE_KEYS.includes(key)) fail(`${at} has an unknown field`);
  if (typeof invite.id !== 'string' || !INVITE_ID_RE.test(invite.id)) fail(`${at}.id must be inv_ followed by 22 base64url characters`);
  if (typeof invite.token_hash !== 'string' || !HASH_RE.test(invite.token_hash)) fail(`${at}.token_hash must be a base64url SHA-256 hash`);
  if (typeof invite.user_id !== 'string' || !USER_ID_RE.test(invite.user_id)) fail(`${at}.user_id must be a user id`);
  if (!isSafeDisplayName(invite.display_name)) fail(`${at}.display_name must be 1 to 128 characters without control or formatting characters`);
  // Invites only ever create members; the owner is created by registration.
  if (invite.role !== 'member') fail(`${at}.role must be member`);
  if (typeof invite.created_by !== 'string' || !USER_ID_RE.test(invite.created_by)) fail(`${at}.created_by must be a user id`);
  for (const key of ['created_at', 'expires_at']) checkTimestamp(invite[key], `${at}.${key}`);
  if (Date.parse(invite.expires_at) <= Date.parse(invite.created_at)) fail(`${at}.expires_at must be after created_at`);
  if (Object.hasOwn(invite, 'claimed_at')) {
    checkTimestamp(invite.claimed_at, `${at}.claimed_at`);
    const claimed = Date.parse(invite.claimed_at);
    if (claimed < Date.parse(invite.created_at) || claimed >= Date.parse(invite.expires_at)) fail(`${at}.claimed_at must be from created_at to before expires_at`);
  }
};

/**
 * Validate a whole invites document. Throws InviteStoreError on the first
 * problem; returns the same object when it is valid.
 *
 * @param {unknown} data
 * @returns {InvitesData}
 */
export const validateInvitesData = (data) => {
  if (!isPlainObject(data)) fail('invites store must be an object');
  for (const key of STORE_KEYS) if (!Object.hasOwn(data, key)) fail(`invites store is missing ${key}`);
  for (const key of Object.keys(data)) if (!STORE_KEYS.includes(key)) fail('invites store has an unknown field');
  if (data.schema_version !== INVITES_SCHEMA_VERSION) fail(`invites store schema_version must be ${INVITES_SCHEMA_VERSION}`, 'unsupported_schema');
  // Every write prunes expired invites before adding one, so the file never
  // holds more than MAX_PENDING_INVITES records.
  if (!Array.isArray(data.invites) || data.invites.length > MAX_PENDING_INVITES) fail(`invites store invites must be an array of at most ${MAX_PENDING_INVITES} invites`);
  const seen = new Set();
  data.invites.forEach((invite, index) => {
    checkInvite(invite, `invites[${index}]`);
    for (const value of [invite.id, invite.token_hash, invite.user_id]) {
      if (seen.has(value)) fail(`invites[${index}] duplicates another invite`, 'duplicate_id');
      seen.add(value);
    }
  });
  return data;
};

/** The invite fields that are safe to show: everything except the token hash and the claim. */
export const publicInvite = ({ token_hash: _hash, claimed_at: _claim, ...rest }) => ({ ...rest });

const EMPTY = Object.freeze({ schema_version: INVITES_SCHEMA_VERSION, invites: Object.freeze([]) });

const iso = (ms) => new Date(ms).toISOString();

const isClaimed = (invite) => Object.hasOwn(invite, 'claimed_at');

// Kept on the next write: not expired, and any claim is within its lease.
const isLive = (invite, nowMs) => Date.parse(invite.expires_at) > nowMs
  && (!isClaimed(invite) || Date.parse(invite.claimed_at) + CLAIM_LEASE_MS > nowMs);

// Usable by an invite link: live and not claimed.
const isPending = (invite, nowMs) => isLive(invite, nowMs) && !isClaimed(invite);

// A token that could never have been issued is not hashed or looked up.
const tokenHash = (token) => (typeof token === 'string' && INVITE_TOKEN_RE.test(token) ? hashToken(token) : null);

const checkLifetime = (value) => {
  if (!Number.isSafeInteger(value) || value < MIN_INVITE_LIFETIME_MS || value > MAX_INVITE_LIFETIME_MS) {
    fail(`invite lifetime must be between ${MIN_INVITE_LIFETIME_MS} and ${MAX_INVITE_LIFETIME_MS} milliseconds`, 'invalid_argument');
  }
  return value;
};

/**
 * Open the invites store at `file` for the Cockpit served from `root`.
 * Nothing is read or written until a method is called.
 *
 * @param {object} options
 * @param {string} options.file Absolute path of the invites file (outside root).
 * @param {string} options.root Served Cockpit root.
 * @param {() => number} [options.now] Clock (tests).
 * @param {number} [options.lifetimeMs] Lifetime of new invites (default 24 hours).
 * @param {number} [options.lockWaitMs] How long a change waits for a busy lock.
 * @param {number} [options.lockStaleMs] Age after which a lock is presumed abandoned.
 * @returns {InviteStore}
 */
export const openInviteStore = ({
  file, root, now = Date.now, lifetimeMs = DEFAULT_INVITE_LIFETIME_MS, lockWaitMs = DEFAULT_LOCK_WAIT_MS, lockStaleMs = DEFAULT_LOCK_STALE_MS,
} = {}) => {
  if (typeof root !== 'string' || root === '') fail('openInviteStore requires the served root', 'invalid_argument');
  checkLifetime(lifetimeMs);
  for (const [name, value] of [['lockWaitMs', lockWaitMs], ['lockStaleMs', lockStaleMs]]) {
    if (!Number.isFinite(value) || value < 0) fail(`${name} must be a non-negative number of milliseconds`, 'invalid_argument');
  }
  const checkPath = (value) => {
    try {
      return path.resolve(assertOutsideRoot(value, root, 'invites store'));
    } catch (error) {
      return fail(error.message, error.code);
    }
  };
  const storeFile = checkPath(file);
  const lockFile = `${storeFile}.lock`;
  const dir = path.dirname(storeFile);

  const readFile = () => {
    try {
      return validateInvitesData(invitesFile.read(storeFile));
    } catch (error) {
      if (error.code === 'missing') return EMPTY;
      throw error;
    }
  };

  // Read without the lock: the file is only ever replaced whole.
  const readCurrent = () => {
    checkPath(storeFile);
    invitesFile.checkDir(dir);
    return readFile();
  };

  // Read, prune expired invites, transform, validate, and atomically write
  // under the lock. `transform` returns { invites, result, changed }.
  const mutate = (transform) => {
    checkPath(storeFile);
    invitesFile.ensureDir(dir);
    return invitesFile.withLock(lockFile, { waitMs: lockWaitMs, staleMs: lockStaleMs }, (isHeld) => {
      const current = readFile();
      const nowMs = now();
      const live = current.invites.filter((invite) => isLive(invite, nowMs));
      const { invites, result, changed = true } = transform(live, nowMs);
      if (changed || live.length !== current.invites.length) {
        const next = validateInvitesData({ schema_version: INVITES_SCHEMA_VERSION, invites });
        invitesFile.write(storeFile, invitesFile.serialize(next), () => {
          if (!isHeld()) fail('Another writer took over the invites store lock; nothing was written', 'store_busy');
        });
      }
      return result;
    });
  };

  const pendingInvites = () => {
    const nowMs = now();
    return readCurrent().invites.filter((invite) => isPending(invite, nowMs));
  };

  /**
   * Create an invite for a new member. Returns the raw token (for the link,
   * never stored) and the public invite.
   */
  const create = ({ displayName, createdBy } = {}) => {
    if (!isSafeDisplayName(displayName)) fail('displayName must be 1 to 128 characters without surrounding whitespace, control, or formatting characters', 'invalid_argument');
    if (typeof createdBy !== 'string' || !USER_ID_RE.test(createdBy)) fail('createdBy must be a user id', 'invalid_argument');
    const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
    return mutate((invites, nowMs) => {
      // Claimed invites still take a slot until they are completed, restored,
      // revoked, or pruned.
      if (invites.length >= MAX_PENDING_INVITES) fail(`There are already ${MAX_PENDING_INVITES} pending invites; revoke one first`, 'too_many_invites');
      const invite = {
        id: `inv_${crypto.randomBytes(16).toString('base64url')}`,
        token_hash: hashToken(token),
        user_id: `usr_${crypto.randomBytes(16).toString('base64url')}`,
        display_name: displayName,
        role: 'member',
        created_by: createdBy,
        created_at: iso(nowMs),
        expires_at: iso(nowMs + lifetimeMs),
      };
      return { invites: [...invites, invite], result: { token, invite: publicInvite(invite) } };
    });
  };

  /** The pending invite for a raw token, or null (unknown, spent, revoked, expired, or malformed). Does not write. */
  const find = (token) => {
    const hash = tokenHash(token);
    if (!hash) return null;
    const invite = pendingInvites().find((candidate) => candidate.token_hash === hash);
    return invite ? publicInvite(invite) : null;
  };

  // Replace the claimed record for `token` and `inviteId` (if it still
  // exists) with `next(record)`, or drop it when `next` returns null.
  const settle = (token, inviteId, next) => {
    const hash = tokenHash(token);
    if (!hash || typeof inviteId !== 'string') return false;
    return mutate((invites) => {
      const invite = invites.find((candidate) => candidate.token_hash === hash && candidate.id === inviteId && isClaimed(candidate));
      if (!invite) return { invites, result: false, changed: false };
      const replacement = next(invite);
      return { invites: invites.flatMap((candidate) => (candidate !== invite ? [candidate] : replacement ? [replacement] : [])), result: true };
    });
  };

  /**
   * Claim the invite for `token`, which must be the pending invite
   * `inviteId`. Marks it claimed under the lock and returns the public
   * invite, or returns null without writing if there is no such pending
   * invite. Follow with complete() or restore().
   */
  const spend = (token, inviteId) => {
    const hash = tokenHash(token);
    if (!hash) return null;
    return mutate((invites, nowMs) => {
      const invite = invites.find((candidate) => candidate.token_hash === hash && !isClaimed(candidate));
      if (!invite || invite.id !== inviteId) return { invites, result: null, changed: false };
      const claimed = { ...invite, claimed_at: iso(nowMs) };
      return { invites: invites.map((candidate) => (candidate === invite ? claimed : candidate)), result: publicInvite(invite) };
    });
  };

  /** Delete a claimed invite once its member exists. Returns true when it was deleted. */
  const complete = (token, inviteId) => settle(token, inviteId, () => null);

  /**
   * Clear the claim spend() set, after a retryable failure created no user.
   * Only if the record still exists: a revoked, expired, or pruned invite
   * stays gone. Returns true when it was restored.
   */
  const restore = (token, inviteId) => settle(token, inviteId, ({ claimed_at: _claim, ...rest }) => rest);

  /** Delete an invite, pending or claimed. Returns the public invite, or null if there is none. */
  const revoke = (inviteId) => mutate((invites) => {
    const invite = invites.find((candidate) => candidate.id === inviteId);
    if (!invite) return { invites, result: null, changed: false };
    return { invites: invites.filter((candidate) => candidate !== invite), result: publicInvite(invite) };
  });

  return Object.freeze({
    file: storeFile,
    lifetimeMs,
    load: () => structuredClone(readCurrent()),
    create,
    list: () => pendingInvites().map(publicInvite),
    find,
    spend,
    complete,
    restore,
    revoke,
  });
};

/**
 * @typedef {object} StoredInvite
 * @property {string} id Public invite id, `inv_` + 22 base64url characters.
 * @property {string} token_hash SHA-256 of the invite token, base64url.
 * @property {string} user_id Id the new member gets at enrollment.
 * @property {string} display_name The new member's display name.
 * @property {'member'} role
 * @property {string} created_by User id of the owner who created it.
 * @property {string} created_at
 * @property {string} expires_at
 * @property {string} [claimed_at] Set by spend() until complete() or restore().
 *
 * @typedef {object} InvitesData
 * @property {1} schema_version
 * @property {StoredInvite[]} invites
 *
 * @typedef {Omit<StoredInvite, 'token_hash' | 'claimed_at'>} PublicInvite
 *
 * @typedef {object} InviteStore
 * @property {string} file
 * @property {number} lifetimeMs
 * @property {() => InvitesData} load
 * @property {(input: { displayName: string, createdBy: string }) => { token: string, invite: PublicInvite }} create
 * @property {() => PublicInvite[]} list Pending invites.
 * @property {(token: string) => PublicInvite | null} find
 * @property {(token: string, inviteId: string) => PublicInvite | null} spend
 * @property {(token: string, inviteId: string) => boolean} complete
 * @property {(token: string, inviteId: string) => boolean} restore
 * @property {(inviteId: string) => PublicInvite | null} revoke
 */
