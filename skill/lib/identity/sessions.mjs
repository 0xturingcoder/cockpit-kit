// Per-device sign-in sessions, stored as a private JSON file outside the
// served root, next to the identity store. Schema and API: docs/sessions.md.
//
// Guarantees:
// - A session token is 32 random bytes. Only its SHA-256 hash is stored, so
//   the file never holds a value that could be replayed as a cookie. Each
//   session also has a separate public id, used to list and revoke it.
// - Sessions expire at a fixed time (created + lifetime, 90 days by
//   default). Expired sessions are refused on the next request and pruned on
//   the next write. Revoking a session deletes it.
// - Validation does not write: the parsed file is cached and re-read only
//   when the file changes (any write renames a new file into place), so a
//   revocation by this or another process is seen on the next request.
//   Last-seen times are written at most once per `lastSeenIntervalMs` per
//   session, and only if the lock is free; a busy store skips the update.
// - File safety (0600, atomic rename, lock file, size cap, fail closed) is
//   shared with the identity store through private-file.mjs.
import crypto from 'node:crypto';
import path from 'node:path';
import { createPrivateFile, fileSignature } from './private-file.mjs';
import { assertOutsideRoot, isSafeLabel } from './store.mjs';

export const SESSIONS_SCHEMA_VERSION = 1;
export const SESSIONS_FILE = 'sessions.json';
const DAY_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_SESSION_LIFETIME_MS = 90 * DAY_MS;
export const MIN_SESSION_LIFETIME_MS = 5 * 60 * 1000;
// Browsers cap cookie lifetimes at 400 days.
export const MAX_SESSION_LIFETIME_MS = 400 * DAY_MS;
export const DEFAULT_LAST_SEEN_INTERVAL_MS = 10 * 60 * 1000;
export const MAX_SESSIONS_PER_USER = 32;
// One session takes about 400 bytes, so this stays well inside the 1 MiB cap.
export const MAX_SESSIONS = 2000;
const DEFAULT_LOCK_WAIT_MS = 1000;
const DEFAULT_LOCK_STALE_MS = 30000;

const TOKEN_BYTES = 32;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const SESSION_ID_RE = /^ses_[A-Za-z0-9_-]{22}$/;
const HASH_RE = /^[A-Za-z0-9_-]{43}$/;
const USER_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const CREDENTIAL_ID_RE = /^[A-Za-z0-9_-]{1,1364}$/;
const STORE_KEYS = ['schema_version', 'sessions'];
const SESSION_KEYS = ['id', 'token_hash', 'user_id', 'credential_id', 'label', 'created_at', 'last_seen_at', 'expires_at'];

export class SessionStoreError extends Error {
  constructor(message, code = 'invalid_store') {
    super(message);
    this.name = 'SessionStoreError';
    this.code = code;
  }
}

const fail = (message, code) => { throw new SessionStoreError(message, code); };

const sessionsFile = createPrivateFile({
  label: 'Sessions store',
  fail,
  isError: (error) => error instanceof SessionStoreError,
  fullHint: 'revoke unused sessions first',
});

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const checkTimestamp = (value, at) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail(`${at} must be an ISO 8601 UTC timestamp`);
  }
};

const checkSession = (session, at) => {
  if (!isPlainObject(session)) fail(`${at} must be an object`);
  for (const key of SESSION_KEYS) if (!Object.hasOwn(session, key)) fail(`${at} is missing ${key}`);
  for (const key of Object.keys(session)) if (!SESSION_KEYS.includes(key)) fail(`${at} has an unknown field`);
  if (typeof session.id !== 'string' || !SESSION_ID_RE.test(session.id)) fail(`${at}.id must be ses_ followed by 22 base64url characters`);
  if (typeof session.token_hash !== 'string' || !HASH_RE.test(session.token_hash)) fail(`${at}.token_hash must be a base64url SHA-256 hash`);
  if (typeof session.user_id !== 'string' || !USER_ID_RE.test(session.user_id)) fail(`${at}.user_id must be a user id`);
  if (session.credential_id !== null && (typeof session.credential_id !== 'string' || !CREDENTIAL_ID_RE.test(session.credential_id))) {
    fail(`${at}.credential_id must be null or a base64url credential id`);
  }
  if (!isSafeLabel(session.label)) fail(`${at}.label must be 0 to 64 characters without control or formatting characters`);
  for (const key of ['created_at', 'last_seen_at', 'expires_at']) checkTimestamp(session[key], `${at}.${key}`);
};

/**
 * Validate a whole sessions document. Throws SessionStoreError on the first
 * problem; returns the same object when it is valid.
 *
 * @param {unknown} data
 * @returns {SessionsData}
 */
export const validateSessionsData = (data) => {
  if (!isPlainObject(data)) fail('sessions store must be an object');
  for (const key of STORE_KEYS) if (!Object.hasOwn(data, key)) fail(`sessions store is missing ${key}`);
  for (const key of Object.keys(data)) if (!STORE_KEYS.includes(key)) fail('sessions store has an unknown field');
  if (data.schema_version !== SESSIONS_SCHEMA_VERSION) fail(`sessions store schema_version must be ${SESSIONS_SCHEMA_VERSION}`, 'unsupported_schema');
  if (!Array.isArray(data.sessions) || data.sessions.length > MAX_SESSIONS) fail(`sessions store sessions must be an array of at most ${MAX_SESSIONS} sessions`);
  const ids = new Set();
  const hashes = new Set();
  data.sessions.forEach((session, index) => {
    checkSession(session, `sessions[${index}]`);
    if (ids.has(session.id) || hashes.has(session.token_hash)) fail(`sessions[${index}] duplicates another session`, 'duplicate_id');
    ids.add(session.id);
    hashes.add(session.token_hash);
  });
  return data;
};

/**
 * SHA-256 of a session token, base64url. This is what the store keeps.
 *
 * @param {string} token
 * @returns {string}
 */
export const hashToken = (token) => crypto.createHash('sha256').update(token, 'utf8').digest('base64url');

/** The session fields that are safe to show: everything except the token hash. */
export const publicSession = ({ token_hash: _hash, ...rest }) => ({ ...rest });

const EMPTY = Object.freeze({ schema_version: SESSIONS_SCHEMA_VERSION, sessions: Object.freeze([]) });

const iso = (ms) => new Date(ms).toISOString();

const isLive = (session, nowMs) => Date.parse(session.expires_at) > nowMs;

const checkLifetime = (value) => {
  if (!Number.isSafeInteger(value) || value < MIN_SESSION_LIFETIME_MS || value > MAX_SESSION_LIFETIME_MS) {
    fail(`session lifetime must be between ${MIN_SESSION_LIFETIME_MS} and ${MAX_SESSION_LIFETIME_MS} milliseconds`, 'invalid_argument');
  }
  return value;
};

/**
 * Open the sessions store at `file` for the Cockpit served from `root`.
 * Nothing is read or written until a method is called.
 *
 * @param {object} options
 * @param {string} options.file Absolute path of the sessions file (outside root).
 * @param {string} options.root Served Cockpit root.
 * @param {() => number} [options.now] Clock (tests).
 * @param {number} [options.lifetimeMs] Lifetime of new sessions (default 90 days).
 * @param {number} [options.lastSeenIntervalMs] Minimum time between last-seen writes for one session.
 * @param {number} [options.lockWaitMs] How long create and revoke wait for a busy lock.
 * @param {number} [options.lockStaleMs] Age after which a lock is presumed abandoned.
 * @returns {SessionStore}
 */
export const openSessionStore = ({
  file, root, now = Date.now, lifetimeMs = DEFAULT_SESSION_LIFETIME_MS, lastSeenIntervalMs = DEFAULT_LAST_SEEN_INTERVAL_MS,
  lockWaitMs = DEFAULT_LOCK_WAIT_MS, lockStaleMs = DEFAULT_LOCK_STALE_MS,
} = {}) => {
  if (typeof root !== 'string' || root === '') fail('openSessionStore requires the served root', 'invalid_argument');
  checkLifetime(lifetimeMs);
  for (const [name, value] of [['lastSeenIntervalMs', lastSeenIntervalMs], ['lockWaitMs', lockWaitMs], ['lockStaleMs', lockStaleMs]]) {
    if (!Number.isFinite(value) || value < 0) fail(`${name} must be a non-negative number of milliseconds`, 'invalid_argument');
  }
  const checkPath = (value) => {
    try {
      return path.resolve(assertOutsideRoot(value, root, 'sessions store'));
    } catch (error) {
      return fail(error.message, error.code);
    }
  };
  const storeFile = checkPath(file);
  const lockFile = `${storeFile}.lock`;
  const dir = path.dirname(storeFile);

  // Parsed file plus a token-hash index, re-read only when the file changes.
  let cache = { signature: undefined, data: EMPTY, byHash: new Map() };
  // Last time this process tried to write last_seen_at, per session id, so a
  // busy store does not turn every request into a write attempt.
  const touchAttempts = new Map();

  const readCurrent = () => {
    let signature;
    try {
      signature = fileSignature(storeFile);
    } catch {
      fail('Sessions store is unreadable', 'unreadable');
    }
    if (signature === cache.signature) return cache;
    let data = EMPTY;
    if (signature !== null) {
      sessionsFile.checkDir(dir);
      try {
        data = validateSessionsData(sessionsFile.read(storeFile));
      } catch (error) {
        if (error.code !== 'missing') throw error;
      }
    }
    cache = { signature, data, byHash: new Map(data.sessions.map((session) => [session.token_hash, session])) };
    return cache;
  };

  // Read, prune expired sessions, transform, validate, and atomically write
  // under the lock. `transform` returns { sessions, result, changed }.
  const mutate = (transform, { waitMs = lockWaitMs } = {}) => {
    checkPath(storeFile);
    sessionsFile.ensureDir(dir);
    return sessionsFile.withLock(lockFile, { waitMs, staleMs: lockStaleMs }, (isHeld) => {
      let current = EMPTY;
      try {
        current = validateSessionsData(sessionsFile.read(storeFile));
      } catch (error) {
        if (error.code !== 'missing') throw error;
      }
      const nowMs = now();
      const live = current.sessions.filter((session) => isLive(session, nowMs));
      const { sessions, result, changed = true } = transform(live, nowMs);
      if (changed || live.length !== current.sessions.length) {
        const next = validateSessionsData({ schema_version: SESSIONS_SCHEMA_VERSION, sessions });
        sessionsFile.write(storeFile, sessionsFile.serialize(next), () => {
          if (!isHeld()) fail('Another writer took over the sessions store lock; nothing was written', 'store_busy');
        });
      }
      return result;
    });
  };

  /**
   * Create a session. Returns the raw token (for the cookie, never stored),
   * the public session, and the cookie Max-Age in seconds.
   */
  const create = ({ userId, credentialId = null, label = '' } = {}) => {
    if (typeof userId !== 'string' || !USER_ID_RE.test(userId)) fail('userId must be a user id', 'invalid_argument');
    if (credentialId !== null && (typeof credentialId !== 'string' || !CREDENTIAL_ID_RE.test(credentialId))) fail('credentialId must be a base64url credential id', 'invalid_argument');
    if (!isSafeLabel(label)) fail('label must be 0 to 64 characters without control or formatting characters', 'invalid_argument');
    const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
    return mutate((sessions, nowMs) => {
      const session = {
        id: `ses_${crypto.randomBytes(16).toString('base64url')}`,
        token_hash: hashToken(token),
        user_id: userId,
        credential_id: credentialId,
        label,
        created_at: iso(nowMs),
        last_seen_at: iso(nowMs),
        expires_at: iso(nowMs + lifetimeMs),
      };
      // Keep at most MAX_SESSIONS_PER_USER per user by dropping the ones
      // seen least recently.
      const mine = sessions.filter((existing) => existing.user_id === userId)
        .sort((a, b) => Date.parse(a.last_seen_at) - Date.parse(b.last_seen_at));
      const drop = new Set(mine.slice(0, Math.max(0, mine.length - MAX_SESSIONS_PER_USER + 1)).map((existing) => existing.id));
      const kept = sessions.filter((existing) => !drop.has(existing.id));
      if (kept.length >= MAX_SESSIONS) fail(`The sessions store already holds ${MAX_SESSIONS} sessions`, 'store_full');
      return { sessions: [...kept, session], result: { token, session: publicSession(session), maxAgeSeconds: Math.floor(lifetimeMs / 1000) } };
    });
  };

  // Record that a session was used, at most once per interval. Never waits
  // for the lock, and never throws for a busy store.
  const touch = (session, nowMs) => {
    if (nowMs - Date.parse(session.last_seen_at) < lastSeenIntervalMs) return;
    if (nowMs - (touchAttempts.get(session.id) ?? -Infinity) < lastSeenIntervalMs) return;
    touchAttempts.set(session.id, nowMs);
    if (touchAttempts.size > MAX_SESSIONS) touchAttempts.delete(touchAttempts.keys().next().value);
    try {
      mutate((sessions, at) => {
        const index = sessions.findIndex((existing) => existing.id === session.id);
        if (index === -1 || at - Date.parse(sessions[index].last_seen_at) < lastSeenIntervalMs) return { sessions, changed: false };
        const updated = { ...sessions[index], last_seen_at: iso(at) };
        return { sessions: sessions.map((existing, i) => (i === index ? updated : existing)) };
      }, { waitMs: 0 });
    } catch (error) {
      if (!(error instanceof SessionStoreError && ['store_busy', 'store_full'].includes(error.code))) throw error;
    }
  };

  /**
   * The live session for a raw cookie token, or null if it is unknown,
   * revoked, or expired. Updates last_seen_at at most once per interval.
   */
  const validate = (token) => {
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) return null;
    const session = readCurrent().byHash.get(hashToken(token));
    const nowMs = now();
    if (!session || !isLive(session, nowMs)) return null;
    touch(session, nowMs);
    return publicSession(session);
  };

  const list = ({ userId } = {}) => {
    const nowMs = now();
    return readCurrent().data.sessions
      .filter((session) => isLive(session, nowMs) && (userId === undefined || session.user_id === userId))
      .map(publicSession);
  };

  const get = (sessionId) => list().find((session) => session.id === sessionId) ?? null;

  // Delete every session matching `predicate`; returns the removed sessions.
  const revokeWhere = (predicate) => mutate((sessions) => {
    const removed = sessions.filter(predicate);
    return { sessions: sessions.filter((session) => !predicate(session)), result: removed.map(publicSession), changed: removed.length > 0 };
  });

  return Object.freeze({
    file: storeFile,
    lifetimeMs,
    load: () => structuredClone(readCurrent().data),
    create,
    validate,
    list,
    get,
    revoke: (sessionId) => revokeWhere((session) => session.id === sessionId)[0] ?? null,
    revokeUser: (userId) => revokeWhere((session) => session.user_id === userId),
    revokeCredential: (credentialId) => revokeWhere((session) => session.credential_id === credentialId),
  });
};

/**
 * @typedef {object} StoredSession
 * @property {string} id Public session id, `ses_` + 22 base64url characters.
 * @property {string} token_hash SHA-256 of the cookie token, base64url.
 * @property {string} user_id
 * @property {string | null} credential_id Passkey used to sign in, if any.
 * @property {string} label Device label.
 * @property {string} created_at
 * @property {string} last_seen_at Updated at most once per lastSeenIntervalMs.
 * @property {string} expires_at
 *
 * @typedef {object} SessionsData
 * @property {1} schema_version
 * @property {StoredSession[]} sessions
 *
 * @typedef {Omit<StoredSession, 'token_hash'>} PublicSession
 *
 * @typedef {object} SessionStore
 * @property {string} file
 * @property {number} lifetimeMs
 * @property {() => SessionsData} load
 * @property {(input: { userId: string, credentialId?: string | null, label?: string }) => { token: string, session: PublicSession, maxAgeSeconds: number }} create
 * @property {(token: string) => PublicSession | null} validate
 * @property {(filter?: { userId?: string }) => PublicSession[]} list Live sessions.
 * @property {(sessionId: string) => PublicSession | null} get
 * @property {(sessionId: string) => PublicSession | null} revoke
 * @property {(userId: string) => PublicSession[]} revokeUser
 * @property {(credentialId: string) => PublicSession[]} revokeCredential
 */
