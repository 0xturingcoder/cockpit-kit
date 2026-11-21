// The owner's recovery token and the recovery audit log, stored as private
// JSON files outside the served root, next to the identity store. See
// docs/recovery.md.
//
// Guarantees:
// - The recovery token is 32 random bytes, base64url. Only its SHA-256 hash
//   is stored, in recovery.json, so the file never holds a value that could
//   be used to sign in. The token is returned once, by ensure() (first start)
//   or rotate(), for the caller to print, and never again.
// - check() refuses anything that is not 43 base64url characters before
//   hashing, then compares hashes in constant time. A missing file matches
//   nothing; a corrupt or unsafe file throws (fail closed).
// - The file is cached and re-read only when it changes, so a rotation by
//   another process takes effect on the next request.
// - The audit log, audit.json, keeps only { at, event, result } per event,
//   from fixed lists: never a token, hash, IP address, or User-Agent. It
//   holds at most MAX_AUDIT_EVENTS events. Past that, the oldest failed
//   attempt (an invalid or rate_limited token_sign_in or first_owner) is
//   dropped first; a notable event (any other result, and every
//   token_rotated and recovery_enroll) is dropped, oldest first, only when
//   notable events alone exceed the cap. So no number of unauthenticated
//   failures can push a successful or security-relevant event out. At most
//   one rate_limited event per event type per minute is written.
// - File safety (0600, atomic rename, lock file, size cap, fail closed) is
//   shared with the other identity files through private-file.mjs.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createPrivateFile, fileSignature } from './private-file.mjs';
import { hashToken } from './sessions.mjs';
import { assertOutsideRoot } from './store.mjs';

export const RECOVERY_FILE = 'recovery.json';
export const AUDIT_FILE = 'audit.json';
export const RECOVERY_SCHEMA_VERSION = 1;
export const AUDIT_SCHEMA_VERSION = 1;
export const MAX_AUDIT_EVENTS = 200;
export const AUDIT_EVENTS = Object.freeze(['token_sign_in', 'token_rotated', 'first_owner', 'recovery_enroll']);
export const AUDIT_RESULTS = Object.freeze(['ok', 'invalid', 'rate_limited', 'no_owner', 'owner_exists']);
// Results of a failed unauthenticated attempt, for these events; dropped first when trimming.
export const FAILURE_RESULTS = Object.freeze(['invalid', 'rate_limited']);
const ATTEMPT_EVENTS = Object.freeze(['token_sign_in', 'first_owner']);
// At most one rate_limited event per event type in this window.
export const RATE_LIMITED_COALESCE_MS = 60 * 1000;
export const RECOVERY_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const TOKEN_BYTES = 32;
const HASH_RE = /^[A-Za-z0-9_-]{43}$/;
const DEFAULT_LOCK_WAIT_MS = 1000;
const DEFAULT_LOCK_STALE_MS = 30000;
const RECOVERY_KEYS = ['schema_version', 'token_hash', 'created_at'];
const AUDIT_KEYS = ['schema_version', 'events'];
const EVENT_KEYS = ['at', 'event', 'result'];

export class RecoveryStoreError extends Error {
  constructor(message, code = 'invalid_store') {
    super(message);
    this.name = 'RecoveryStoreError';
    this.code = code;
  }
}

const fail = (message, code) => { throw new RecoveryStoreError(message, code); };
const isError = (error) => error instanceof RecoveryStoreError;

const recoveryFile = createPrivateFile({ label: 'Recovery token file', fail, isError });
const auditFile = createPrivateFile({ label: 'Audit log', fail, isError });

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const checkTimestamp = (value, at) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail(`${at} must be an ISO 8601 UTC timestamp`);
  }
};

const checkKeys = (value, keys, at) => {
  if (!isPlainObject(value)) fail(`${at} must be an object`);
  for (const key of keys) if (!Object.hasOwn(value, key)) fail(`${at} is missing ${key}`);
  for (const key of Object.keys(value)) if (!keys.includes(key)) fail(`${at} has an unknown field`);
};

/**
 * Validate a recovery token document. Returns it when valid.
 *
 * @param {unknown} data
 * @returns {{ schema_version: 1, token_hash: string, created_at: string }}
 */
export const validateRecoveryData = (data) => {
  checkKeys(data, RECOVERY_KEYS, 'recovery token file');
  if (data.schema_version !== RECOVERY_SCHEMA_VERSION) fail(`recovery token file schema_version must be ${RECOVERY_SCHEMA_VERSION}`, 'unsupported_schema');
  if (typeof data.token_hash !== 'string' || !HASH_RE.test(data.token_hash)) fail('recovery token file token_hash must be a base64url SHA-256 hash');
  checkTimestamp(data.created_at, 'recovery token file created_at');
  return data;
};

/**
 * Validate an audit log document. Returns it when valid.
 *
 * @param {unknown} data
 * @returns {{ schema_version: 1, events: { at: string, event: string, result: string }[] }}
 */
export const validateAuditData = (data) => {
  checkKeys(data, AUDIT_KEYS, 'audit log');
  if (data.schema_version !== AUDIT_SCHEMA_VERSION) fail(`audit log schema_version must be ${AUDIT_SCHEMA_VERSION}`, 'unsupported_schema');
  if (!Array.isArray(data.events) || data.events.length > MAX_AUDIT_EVENTS) fail(`audit log events must be an array of at most ${MAX_AUDIT_EVENTS} events`);
  data.events.forEach((entry, index) => {
    const at = `events[${index}]`;
    checkKeys(entry, EVENT_KEYS, at);
    checkTimestamp(entry.at, `${at}.at`);
    if (!AUDIT_EVENTS.includes(entry.event)) fail(`${at}.event is not a known event`);
    if (!AUDIT_RESULTS.includes(entry.result)) fail(`${at}.result is not a known result`);
  });
  return data;
};

const iso = (ms) => new Date(ms).toISOString();

/** True for a failed unauthenticated attempt; every other entry is notable. */
export const isFailedAttempt = (entry) => ATTEMPT_EVENTS.includes(entry.event) && FAILURE_RESULTS.includes(entry.result);

/**
 * Keep at most `max` of `events` (oldest first), in order: drop the oldest
 * failed attempts first, then, only if notable entries alone exceed `max`,
 * the oldest notable entries.
 *
 * @template {{ event: string, result: string }} T
 * @param {T[]} events
 * @param {number} [max]
 * @returns {T[]}
 */
export const trimAuditEvents = (events, max = MAX_AUDIT_EVENTS) => {
  const excess = events.length - max;
  if (excess <= 0) return events;
  const indexesWhere = (keep) => events.flatMap((entry, index) => (keep(entry) ? [index] : []));
  const failures = indexesWhere(isFailedAttempt);
  const dropFailures = Math.min(excess, failures.length);
  const dropped = new Set([
    ...failures.slice(0, dropFailures),
    ...indexesWhere((entry) => !isFailedAttempt(entry)).slice(0, excess - dropFailures),
  ]);
  return events.filter((_, index) => !dropped.has(index));
};

const constantTimeEqual = (a, b) => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
};

const checkOptions = ({ root, lockWaitMs, lockStaleMs }, name) => {
  if (typeof root !== 'string' || root === '') fail(`${name} requires the served root`, 'invalid_argument');
  for (const [key, value] of [['lockWaitMs', lockWaitMs], ['lockStaleMs', lockStaleMs]]) {
    if (!Number.isFinite(value) || value < 0) fail(`${key} must be a non-negative number of milliseconds`, 'invalid_argument');
  }
};

const pathChecker = (root, source) => (value) => {
  try {
    return path.resolve(assertOutsideRoot(value, root, source));
  } catch (error) {
    return fail(error.message, error.code);
  }
};

/**
 * Open the recovery token file at `file` for the Cockpit served from `root`.
 * Nothing is read or written until a method is called.
 *
 * @param {object} options
 * @param {string} options.file Absolute path of recovery.json (outside root).
 * @param {string} options.root Served Cockpit root.
 * @param {() => number} [options.now] Clock (tests).
 * @param {number} [options.lockWaitMs]
 * @param {number} [options.lockStaleMs]
 */
export const openRecoveryStore = ({
  file, root, now = Date.now, lockWaitMs = DEFAULT_LOCK_WAIT_MS, lockStaleMs = DEFAULT_LOCK_STALE_MS,
} = {}) => {
  checkOptions({ root, lockWaitMs, lockStaleMs }, 'openRecoveryStore');
  const checkPath = pathChecker(root, 'recovery token file');
  const storeFile = checkPath(file);
  const lockFile = `${storeFile}.lock`;
  const dir = path.dirname(storeFile);

  let cache = { signature: undefined, data: null };

  // The current document, or null when there is none. Throws when it is unsafe or invalid.
  const readCurrent = () => {
    checkPath(storeFile);
    let signature;
    try {
      signature = fileSignature(storeFile);
    } catch {
      fail('Recovery token file is unreadable', 'unreadable');
    }
    if (signature !== null && signature === cache.signature) return cache.data;
    let data = null;
    // fileSignature follows symlinks, so a dangling one looks missing; read
    // it anyway so it is refused as unsafe rather than taken as "no token".
    if (signature !== null || fs.lstatSync(storeFile, { throwIfNoEntry: false })) {
      recoveryFile.checkDir(dir);
      try {
        data = validateRecoveryData(recoveryFile.read(storeFile));
      } catch (error) {
        if (error.code !== 'missing') throw error;
      }
    }
    cache = { signature, data };
    return data;
  };

  // Write a new token under the lock. With `onlyIfMissing`, keep an existing
  // file (and refuse an invalid one); otherwise replace whatever is there, so
  // rotation also recovers from a corrupt file. Returns the new token, or
  // null when nothing was written.
  const replace = ({ onlyIfMissing }) => {
    checkPath(storeFile);
    recoveryFile.ensureDir(dir);
    return recoveryFile.withLock(lockFile, { waitMs: lockWaitMs, staleMs: lockStaleMs }, (isHeld) => {
      if (onlyIfMissing) {
        try {
          validateRecoveryData(recoveryFile.read(storeFile));
          return null;
        } catch (error) {
          if (error.code !== 'missing') throw error;
        }
      }
      const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
      const createdAt = iso(now());
      const next = validateRecoveryData({ schema_version: RECOVERY_SCHEMA_VERSION, token_hash: hashToken(token), created_at: createdAt });
      recoveryFile.write(storeFile, recoveryFile.serialize(next), () => {
        if (!isHeld()) fail('Another writer took over the recovery token lock; nothing was written', 'store_busy');
      });
      return { token, createdAt };
    });
  };

  return Object.freeze({
    file: storeFile,
    /**
     * Create the token if there is none. Returns { created: true, token,
     * createdAt } the first time (print the token once), else { created: false }.
     * An existing but invalid file is not replaced; it throws.
     */
    ensure: () => {
      const made = replace({ onlyIfMissing: true });
      return made ? { created: true, ...made } : { created: false };
    },
    /** Replace the token. Returns { token, createdAt }; print the token once. */
    rotate: () => replace({ onlyIfMissing: false }),
    /** True when `token` is the current recovery token. Throws for an invalid file. */
    check: (token) => {
      if (typeof token !== 'string' || !RECOVERY_TOKEN_RE.test(token)) return false;
      const data = readCurrent();
      // Hash first either way, so a missing file costs the same as a mismatch.
      const hash = hashToken(token);
      return data !== null && constantTimeEqual(hash, data.token_hash);
    },
    /** Creation time (ms) of the current token, or null if there is none. Throws for an invalid file. */
    createdAt: () => {
      const data = readCurrent();
      return data ? Date.parse(data.created_at) : null;
    },
    exists: () => readCurrent() !== null,
  });
};

/**
 * Open the recovery audit log at `file`. Nothing is read or written until a
 * method is called.
 *
 * @param {object} options
 * @param {string} options.file Absolute path of audit.json (outside root).
 * @param {string} options.root Served Cockpit root.
 * @param {() => number} [options.now] Clock (tests).
 * @param {number} [options.lockWaitMs]
 * @param {number} [options.lockStaleMs]
 */
export const openAuditLog = ({
  file, root, now = Date.now, lockWaitMs = DEFAULT_LOCK_WAIT_MS, lockStaleMs = DEFAULT_LOCK_STALE_MS,
} = {}) => {
  checkOptions({ root, lockWaitMs, lockStaleMs }, 'openAuditLog');
  const checkPath = pathChecker(root, 'audit log');
  const storeFile = checkPath(file);
  const lockFile = `${storeFile}.lock`;
  const dir = path.dirname(storeFile);
  const EMPTY = Object.freeze({ schema_version: AUDIT_SCHEMA_VERSION, events: Object.freeze([]) });

  const readFile = () => {
    try {
      return validateAuditData(auditFile.read(storeFile));
    } catch (error) {
      if (error.code === 'missing') return EMPTY;
      throw error;
    }
  };

  /**
   * Append { at, event, result }, then trim to MAX_AUDIT_EVENTS with
   * trimAuditEvents: the oldest failed attempts (invalid or rate_limited)
   * go first, and a notable entry goes only to make room for a newer notable
   * entry once notable entries alone fill the log. A failed attempt that
   * finds the log full of notable entries is therefore not written, nor is
   * a rate_limited event within a minute of the last one for the same event
   * type. Returns true when written. Throws RecoveryStoreError when the log
   * cannot be written (or is damaged: nothing is trimmed or rewritten then).
   */
  const record = (event, result) => {
    if (!AUDIT_EVENTS.includes(event)) fail('event is not a known event', 'invalid_argument');
    if (!AUDIT_RESULTS.includes(result)) fail('result is not a known result', 'invalid_argument');
    checkPath(storeFile);
    auditFile.ensureDir(dir);
    return auditFile.withLock(lockFile, { waitMs: lockWaitMs, staleMs: lockStaleMs }, (isHeld) => {
      const current = readFile();
      const nowMs = now();
      if (result === 'rate_limited') {
        const last = current.events.findLast((entry) => entry.event === event && entry.result === 'rate_limited');
        if (last && nowMs - Date.parse(last.at) < RATE_LIMITED_COALESCE_MS) return false;
      }
      const entry = { at: iso(nowMs), event, result };
      const events = trimAuditEvents([...current.events, entry]);
      if (events.at(-1) !== entry) return false;
      const next = validateAuditData({ schema_version: AUDIT_SCHEMA_VERSION, events });
      auditFile.write(storeFile, auditFile.serialize(next), () => {
        if (!isHeld()) fail('Another writer took over the audit log lock; nothing was written', 'store_busy');
      });
      return true;
    });
  };

  return Object.freeze({
    file: storeFile,
    record,
    /** Every kept event, newest first. */
    list: () => {
      checkPath(storeFile);
      auditFile.checkDir(dir);
      return readFile().events.map((entry) => ({ ...entry })).reverse();
    },
  });
};
