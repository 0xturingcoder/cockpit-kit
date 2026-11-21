// Users and passkey credentials for one Cockpit, stored as a private JSON
// file outside the served root.
//
// This is the single place later identity features (WebAuthn sign-in,
// sessions, invites) read identities from. Callers only use the functions
// returned by openIdentityStore(), so the file can later be replaced by a
// small database without changing them. Schema and API: docs/identity-store.md.
//
// Guarantees:
// - The store path must resolve (lexically and by real path) outside the
//   served root; openIdentityStore() refuses otherwise.
// - Writes go to an exclusive 0600 temp file in the same directory, are
//   fsynced, then renamed over the store, so a reader sees the old file or
//   the new one, never a partial one. Mutations hold a short lock file that
//   carries a random token, and re-read the file first, so concurrent writers
//   do not lose updates. A lock is only removed (on release or stale
//   takeover) if its token still matches, and a writer that lost its lock
//   writes nothing.
// - A write whose serialized size exceeds the 1 MiB load cap is refused
//   ("store_full") before anything is written.
// - Loading fails closed: a symlink, a file another user owns, a file with
//   any group/world permission bit, invalid JSON, an unknown field, a bad or
//   duplicate id, an unknown role, or anything other than exactly one owner
//   is an error. Permissions are not repaired silently; run `chmod 600`.
// - Error messages name fields by position (users[0].credentials[1].id) and
//   never include credential ids, public keys, or other stored values.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isPathInside } from '../paths.mjs';

export const IDENTITY_SCHEMA_VERSION = 1;
export const IDENTITY_STORE_FILE = 'identity.json';
export const ROLES = Object.freeze(['owner', 'member']);

// The serialized file is capped at 1 MiB, and this cap is the binding limit.
// The per-field limits below bound each record but do not add up to a store
// that fits: one credential at the field maxima takes about 4.5 KB (about 230
// fit), a typical passkey about 0.4 KB (about 2,500 fit). A write that would
// exceed the cap is refused with "store_full" and nothing is written, so the
// store always stays loadable.
export const MAX_FILE_BYTES = 1024 * 1024;
const MAX_USERS = 1000;
const MAX_CREDENTIALS_PER_USER = 32;
// WebAuthn credential ids are at most 1023 bytes.
const MAX_CREDENTIAL_ID_BYTES = 1023;
const MAX_PUBLIC_KEY_BYTES = 2048;
const MAX_TRANSPORTS = 8;
const MAX_DISPLAY_NAME = 128;
const MAX_LABEL = 64;
const MAX_COUNTER = 0xffffffff;
const USER_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const TRANSPORT_RE = /^[a-z][a-z0-9-]{0,31}$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
const DEFAULT_LOCK_WAIT_MS = 5000;
const DEFAULT_LOCK_STALE_MS = 30000;
const CHECK_MODE = process.platform !== 'win32';
// Open without following a final symlink, and without blocking on a FIFO,
// where the platform has those flags.
const READ_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);

const STORE_KEYS = ['schema_version', 'users'];
const USER_KEYS = ['id', 'display_name', 'role', 'disabled', 'created_at', 'credentials'];
const CREDENTIAL_KEYS = ['id', 'public_key', 'counter', 'transports', 'created_at', 'label'];

export class IdentityStoreError extends Error {
  constructor(message, code = 'invalid_store') {
    super(message);
    this.name = 'IdentityStoreError';
    this.code = code;
  }
}

const fail = (message, code) => { throw new IdentityStoreError(message, code); };

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const sleep = (ms) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };

// ---------------------------------------------------------------------------
// Field validation. Messages cite `at` (a field path), never the value.

const checkKeys = (value, allowed, at) => {
  if (!isPlainObject(value)) fail(`${at} must be an object`);
  for (const key of allowed) if (!Object.hasOwn(value, key)) fail(`${at} is missing ${key}`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${at} has an unknown field`);
};

const checkText = (value, { at, min, max }) => {
  if (typeof value !== 'string') fail(`${at} must be a string`);
  if (value !== value.trim()) fail(`${at} must not start or end with whitespace`);
  if ([...value].length < min || [...value].length > max) fail(`${at} must be ${min} to ${max} characters`);
  if (CONTROL_RE.test(value)) fail(`${at} must not contain control characters`);
  return value;
};

const checkTimestamp = (value, at) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail(`${at} must be an ISO 8601 UTC timestamp like 2026-01-02T03:04:05.000Z`);
  }
  return value;
};

// Canonical unpadded base64url: decoding and re-encoding gives the same text.
const checkBase64url = (value, { at, maxBytes }) => {
  if (typeof value !== 'string' || value === '' || !BASE64URL_RE.test(value)) fail(`${at} must be non-empty unpadded base64url`);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || bytes.toString('base64url') !== value) fail(`${at} must be canonical unpadded base64url`);
  if (bytes.length > maxBytes) fail(`${at} must decode to at most ${maxBytes} bytes`);
  return bytes;
};

const checkUserId = (value, at) => {
  if (typeof value !== 'string' || !USER_ID_RE.test(value)) fail(`${at} must be 8 to 64 characters of A-Z, a-z, 0-9, _ or -`, 'invalid_id');
  return value;
};

const checkRole = (value, at) => {
  if (!ROLES.includes(value)) fail(`${at} must be one of: ${ROLES.join(', ')}`, 'invalid_role');
  return value;
};

const checkCounter = (value, at) => {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_COUNTER) fail(`${at} must be an integer from 0 to ${MAX_COUNTER}`);
  return value;
};

const checkTransports = (value, at) => {
  if (!Array.isArray(value) || value.length > MAX_TRANSPORTS) fail(`${at} must be an array of at most ${MAX_TRANSPORTS} strings`);
  value.forEach((transport, index) => {
    if (typeof transport !== 'string' || !TRANSPORT_RE.test(transport)) fail(`${at}[${index}] must be a lowercase transport name such as usb, nfc, ble, hybrid, or internal`);
  });
  if (new Set(value).size !== value.length) fail(`${at} must not repeat a transport`);
  return value;
};

const checkPublicKey = (value, at) => {
  const bytes = checkBase64url(value, { at, maxBytes: MAX_PUBLIC_KEY_BYTES });
  // A COSE_Key is a CBOR map (major type 5). Full decoding is the verifier's job.
  if (bytes[0] >> 5 !== 5) fail(`${at} must be a COSE key (CBOR map)`);
  return value;
};

const checkCredential = (credential, at) => {
  checkKeys(credential, CREDENTIAL_KEYS, at);
  checkBase64url(credential.id, { at: `${at}.id`, maxBytes: MAX_CREDENTIAL_ID_BYTES });
  checkPublicKey(credential.public_key, `${at}.public_key`);
  checkCounter(credential.counter, `${at}.counter`);
  checkTransports(credential.transports, `${at}.transports`);
  checkTimestamp(credential.created_at, `${at}.created_at`);
  checkText(credential.label, { at: `${at}.label`, min: 0, max: MAX_LABEL });
};

const checkUser = (user, at) => {
  checkKeys(user, USER_KEYS, at);
  checkUserId(user.id, `${at}.id`);
  checkText(user.display_name, { at: `${at}.display_name`, min: 1, max: MAX_DISPLAY_NAME });
  checkRole(user.role, `${at}.role`);
  if (typeof user.disabled !== 'boolean') fail(`${at}.disabled must be true or false`);
  checkTimestamp(user.created_at, `${at}.created_at`);
  if (!Array.isArray(user.credentials) || user.credentials.length > MAX_CREDENTIALS_PER_USER) {
    fail(`${at}.credentials must be an array of at most ${MAX_CREDENTIALS_PER_USER} credentials`);
  }
  user.credentials.forEach((credential, index) => checkCredential(credential, `${at}.credentials[${index}]`));
};

/**
 * Validate a whole store document. Throws IdentityStoreError on the first
 * problem; returns the same object when it is valid.
 *
 * @param {unknown} data Parsed store document.
 * @returns {IdentityData}
 */
export const validateIdentityData = (data) => {
  checkKeys(data, STORE_KEYS, 'identity store');
  if (data.schema_version !== IDENTITY_SCHEMA_VERSION) fail(`identity store schema_version must be ${IDENTITY_SCHEMA_VERSION}`, 'unsupported_schema');
  if (!Array.isArray(data.users) || data.users.length > MAX_USERS) fail(`identity store users must be an array of at most ${MAX_USERS} users`);
  data.users.forEach((user, index) => checkUser(user, `users[${index}]`));

  const userIds = new Map();
  const credentialIds = new Map();
  data.users.forEach((user, userIndex) => {
    if (userIds.has(user.id)) fail(`users[${userIndex}].id duplicates users[${userIds.get(user.id)}].id`, 'duplicate_id');
    userIds.set(user.id, userIndex);
    user.credentials.forEach((credential, credentialIndex) => {
      const at = `users[${userIndex}].credentials[${credentialIndex}]`;
      if (credentialIds.has(credential.id)) fail(`${at}.id duplicates ${credentialIds.get(credential.id)}.id; credential ids must be unique across all users`, 'duplicate_id');
      credentialIds.set(credential.id, at);
    });
  });

  const owners = data.users.filter((user) => user.role === 'owner').length;
  if (owners !== 1) fail(`identity store must have exactly one owner (found ${owners})`, 'owner_required');
  return data;
};

// ---------------------------------------------------------------------------
// Pure transforms. Each takes a valid document and returns a new one.

const newUserId = () => `usr_${crypto.randomBytes(16).toString('base64url')}`;

const nowIso = (now) => new Date(now()).toISOString();

const toBase64url = (value, at, maxBytes) => {
  if (value instanceof Uint8Array) {
    if (value.length === 0) fail(`${at} must not be empty`, 'invalid_argument');
    return Buffer.from(value).toString('base64url');
  }
  if (typeof value === 'string') {
    checkBase64url(value, { at, maxBytes });
    return value;
  }
  return fail(`${at} must be a Uint8Array or a base64url string`, 'invalid_argument');
};

const userIndexOf = (data, userId) => {
  const index = data.users.findIndex((user) => user.id === userId);
  if (index === -1) fail('No user with that id', 'not_found');
  return index;
};

const credentialPosition = (data, credentialId) => {
  for (let userIndex = 0; userIndex < data.users.length; userIndex += 1) {
    const credentialIndex = data.users[userIndex].credentials.findIndex((credential) => credential.id === credentialId);
    if (credentialIndex !== -1) return { userIndex, credentialIndex };
  }
  return fail('No credential with that id', 'not_found');
};

const replaceUser = (data, userIndex, user) => ({
  ...data,
  users: data.users.map((existing, index) => (index === userIndex ? user : existing)),
});

const applyCreateUser = (data, { id, displayName, role, now }) => {
  const userId = id === undefined ? newUserId() : checkUserId(id, 'id');
  checkText(displayName, { at: 'displayName', min: 1, max: MAX_DISPLAY_NAME });
  checkRole(role, 'role');
  if (data.users.some((user) => user.id === userId)) fail('A user with that id already exists', 'duplicate_id');
  if (role === 'owner' && data.users.some((user) => user.role === 'owner')) fail('The store already has an owner; exactly one owner is allowed', 'owner_required');
  if (role !== 'owner' && !data.users.some((user) => user.role === 'owner')) fail('The first user must be the owner', 'owner_required');
  const user = { id: userId, display_name: displayName, role, disabled: false, created_at: nowIso(now), credentials: [] };
  return { data: { ...data, users: [...data.users, user] }, result: user };
};

const applyAddCredential = (data, userId, { id, publicKey, counter = 0, transports = [], label = '', now }) => {
  const userIndex = userIndexOf(data, userId);
  const user = data.users[userIndex];
  if (user.disabled) fail('Cannot add a credential to a disabled user', 'user_disabled');
  const credential = {
    id: toBase64url(id, 'credential id', MAX_CREDENTIAL_ID_BYTES),
    public_key: toBase64url(publicKey, 'publicKey', MAX_PUBLIC_KEY_BYTES),
    counter: checkCounter(counter, 'counter'),
    transports: [...checkTransports(transports, 'transports')],
    created_at: nowIso(now),
    label: checkText(label, { at: 'label', min: 0, max: MAX_LABEL }),
  };
  if (data.users.some((existing) => existing.credentials.some((other) => other.id === credential.id))) {
    fail('That credential id is already registered', 'duplicate_id');
  }
  const next = { ...user, credentials: [...user.credentials, credential] };
  return { data: replaceUser(data, userIndex, next), result: credential };
};

// WebAuthn signature counters only move forward. Authenticators that do not
// implement a counter always report 0; 0 -> 0 is accepted as a no-op.
const applyUpdateCounter = (data, credentialId, counter) => {
  checkCounter(counter, 'counter');
  const { userIndex, credentialIndex } = credentialPosition(data, credentialId);
  const user = data.users[userIndex];
  const credential = user.credentials[credentialIndex];
  if (user.disabled) fail('Cannot update a credential of a disabled user', 'user_disabled');
  if (counter === 0 && credential.counter === 0) return { data, result: credential, unchanged: true };
  if (counter <= credential.counter) fail('Signature counter did not increase; the authenticator may be cloned', 'counter_regression');
  const updated = { ...credential, counter };
  const next = { ...user, credentials: user.credentials.map((existing, index) => (index === credentialIndex ? updated : existing)) };
  return { data: replaceUser(data, userIndex, next), result: updated };
};

const applyRemoveCredential = (data, credentialId) => {
  const { userIndex, credentialIndex } = credentialPosition(data, credentialId);
  const user = data.users[userIndex];
  const removed = user.credentials[credentialIndex];
  const next = { ...user, credentials: user.credentials.filter((_, index) => index !== credentialIndex) };
  return { data: replaceUser(data, userIndex, next), result: removed };
};

const applyDisableUser = (data, userId) => {
  const userIndex = userIndexOf(data, userId);
  const user = data.users[userIndex];
  if (user.role === 'owner') fail('The owner cannot be disabled', 'owner_required');
  if (user.disabled) return { data, result: user, unchanged: true };
  const next = { ...user, disabled: true };
  return { data: replaceUser(data, userIndex, next), result: next };
};

// ---------------------------------------------------------------------------
// Lookups over a loaded document.

/**
 * Find a user by id in a loaded document.
 *
 * @param {IdentityData} data
 * @param {string} userId
 * @returns {IdentityUser | null}
 */
export const findUser = (data, userId) => data.users.find((user) => user.id === userId) ?? null;

/**
 * Find a credential (and its user) by base64url credential id.
 *
 * @param {IdentityData} data
 * @param {string} credentialId
 * @returns {{ user: IdentityUser, credential: IdentityCredential } | null}
 */
export const findCredential = (data, credentialId) => {
  for (const user of data.users) {
    const credential = user.credentials.find((candidate) => candidate.id === credentialId);
    if (credential) return { user, credential };
  }
  return null;
};

// ---------------------------------------------------------------------------
// Path checks and file I/O.

const lexicallyInside = (child, parent) => {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
};

/**
 * Throw unless `file` is outside `root`, comparing both the resolved path
 * (so `..` cannot sneak back in) and the real path (so symlinked
 * directories cannot alias the served tree).
 *
 * @param {string} file Store file path (absolute).
 * @param {string} root Served Cockpit root.
 * @param {string} [source] Name used in the error message.
 */
export const assertOutsideRoot = (file, root, source = 'identity store') => {
  if (typeof file !== 'string' || !path.isAbsolute(file)) fail(`${source} path must be absolute`, 'unsafe_path');
  if (lexicallyInside(file, root) || isPathInside(file, root)) {
    fail(`${source} must be outside the served Cockpit root`, 'unsafe_path');
  }
  return file;
};

const NOT_REGULAR = 'Identity store must be a regular file, not a symlink';

const openStoreFile = (file) => {
  if (!fs.constants.O_NOFOLLOW) {
    // No O_NOFOLLOW on this platform (Windows): refuse a symlink up front.
    let stat;
    try {
      stat = fs.lstatSync(file);
    } catch (error) {
      if (error.code === 'ENOENT') fail('Identity store does not exist yet; create the owner first', 'missing');
      fail('Identity store is unreadable', 'unreadable');
    }
    if (stat.isSymbolicLink()) fail(NOT_REGULAR, 'unsafe_file');
  }
  try {
    return fs.openSync(file, READ_FLAGS);
  } catch (error) {
    if (error.code === 'ENOENT') fail('Identity store does not exist yet; create the owner first', 'missing');
    // O_NOFOLLOW on a symlink fails with ELOOP (EMLINK on some BSDs).
    if (error.code === 'ELOOP' || error.code === 'EMLINK') fail(NOT_REGULAR, 'unsafe_file');
    // Node's own message includes the absolute path; do not pass it through.
    return fail('Identity store is unreadable', 'unreadable');
  }
};

const readAtMost = (fd, limit) => {
  const buffer = Buffer.alloc(limit);
  let length = 0;
  while (length < limit) {
    const count = fs.readSync(fd, buffer, length, limit - length, length);
    if (count === 0) break;
    length += count;
  }
  return buffer.subarray(0, length);
};

// Open once without following symlinks, check what was actually opened
// (fstat), and read from that same descriptor, so the path cannot be
// swapped between the checks and the read.
const readStoreFile = (file) => {
  const fd = openStoreFile(file);
  let bytes;
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) fail(NOT_REGULAR, 'unsafe_file');
    if (CHECK_MODE && (stat.mode & 0o077) !== 0) fail('Identity store must not be accessible by group or others (chmod 600)', 'unsafe_permissions');
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) fail('Identity store must be owned by the service user', 'unsafe_permissions');
    if (stat.size > MAX_FILE_BYTES) fail(`Identity store is larger than ${MAX_FILE_BYTES} bytes`);
    bytes = readAtMost(fd, MAX_FILE_BYTES + 1);
  } catch (error) {
    if (error instanceof IdentityStoreError) throw error;
    fail('Identity store is unreadable', 'unreadable');
  } finally {
    fs.closeSync(fd);
  }
  // The file may have grown after fstat; the bound applies to what was read.
  if (bytes.length > MAX_FILE_BYTES) fail(`Identity store is larger than ${MAX_FILE_BYTES} bytes`);
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    // JSON.parse messages can quote file content; do not pass them through.
    fail('Identity store is not valid JSON');
  }
  return validateIdentityData(parsed);
};

const fsyncDir = (dir) => {
  if (process.platform === 'win32') return;
  let fd;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch {
    // Best effort: some filesystems refuse fsync on directories.
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
};

// Serialize before touching the disk, and refuse anything load() would refuse.
const serialize = (data) => {
  const text = `${JSON.stringify(data, null, 2)}\n`;
  if (Buffer.byteLength(text, 'utf8') > MAX_FILE_BYTES) {
    fail(`Identity store would exceed ${MAX_FILE_BYTES} bytes; remove unused users or credentials first`, 'store_full');
  }
  return text;
};

const writeStoreFile = (file, text, beforeRename = () => {}) => {
  const dir = path.dirname(file);
  const temp = path.join(dir, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  const fd = fs.openSync(temp, 'wx', 0o600);
  try {
    try {
      fs.writeFileSync(fd, text, 'utf8');
      fs.fchmodSync(fd, 0o600);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    beforeRename();
    fs.renameSync(temp, file);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
  fsyncDir(dir);
};

// Anyone who can write to the store's directory can rename a file over the
// store, so the directory itself must not be a symlink or writable by group
// or others. A missing directory is left to the caller.
const checkDir = (dir) => {
  let stat;
  try {
    stat = fs.lstatSync(dir);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    fail('Identity store directory is unreadable', 'unreadable');
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail('Identity store directory must be a directory, not a symlink', 'unsafe_path');
  if (CHECK_MODE && (stat.mode & 0o022) !== 0) fail('Identity store directory must not be writable by group or others (chmod 700)', 'unsafe_permissions');
};

const ensureDir = (dir) => {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  checkDir(dir);
};

// The write lock is a file, <store>.lock, holding a random token that names
// its owner. It is written to a temp file and hard-linked into place, which
// fails with EEXIST while another writer holds it, so the lock never exists
// half-written.

// Returns { token, mtimeMs } for the lock at `lockFile`, or null if none.
const readLock = (lockFile) => {
  let fd;
  try {
    fd = fs.openSync(lockFile, READ_FLAGS);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    const buffer = Buffer.alloc(64);
    const length = stat.isFile() ? fs.readSync(fd, buffer, 0, buffer.length, 0) : 0;
    return { token: buffer.toString('utf8', 0, length), mtimeMs: stat.mtimeMs };
  } finally {
    fs.closeSync(fd);
  }
};

const createLock = (lockFile, token) => {
  const temp = `${lockFile}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(temp, token, { flag: 'wx', mode: 0o600 });
  try {
    fs.linkSync(temp, lockFile);
    return true;
  } catch (error) {
    if (error.code === 'EEXIST') return false;
    throw error;
  } finally {
    fs.rmSync(temp, { force: true });
  }
};

// Remove the lock only if it still carries `token`. Renaming it to a unique
// name first means only one process can claim a given lock file. If what was
// moved turns out to be someone else's lock (it was re-taken in between), it
// is linked straight back.
const removeLockIf = (lockFile, token) => {
  const aside = `${lockFile}.${crypto.randomBytes(6).toString('hex')}.stale`;
  try {
    fs.renameSync(lockFile, aside);
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
  try {
    if (readLock(aside)?.token === token) return true;
    try {
      fs.linkSync(aside, lockFile);
    } catch {
      // A newer lock is already in place; leave it alone.
    }
    return false;
  } finally {
    fs.rmSync(aside, { recursive: true, force: true });
  }
};

// Run fn(isHeld) while holding the lock. isHeld() reports whether the lock
// still carries this writer's token, so a writer whose lock was taken over
// can stop before it writes.
const withLock = (lockFile, { waitMs, staleMs }, fn) => {
  const token = crypto.randomBytes(16).toString('hex');
  const deadline = Date.now() + waitMs;
  for (;;) {
    let current;
    try {
      if (createLock(lockFile, token)) break;
      current = readLock(lockFile);
      if (!current) continue;
      // A lock older than staleMs is presumed abandoned; locks are held only
      // for one read-modify-write, which takes milliseconds.
      if (Date.now() - current.mtimeMs > staleMs && removeLockIf(lockFile, current.token)) continue;
    } catch {
      fail('Cannot take the identity store lock', 'store_busy');
    }
    if (Date.now() > deadline) fail('Identity store is locked by another writer', 'store_busy');
    sleep(25);
  }
  const isHeld = () => {
    try {
      return readLock(lockFile)?.token === token;
    } catch {
      return false;
    }
  };
  try {
    return fn(isHeld);
  } finally {
    try {
      removeLockIf(lockFile, token);
    } catch {
      // Leave it; it becomes stale and is taken over later.
    }
  }
};

const EMPTY = Object.freeze({ schema_version: IDENTITY_SCHEMA_VERSION, users: Object.freeze([]) });

const clone = (value) => structuredClone(value);

/**
 * Open the identity store at `file` for the Cockpit served from `root`.
 * Nothing is read or written until a method is called.
 *
 * Every method returns plain copies; mutating them does not change the store.
 *
 * The API is synchronous. A mutator waits for the write lock by blocking the
 * thread (up to `lockWaitMs`, 5 s by default), so a server should keep
 * mutators off latency-sensitive request paths such as sign-in, or account
 * for that wait.
 *
 * @param {object} options
 * @param {string} options.file Absolute path of the store file (outside root).
 * @param {string} options.root Served Cockpit root.
 * @param {() => number} [options.now] Clock for created_at (tests).
 * @param {number} [options.lockWaitMs] How long a mutator waits for a busy lock before throwing "store_busy".
 * @param {number} [options.lockStaleMs] Age after which a lock is presumed abandoned and taken over.
 * @returns {IdentityStore}
 */
export const openIdentityStore = ({
  file, root, now = Date.now, lockWaitMs = DEFAULT_LOCK_WAIT_MS, lockStaleMs = DEFAULT_LOCK_STALE_MS,
} = {}) => {
  if (typeof root !== 'string' || root === '') fail('openIdentityStore requires the served root', 'invalid_argument');
  for (const [name, value] of [['lockWaitMs', lockWaitMs], ['lockStaleMs', lockStaleMs]]) {
    if (!Number.isFinite(value) || value < 0) fail(`${name} must be a non-negative number of milliseconds`, 'invalid_argument');
  }
  const storeFile = path.resolve(assertOutsideRoot(file, root));
  const lockFile = `${storeFile}.lock`;
  const lockOptions = { waitMs: lockWaitMs, staleMs: lockStaleMs };

  // Read, transform, validate, and atomically write under the lock. A missing
  // file starts from an empty document only for createUser (bootstrap).
  const mutate = (transform, { allowMissing = false } = {}) => {
    assertOutsideRoot(storeFile, root);
    ensureDir(path.dirname(storeFile));
    return withLock(lockFile, lockOptions, (isHeld) => {
      let current;
      try {
        current = readStoreFile(storeFile);
      } catch (error) {
        if (!(allowMissing && error.code === 'missing')) throw error;
        current = EMPTY;
      }
      const { data, result, unchanged } = transform(current);
      if (!unchanged) {
        writeStoreFile(storeFile, serialize(validateIdentityData(data)), () => {
          if (!isHeld()) fail('Another writer took over the identity store lock; nothing was written', 'store_busy');
        });
      }
      return clone(result);
    });
  };

  return Object.freeze({
    file: storeFile,
    load: () => {
      assertOutsideRoot(storeFile, root);
      checkDir(path.dirname(storeFile));
      return clone(readStoreFile(storeFile));
    },
    createUser: ({ id, displayName, role = 'member' } = {}) => mutate(
      (data) => applyCreateUser(data, { id, displayName, role, now }),
      { allowMissing: true },
    ),
    addCredential: (userId, credential = {}) => mutate((data) => applyAddCredential(data, userId, { ...credential, now })),
    updateCounter: (credentialId, counter) => mutate((data) => applyUpdateCounter(data, credentialId, counter)),
    removeCredential: (credentialId) => mutate((data) => applyRemoveCredential(data, credentialId)),
    disableUser: (userId) => mutate((data) => applyDisableUser(data, userId)),
  });
};

/**
 * @typedef {object} IdentityCredential
 * @property {string} id Credential id, unpadded base64url (unique across all users).
 * @property {string} public_key COSE_Key bytes, unpadded base64url.
 * @property {number} counter Last accepted signature counter (0..2^32-1).
 * @property {string[]} transports Authenticator transport hints, e.g. ["internal", "hybrid"].
 * @property {string} created_at ISO 8601 UTC timestamp.
 * @property {string} label Operator-facing device label (may be empty).
 *
 * @typedef {object} IdentityUser
 * @property {string} id Stable opaque id (8-64 chars of A-Z a-z 0-9 _ -).
 * @property {string} display_name 1-128 characters, no control characters.
 * @property {'owner' | 'member'} role
 * @property {boolean} disabled Disabled users must not sign in.
 * @property {string} created_at ISO 8601 UTC timestamp.
 * @property {IdentityCredential[]} credentials
 *
 * @typedef {object} IdentityData
 * @property {1} schema_version
 * @property {IdentityUser[]} users Exactly one has role "owner".
 *
 * @typedef {object} IdentityStore
 * @property {string} file Resolved store path.
 * @property {() => IdentityData} load Read and validate the whole store.
 * @property {(input: { displayName: string, role?: 'owner' | 'member', id?: string }) => IdentityUser} createUser
 *   Add a user (generated id unless `id` is given). The first user must be the owner and creates the file.
 * @property {(userId: string, input: { id: Uint8Array | string, publicKey: Uint8Array | string, counter?: number, transports?: string[], label?: string }) => IdentityCredential} addCredential
 *   Register a credential for an enabled user.
 * @property {(credentialId: string, counter: number) => IdentityCredential} updateCounter
 *   Record a newer signature counter; throws code "counter_regression" if it does not increase (0 -> 0 is allowed).
 * @property {(credentialId: string) => IdentityCredential} removeCredential Remove a credential and return it.
 * @property {(userId: string) => IdentityUser} disableUser Disable a member (the owner cannot be disabled).
 */
