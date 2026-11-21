// Private JSON files outside the served root: the identity store
// (store.mjs) and the sessions store (sessions.mjs) share this code, so both
// get the same file safety. See docs/identity-store.md#file-safety.
//
// - Reads open the file once without following a final symlink, check what
//   was opened (regular file, owner, no group/world bits, size cap), and read
//   from that same descriptor.
// - Writes go to an exclusive 0600 temp file in the same directory, are
//   fsynced, then renamed over the file.
// - Changes hold a lock file (<file>.lock) carrying a random token; a lock is
//   only removed if its token still matches.
// - Messages never include file content or system error text (which can
//   contain the absolute path).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const MAX_FILE_BYTES = 1024 * 1024;
const CHECK_MODE = process.platform !== 'win32';
// Open without following a final symlink, and without blocking on a FIFO,
// where the platform has those flags.
const READ_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);

const sleep = (ms) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };

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

// The write lock is a file, <file>.lock, holding a random token that names
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

/**
 * File operations for one kind of private JSON file.
 *
 * @param {object} options
 * @param {string} options.label Capitalized name used in messages, e.g. "Identity store".
 * @param {(message: string, code?: string) => never} options.fail Throws the caller's error type.
 * @param {(error: unknown) => boolean} options.isError True for errors thrown by `fail`, which pass through unchanged.
 * @param {string} [options.missingMessage] Message for a missing file (code "missing").
 * @param {string} [options.fullHint] Appended to the "would exceed" message (code "store_full").
 */
export const createPrivateFile = ({ label, fail, isError, missingMessage = `${label} does not exist yet`, fullHint = '' }) => {
  const lower = label.toLowerCase();
  const notRegular = `${label} must be a regular file, not a symlink`;

  const open = (file) => {
    if (!fs.constants.O_NOFOLLOW) {
      // No O_NOFOLLOW on this platform (Windows): refuse a symlink up front.
      let stat;
      try {
        stat = fs.lstatSync(file);
      } catch (error) {
        if (error.code === 'ENOENT') fail(missingMessage, 'missing');
        fail(`${label} is unreadable`, 'unreadable');
      }
      if (stat.isSymbolicLink()) fail(notRegular, 'unsafe_file');
    }
    try {
      return fs.openSync(file, READ_FLAGS);
    } catch (error) {
      if (error.code === 'ENOENT') fail(missingMessage, 'missing');
      // O_NOFOLLOW on a symlink fails with ELOOP (EMLINK on some BSDs).
      if (error.code === 'ELOOP' || error.code === 'EMLINK') fail(notRegular, 'unsafe_file');
      // Node's own message includes the absolute path; do not pass it through.
      return fail(`${label} is unreadable`, 'unreadable');
    }
  };

  // Open once without following symlinks, check what was actually opened
  // (fstat), and read from that same descriptor, so the path cannot be
  // swapped between the checks and the read. Returns the parsed JSON, not
  // yet validated.
  const read = (file) => {
    const fd = open(file);
    let bytes;
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile()) fail(notRegular, 'unsafe_file');
      if (CHECK_MODE && (stat.mode & 0o077) !== 0) fail(`${label} must not be accessible by group or others (chmod 600)`, 'unsafe_permissions');
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) fail(`${label} must be owned by the service user`, 'unsafe_permissions');
      if (stat.size > MAX_FILE_BYTES) fail(`${label} is larger than ${MAX_FILE_BYTES} bytes`);
      bytes = readAtMost(fd, MAX_FILE_BYTES + 1);
    } catch (error) {
      if (isError(error)) throw error;
      fail(`${label} is unreadable`, 'unreadable');
    } finally {
      fs.closeSync(fd);
    }
    // The file may have grown after fstat; the bound applies to what was read.
    if (bytes.length > MAX_FILE_BYTES) fail(`${label} is larger than ${MAX_FILE_BYTES} bytes`);
    try {
      return JSON.parse(bytes.toString('utf8'));
    } catch {
      // JSON.parse messages can quote file content; do not pass them through.
      return fail(`${label} is not valid JSON`);
    }
  };

  // Serialize before touching the disk, and refuse anything read() would refuse.
  const serialize = (data) => {
    const text = `${JSON.stringify(data, null, 2)}\n`;
    if (Buffer.byteLength(text, 'utf8') > MAX_FILE_BYTES) {
      fail(`${label} would exceed ${MAX_FILE_BYTES} bytes${fullHint ? `; ${fullHint}` : ''}`, 'store_full');
    }
    return text;
  };

  const write = (file, text, beforeRename = () => {}) => {
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

  // Anyone who can write to the file's directory can rename a file over it,
  // so the directory itself must not be a symlink or writable by group or
  // others. A missing directory is left to the caller.
  const checkDir = (dir) => {
    let stat;
    try {
      stat = fs.lstatSync(dir);
    } catch (error) {
      if (error.code === 'ENOENT') return;
      fail(`${label} directory is unreadable`, 'unreadable');
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) fail(`${label} directory must be a directory, not a symlink`, 'unsafe_path');
    if (CHECK_MODE && (stat.mode & 0o022) !== 0) fail(`${label} directory must not be writable by group or others (chmod 700)`, 'unsafe_permissions');
  };

  const ensureDir = (dir) => {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    checkDir(dir);
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
        fail(`Cannot take the ${lower} lock`, 'store_busy');
      }
      if (Date.now() > deadline) fail(`${label} is locked by another writer`, 'store_busy');
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

  return Object.freeze({ read, serialize, write, checkDir, ensureDir, withLock });
};

/**
 * Identity of the file currently at `file` (device, inode, size, and times),
 * or null if there is none. Readers compare it to skip re-reading an
 * unchanged file; any write by this module renames a new inode into place,
 * so a change is always visible here.
 *
 * @param {string} file
 * @returns {string | null}
 */
export const fileSignature = (file) => {
  const stat = fs.statSync(file, { throwIfNoEntry: false, bigint: true });
  return stat ? `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}` : null;
};
