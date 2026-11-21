// Recovery token file and audit log (skill/lib/identity/recovery.mjs):
// first-start creation, rotation, constant-format checks, audit bounds and
// coalescing, fail-closed loading, and nothing secret on disk. Tokens are
// generated at runtime.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import {
  MAX_AUDIT_EVENTS, RecoveryStoreError, openAuditLog, openRecoveryStore, validateAuditData, validateRecoveryData,
} from '../skill/lib/identity/recovery.mjs';
import { hashToken } from '../skill/lib/identity/sessions.mjs';
import { parseServeConfig } from '../skill/lib/serve-config.mjs';
import { makeServeRoot } from './support/serve-harness.mjs';

const posixOnly = { skip: process.platform === 'win32' ? 'POSIX permissions only' : false };

const layout = () => {
  const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cockpit-recovery-')));
  const root = path.join(base, 'root');
  fs.mkdirSync(root);
  return { base, root, file: path.join(base, 'state', 'recovery.json'), audit: path.join(base, 'state', 'audit.json') };
};

const clock = (start = Date.parse('2026-03-04T05:06:07.000Z')) => {
  const c = { at: start, now: () => c.at };
  return c;
};

const assertCode = (fn, code) => {
  assert.throws(fn, (error) => error instanceof RecoveryStoreError && error.code === code);
};

const replaceFile = (file, value) => {
  fs.writeFileSync(`${file}.new`, typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(`${file}.new`, file);
};

test('recovery: ensure creates a token once, stores only its hash, and later calls never return it', () => {
  const { root, file } = layout();
  const c = clock();
  const recovery = openRecoveryStore({ file, root, now: c.now });
  assert.equal(recovery.exists(), false);
  assert.equal(recovery.check('A'.repeat(43)), false, 'no file matches nothing');
  const first = recovery.ensure();
  assert.equal(first.created, true);
  assert.match(first.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(first.token, 'base64url').length, 32);
  assert.deepEqual(recovery.ensure(), { created: false }, 'a later start never prints it again');
  assert.deepEqual(openRecoveryStore({ file, root }).ensure(), { created: false });

  const text = fs.readFileSync(file, 'utf8');
  assert.ok(!text.includes(first.token), 'the token is never written');
  assert.deepEqual(JSON.parse(text), { schema_version: 1, token_hash: hashToken(first.token), created_at: '2026-03-04T05:06:07.000Z' });
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(recovery.createdAt(), c.at);

  assert.equal(recovery.check(first.token), true);
  for (const wrong of ['', first.token.slice(1), `${first.token}A`, hashToken(first.token), first.token.toUpperCase() === first.token ? 'b'.repeat(43) : first.token.toUpperCase(), 42, null, undefined]) {
    assert.equal(recovery.check(wrong), false, String(wrong));
  }
});

test('recovery: rotate replaces the token, the old one stops matching, and another process sees it on the next check', () => {
  const { root, file } = layout();
  const c = clock();
  const recovery = openRecoveryStore({ file, root, now: c.now });
  const { token: old } = recovery.ensure();
  const other = openRecoveryStore({ file, root });
  assert.equal(other.check(old), true);
  c.at += 1000;
  const rotated = recovery.rotate();
  assert.notEqual(rotated.token, old);
  assert.equal(rotated.createdAt, new Date(c.at).toISOString());
  assert.equal(other.check(old), false, 'the cached reader picks up the new file');
  assert.equal(other.check(rotated.token), true);
  assert.equal(other.createdAt(), c.at);
  assert.ok(!fs.readFileSync(file, 'utf8').includes(rotated.token));
});

test('recovery: an invalid, unsafe, or unknown-schema file fails closed and is not replaced by ensure', posixOnly, () => {
  const { root, file } = layout();
  const recovery = openRecoveryStore({ file, root });
  const { token } = recovery.ensure();
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  replaceFile(file, { ...doc, token: token });
  assertCode(() => recovery.check(token), 'invalid_store');
  assertCode(() => recovery.ensure(), 'invalid_store');
  replaceFile(file, { ...doc, schema_version: 2 });
  assertCode(() => recovery.check(token), 'unsupported_schema');
  replaceFile(file, { ...doc, token_hash: 'short' });
  assertCode(() => recovery.createdAt(), 'invalid_store');
  replaceFile(file, '{not json');
  assertCode(() => recovery.check(token), 'invalid_store');
  // Rotation replaces a corrupt file, so the operator can always recover.
  const rotated = recovery.rotate();
  assert.equal(recovery.check(rotated.token), true);
  assert.equal(recovery.check(token), false);
  replaceFile(file, doc);
  fs.chmodSync(file, 0o644);
  assertCode(() => recovery.check(token), 'unsafe_permissions');
  fs.chmodSync(file, 0o600);
  assert.equal(recovery.check(token), true);
  fs.rmSync(file);
  fs.symlinkSync(path.join(root, 'elsewhere.json'), file);
  assertCode(() => recovery.check(token), 'unsafe_file');
  assert.throws(() => validateRecoveryData({ ...doc, extra: 1 }), /unknown field/);
  assertCode(() => openRecoveryStore({ file: path.join(root, 'recovery.json'), root }), 'unsafe_path');
});

test('recovery: two processes ensuring at once create exactly one token', async () => {
  const { root, file } = layout();
  const url = new URL('../skill/lib/identity/recovery.mjs', import.meta.url).href;
  const script = `
    import { openRecoveryStore } from ${JSON.stringify(url)};
    const [file, root] = process.argv.slice(1);
    process.stdout.write(String(openRecoveryStore({ file, root, lockWaitMs: 20000 }).ensure().created));`;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, file, root], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve(stdout) : reject(new Error(`exited ${code}`))));
  });
  const results = await Promise.all([run(), run(), run()]);
  assert.deepEqual(results.sort(), ['false', 'false', 'true']);
});

test('audit: events hold only time, event, and result, newest first, bounded to the last 200', () => {
  const { root, audit } = layout();
  const c = clock();
  const log = openAuditLog({ file: audit, root, now: c.now });
  assert.deepEqual(log.list(), []);
  assert.equal(log.record('token_sign_in', 'invalid'), true);
  c.at += 1000;
  assert.equal(log.record('token_sign_in', 'ok'), true);
  assert.deepEqual(log.list(), [
    { at: '2026-03-04T05:06:08.000Z', event: 'token_sign_in', result: 'ok' },
    { at: '2026-03-04T05:06:07.000Z', event: 'token_sign_in', result: 'invalid' },
  ]);
  if (process.platform !== 'win32') assert.equal(fs.statSync(audit).mode & 0o777, 0o600);
  for (let i = 0; i < MAX_AUDIT_EVENTS + 5; i += 1) {
    c.at += 1000;
    log.record('token_rotated', 'ok');
  }
  const events = log.list();
  assert.equal(events.length, MAX_AUDIT_EVENTS);
  assert.ok(events.every((entry) => entry.event === 'token_rotated'), 'the oldest events were dropped');
  assert.equal(events[0].at, new Date(c.at).toISOString());
  for (const entry of events) assert.deepEqual(Object.keys(entry), ['at', 'event', 'result']);
  assertCode(() => log.record('token_sign_in', 'secret'), 'invalid_argument');
  assertCode(() => log.record('anything', 'ok'), 'invalid_argument');
});

test('audit: rate_limited events are written at most once per minute per event type', () => {
  const { root, audit } = layout();
  const c = clock();
  const log = openAuditLog({ file: audit, root, now: c.now });
  assert.equal(log.record('token_sign_in', 'rate_limited'), true);
  for (let i = 0; i < 20; i += 1) {
    c.at += 2000;
    assert.equal(log.record('token_sign_in', 'rate_limited'), false);
  }
  assert.equal(log.record('first_owner', 'rate_limited'), true, 'counted per event type');
  assert.equal(log.record('token_sign_in', 'invalid'), true, 'other results are always written');
  c.at = Date.parse('2026-03-04T05:07:07.000Z');
  assert.equal(log.record('token_sign_in', 'rate_limited'), true, 'a minute later another one is written');
  assert.equal(log.list().filter((entry) => entry.result === 'rate_limited').length, 3);
});

test('audit: an invalid or unsafe log fails closed for reads and writes', posixOnly, () => {
  const { root, audit } = layout();
  const log = openAuditLog({ file: audit, root });
  log.record('token_sign_in', 'ok');
  const doc = JSON.parse(fs.readFileSync(audit, 'utf8'));
  replaceFile(audit, { ...doc, events: [{ ...doc.events[0], ip: '192.0.2.1' }] });
  assertCode(() => log.list(), 'invalid_store');
  assertCode(() => log.record('token_sign_in', 'ok'), 'invalid_store');
  replaceFile(audit, { ...doc, events: Array(MAX_AUDIT_EVENTS + 1).fill(doc.events[0]) });
  assertCode(() => log.list(), 'invalid_store');
  replaceFile(audit, doc);
  fs.chmodSync(audit, 0o640);
  assertCode(() => log.record('token_sign_in', 'ok'), 'unsafe_permissions');
  fs.chmodSync(audit, 0o600);
  assert.equal(log.list().length, 1);
  assert.throws(() => validateAuditData({ ...doc, schema_version: 2 }), /schema_version/);
  // A held lock makes the write fail rather than wait forever.
  fs.writeFileSync(`${audit}.lock`, 'another-writer', { mode: 0o600 });
  assertCode(() => openAuditLog({ file: audit, root, lockWaitMs: 50 }).record('token_sign_in', 'ok'), 'store_busy');
});

test('serve config: the recovery token file and audit log sit next to the identity store, which may not take their names', () => {
  const serve = makeServeRoot();
  const parse = (argv) => parseServeConfig({ argv: ['--identity-store', serve.identityStore, ...argv], env: serve.env });
  const config = parse(['--passkeys']);
  assert.equal(config.recoveryStore, path.join(path.dirname(serve.identityStore), 'recovery.json'));
  assert.equal(config.auditStore, path.join(path.dirname(serve.identityStore), 'audit.json'));
  assert.equal(parse([]).recoveryStore, null);
  for (const name of ['recovery.json', 'audit.json']) {
    const clash = path.join(serve.base, 'state', name);
    assert.throws(() => parseServeConfig({ argv: ['--passkeys', '--identity-store', clash], env: serve.env }), new RegExp(`must not be named ${name.replace('.', '\\.')}`));
  }
});
