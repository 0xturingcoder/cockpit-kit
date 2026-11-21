// Sessions store (skill/lib/identity/sessions.mjs): hashing, expiry,
// revocation, concurrent sessions and writers, throttled last-seen writes,
// and file safety. User and credential ids are invented.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import {
  DEFAULT_SESSION_LIFETIME_MS, MAX_SESSIONS_PER_USER, SessionStoreError, hashToken, openSessionStore, validateSessionsData,
} from '../skill/lib/identity/sessions.mjs';

const posixOnly = { skip: process.platform === 'win32' ? 'POSIX permissions only' : false };
const DAY = 24 * 60 * 60 * 1000;
const OWNER = 'usr_ownerEXAMPLEonly0001';
const MEMBER = 'usr_memberEXAMPLEonly001';

const layout = () => {
  const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cockpit-sessions-')));
  const root = path.join(base, 'root');
  fs.mkdirSync(root);
  return { base, root, file: path.join(base, 'state', 'sessions.json') };
};

const clock = (start = Date.parse('2026-03-04T05:06:07.000Z')) => {
  const c = { at: start, now: () => c.at };
  return c;
};

const assertCode = (fn, code) => {
  assert.throws(fn, (error) => error instanceof SessionStoreError && error.code === code);
};

test('sessions: create returns a random token, stores only its hash, and records the device fields', () => {
  const { root, file } = layout();
  const c = clock();
  const sessions = openSessionStore({ file, root, now: c.now });
  const { token, session, maxAgeSeconds } = sessions.create({ userId: OWNER, credentialId: 'q83vEjRWeJA', label: 'Work laptop' });
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(maxAgeSeconds, DEFAULT_SESSION_LIFETIME_MS / 1000);
  assert.deepEqual(Object.keys(session).sort(), ['created_at', 'credential_id', 'expires_at', 'id', 'kind', 'label', 'last_seen_at', 'step_up_at', 'user_id']);
  assert.equal(session.kind, 'passkey');
  assert.equal(session.step_up_at, session.created_at, 'a passkey sign-in counts as a step-up');
  assert.equal(session.user_id, OWNER);
  assert.equal(session.label, 'Work laptop');
  assert.equal(session.created_at, '2026-03-04T05:06:07.000Z');
  assert.equal(session.last_seen_at, session.created_at);
  assert.equal(Date.parse(session.expires_at) - Date.parse(session.created_at), 90 * DAY);

  const text = fs.readFileSync(file, 'utf8');
  assert.ok(!text.includes(token), 'the raw token is never written');
  assert.ok(text.includes(hashToken(token)));
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(sessions.load().sessions[0].token_hash, hashToken(token));
  assert.deepEqual(sessions.validate(token), session);
  assert.equal(sessions.validate(`${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`), null);
  assert.equal(sessions.validate(''), null);
  assert.equal(sessions.validate(session.id), null, 'the public id is not a credential');
  assert.equal(sessions.validate(hashToken(token)), null, 'the stored hash is not a credential');
});

test('sessions: each sign-in gets its own session, and they are independent', () => {
  const { root, file } = layout();
  const sessions = openSessionStore({ file, root });
  const a = sessions.create({ userId: OWNER, label: 'Laptop' });
  const b = sessions.create({ userId: OWNER, label: 'Phone' });
  const m = sessions.create({ userId: MEMBER });
  assert.notEqual(a.token, b.token);
  assert.notEqual(a.session.id, b.session.id);
  assert.deepEqual(sessions.list({ userId: OWNER }).map((s) => s.label).sort(), ['Laptop', 'Phone']);
  assert.equal(sessions.list().length, 3);
  assert.equal(sessions.revoke(a.session.id).id, a.session.id);
  assert.equal(sessions.validate(a.token), null, 'revoked: rejected on the next check');
  assert.equal(sessions.validate(b.token).id, b.session.id, 'other sessions are untouched');
  assert.equal(sessions.validate(m.token).user_id, MEMBER);
  assert.equal(sessions.revoke(a.session.id), null);
  assert.equal(sessions.revokeUser(OWNER).length, 1);
  assert.equal(sessions.validate(b.token), null);
});

test('sessions: expiry is enforced on every check and expired sessions are pruned on the next write', () => {
  const { root, file } = layout();
  const c = clock();
  const sessions = openSessionStore({ file, root, now: c.now, lifetimeMs: DAY });
  const { token, maxAgeSeconds } = sessions.create({ userId: OWNER });
  assert.equal(maxAgeSeconds, 86400);
  c.at += DAY - 1;
  assert.ok(sessions.validate(token));
  c.at += 1;
  assert.equal(sessions.validate(token), null, 'expired at expires_at exactly');
  assert.deepEqual(sessions.list(), []);
  assert.equal(sessions.load().sessions.length, 1, 'still on disk until the next write');
  sessions.create({ userId: MEMBER });
  assert.deepEqual(sessions.load().sessions.map((s) => s.user_id), [MEMBER]);
});

test('sessions: the lifetime is configurable within bounds', () => {
  const { root, file } = layout();
  assert.equal(openSessionStore({ file, root, lifetimeMs: 5 * 60 * 1000 }).lifetimeMs, 300000);
  assertCode(() => openSessionStore({ file, root, lifetimeMs: 1000 }), 'invalid_argument');
  assertCode(() => openSessionStore({ file, root, lifetimeMs: 401 * DAY }), 'invalid_argument');
  assertCode(() => openSessionStore({ file, root, lifetimeMs: DAY + 0.5 }), 'invalid_argument');
});

test('sessions: revocation by another process is seen on the next check', () => {
  const { root, file } = layout();
  const server = openSessionStore({ file, root });
  const cli = openSessionStore({ file, root });
  const { token, session } = server.create({ userId: OWNER });
  assert.ok(server.validate(token));
  cli.revoke(session.id);
  assert.equal(server.validate(token), null);
});

test('sessions: last_seen_at is written at most once per interval, so requests do not write the file', () => {
  const { root, file } = layout();
  const c = clock();
  const sessions = openSessionStore({ file, root, now: c.now, lastSeenIntervalMs: 60000 });
  const { token, session } = sessions.create({ userId: OWNER });
  const inode = () => fs.statSync(file).ino;
  const first = inode();
  for (let i = 0; i < 50; i += 1) {
    c.at += 1000;
    assert.ok(sessions.validate(token));
  }
  // 50 s of requests: no write yet.
  assert.equal(inode(), first);
  c.at += 10000;
  assert.ok(sessions.validate(token));
  assert.notEqual(inode(), first, 'one write after the interval');
  assert.equal(sessions.get(session.id).last_seen_at, new Date(c.at).toISOString());
  const second = inode();
  c.at += 1000;
  sessions.validate(token);
  assert.equal(inode(), second);
});

test('sessions: a busy store skips the last-seen write instead of blocking or failing the request', posixOnly, () => {
  const { root, file } = layout();
  const c = clock();
  const sessions = openSessionStore({ file, root, now: c.now, lastSeenIntervalMs: 1000 });
  const { token, session } = sessions.create({ userId: OWNER });
  fs.writeFileSync(`${file}.lock`, 'someone-else', { mode: 0o600 });
  c.at += 5000;
  const started = Date.now();
  assert.ok(sessions.validate(token), 'still valid');
  assert.ok(Date.now() - started < 500, 'does not wait for the lock');
  assert.equal(sessions.get(session.id).last_seen_at, session.last_seen_at);
  // Create and revoke do wait, then report store_busy.
  const busy = openSessionStore({ file, root, now: c.now, lockWaitMs: 50 });
  assertCode(() => busy.revoke(session.id), 'store_busy');
  fs.rmSync(`${file}.lock`);
  assert.ok(busy.revoke(session.id));
});

test('sessions: each user keeps at most MAX_SESSIONS_PER_USER, dropping the least recently seen', () => {
  const { root, file } = layout();
  const c = clock();
  const sessions = openSessionStore({ file, root, now: c.now });
  const created = [];
  for (let i = 0; i < MAX_SESSIONS_PER_USER; i += 1) {
    c.at += 1000;
    created.push(sessions.create({ userId: OWNER, label: `Device ${i}` }));
  }
  sessions.create({ userId: MEMBER });
  c.at += 1000;
  const extra = sessions.create({ userId: OWNER, label: 'Newest' });
  const mine = sessions.list({ userId: OWNER });
  assert.equal(mine.length, MAX_SESSIONS_PER_USER);
  assert.equal(sessions.validate(created[0].token), null, 'the oldest was dropped');
  assert.ok(sessions.validate(extra.token));
  assert.equal(sessions.list({ userId: MEMBER }).length, 1);
});

test('sessions: revokeCredential removes the sessions created with that passkey', () => {
  const { root, file } = layout();
  const sessions = openSessionStore({ file, root });
  const a = sessions.create({ userId: OWNER, credentialId: 'AAAA' });
  const b = sessions.create({ userId: OWNER, credentialId: 'BBBB' });
  assert.deepEqual(sessions.revokeCredential('AAAA').map((s) => s.id), [a.session.id]);
  assert.equal(sessions.validate(a.token), null);
  assert.ok(sessions.validate(b.token));
});

test('sessions: input is validated', () => {
  const { root, file } = layout();
  const sessions = openSessionStore({ file, root });
  assertCode(() => sessions.create({ userId: 'x' }), 'invalid_argument');
  assertCode(() => sessions.create({ userId: OWNER, label: 'a‮b' }), 'invalid_argument');
  assertCode(() => sessions.create({ userId: OWNER, label: 'x'.repeat(65) }), 'invalid_argument');
  assertCode(() => sessions.create({ userId: OWNER, credentialId: 'not base64url!' }), 'invalid_argument');
  assert.equal(fs.existsSync(file), false, 'nothing written');
});

test('sessions: the file is validated and fails closed', posixOnly, () => {
  const { root, file } = layout();
  const sessions = openSessionStore({ file, root });
  const { token } = sessions.create({ userId: OWNER });
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  const write = (value) => {
    fs.writeFileSync(`${file}.new`, typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
    fs.renameSync(`${file}.new`, file);
  };
  write({ ...doc, extra: 1 });
  assertCode(() => sessions.validate(token), 'invalid_store');
  write({ ...doc, schema_version: 3 });
  assertCode(() => sessions.validate(token), 'unsupported_schema');
  write({ ...doc, schema_version: 1 });
  assertCode(() => sessions.validate(token), 'invalid_store');
  write({ ...doc, sessions: [{ ...doc.sessions[0], kind: 'token' }] });
  assertCode(() => sessions.validate(token), 'invalid_store');
  write({ ...doc, sessions: [{ ...doc.sessions[0], kind: 'recovery', credential_id: 'q83vEjRWeJA' }] });
  assertCode(() => sessions.validate(token), 'invalid_store');
  write({ ...doc, sessions: [{ ...doc.sessions[0], step_up_at: 'yesterday' }] });
  assertCode(() => sessions.validate(token), 'invalid_store');
  write({ ...doc, sessions: [doc.sessions[0], doc.sessions[0]] });
  assertCode(() => sessions.validate(token), 'duplicate_id');
  write('{not json');
  assertCode(() => sessions.validate(token), 'invalid_store');
  write(doc);
  fs.chmodSync(file, 0o644);
  assertCode(() => sessions.validate(token), 'unsafe_permissions');
  fs.chmodSync(file, 0o600);
  assert.ok(sessions.validate(token));
  assert.throws(() => validateSessionsData({ ...doc, sessions: [{ ...doc.sessions[0], token: token }] }), /unknown field/);
});

test('sessions: the file must be outside the served root', () => {
  const { root } = layout();
  assertCode(() => openSessionStore({ file: path.join(root, 'sessions.json'), root }), 'unsafe_path');
  assertCode(() => openSessionStore({ file: 'relative/sessions.json', root }), 'unsafe_path');
});

test('sessions: two processes creating sessions at once do not lose updates', async () => {
  const { root, file } = layout();
  const url = new URL('../skill/lib/identity/sessions.mjs', import.meta.url).href;
  const script = `
    import { openSessionStore } from ${JSON.stringify(url)};
    const [file, root, userId] = process.argv.slice(1);
    const sessions = openSessionStore({ file, root, lockWaitMs: 20000 });
    for (let i = 0; i < 12; i += 1) sessions.create({ userId, label: 'Concurrent' });`;
  const run = (userId) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, file, root, userId], { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`writer exited ${code}: ${stderr}`))));
  });
  await Promise.all([run(OWNER), run(MEMBER)]);
  const sessions = openSessionStore({ file, root });
  assert.equal(sessions.list({ userId: OWNER }).length, 12);
  assert.equal(sessions.list({ userId: MEMBER }).length, 12);
  assert.equal(new Set(sessions.load().sessions.map((s) => s.token_hash)).size, 24);
  assert.deepEqual(fs.readdirSync(path.dirname(file)).filter((name) => name !== 'sessions.json'), []);
});

test('sessions: tokens have 256 bits of randomness and do not repeat', () => {
  const { root, file } = layout();
  const sessions = openSessionStore({ file, root });
  const tokens = new Set(Array.from({ length: 20 }, () => sessions.create({ userId: crypto.randomBytes(9).toString('base64url') }).token));
  assert.equal(tokens.size, 20);
  for (const token of tokens) assert.equal(Buffer.from(token, 'base64url').length, 32);
});

test('sessions: version 1 files load as passkey sessions without a step-up and are written back as version 2', () => {
  const { root, file } = layout();
  const c = clock();
  const sessions = openSessionStore({ file, root, now: c.now });
  const { token } = sessions.create({ userId: OWNER, credentialId: 'q83vEjRWeJA', label: 'Work laptop' });
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  const v1 = { schema_version: 1, sessions: doc.sessions.map(({ kind: _kind, step_up_at: _stepUp, ...rest }) => rest) };
  fs.writeFileSync(`${file}.new`, JSON.stringify(v1), { mode: 0o600 });
  fs.renameSync(`${file}.new`, file);
  const loaded = sessions.validate(token);
  assert.equal(loaded.kind, 'passkey');
  assert.equal(loaded.step_up_at, null, 'an upgraded session has to step up before adding a passkey');
  sessions.create({ userId: MEMBER });
  const written = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(written.schema_version, 2);
  assert.deepEqual(written.sessions.map((s) => [s.kind, s.step_up_at === null]), [['passkey', true], ['passkey', false]]);
});

test('sessions: recovery sessions have no passkey, start without a step-up, can be shorter, and are revoked by kind', () => {
  const { root, file } = layout();
  const c = clock();
  const sessions = openSessionStore({ file, root, now: c.now });
  const recovery = sessions.create({ userId: OWNER, kind: 'recovery', label: 'Recovery (server token)', maxLifetimeMs: 12 * 60 * 60 * 1000 });
  assert.equal(recovery.session.kind, 'recovery');
  assert.equal(recovery.session.credential_id, null);
  assert.equal(recovery.session.step_up_at, null);
  assert.equal(recovery.maxAgeSeconds, 12 * 60 * 60);
  assert.equal(Date.parse(recovery.session.expires_at) - Date.parse(recovery.session.created_at), 12 * 60 * 60 * 1000);
  // maxLifetimeMs only shortens.
  const short = openSessionStore({ file, root, now: c.now, lifetimeMs: 60 * 60 * 1000 });
  assert.equal(short.create({ userId: OWNER, kind: 'recovery', maxLifetimeMs: 12 * 60 * 60 * 1000 }).maxAgeSeconds, 3600);
  assertCode(() => sessions.create({ userId: OWNER, kind: 'recovery', credentialId: 'q83vEjRWeJA' }), 'invalid_argument');
  assertCode(() => sessions.create({ userId: OWNER, kind: 'token' }), 'invalid_argument');

  c.at += 60 * 1000;
  const stepped = sessions.markStepUp(recovery.session.id);
  assert.equal(stepped.step_up_at, new Date(c.at).toISOString());
  assert.equal(sessions.validate(recovery.token).step_up_at, stepped.step_up_at);
  assert.equal(sessions.markStepUp('ses_AAAAAAAAAAAAAAAAAAAAAA'), null);

  const passkey = sessions.create({ userId: OWNER, credentialId: 'q83vEjRWeJA' });
  const revoked = sessions.revokeKind('recovery');
  assert.equal(revoked.length, 2);
  assert.ok(revoked.every((s) => s.kind === 'recovery'));
  assert.equal(sessions.validate(recovery.token), null);
  assert.ok(sessions.validate(passkey.token));
});
