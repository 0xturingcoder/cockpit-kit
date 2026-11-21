// Invites store (skill/lib/identity/invites.mjs): hashing, single use,
// expiry with an injected clock, pruning, the pending cap, revocation,
// restoring after a retryable failure, fail-closed loading, and two processes
// spending one invite at once. Users are invented; tokens are generated at
// runtime.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import {
  DEFAULT_INVITE_LIFETIME_MS, InviteStoreError, MAX_PENDING_INVITES, openInviteStore, validateInvitesData,
} from '../skill/lib/identity/invites.mjs';
import { hashToken } from '../skill/lib/identity/sessions.mjs';

const posixOnly = { skip: process.platform === 'win32' ? 'POSIX permissions only' : false };
const HOUR = 60 * 60 * 1000;
const OWNER = 'usr_ownerEXAMPLEonly0001';

const layout = () => {
  const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cockpit-invites-')));
  const root = path.join(base, 'root');
  fs.mkdirSync(root);
  return { base, root, file: path.join(base, 'state', 'invites.json') };
};

const clock = (start = Date.parse('2026-03-04T05:06:07.000Z')) => {
  const c = { at: start, now: () => c.at };
  return c;
};

const assertCode = (fn, code) => {
  assert.throws(fn, (error) => error instanceof InviteStoreError && error.code === code);
};

const writeFile = (file, doc) => {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(doc), { mode: 0o600 });
};

test('invites: create returns a random token once, stores only its hash, and binds a new member', () => {
  const { root, file } = layout();
  const c = clock();
  const invites = openInviteStore({ file, root, now: c.now });
  const { token, invite } = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(token, 'base64url').length, 32);
  assert.deepEqual(Object.keys(invite).sort(), ['created_at', 'created_by', 'display_name', 'expires_at', 'id', 'role', 'user_id']);
  assert.match(invite.id, /^inv_[A-Za-z0-9_-]{22}$/);
  assert.match(invite.user_id, /^usr_[A-Za-z0-9_-]{22}$/);
  assert.equal(invite.display_name, 'Test Member');
  assert.equal(invite.role, 'member');
  assert.equal(invite.created_by, OWNER);
  assert.equal(invite.created_at, '2026-03-04T05:06:07.000Z');
  assert.equal(Date.parse(invite.expires_at) - Date.parse(invite.created_at), DEFAULT_INVITE_LIFETIME_MS);
  assert.equal(DEFAULT_INVITE_LIFETIME_MS, 24 * HOUR);

  const text = fs.readFileSync(file, 'utf8');
  assert.ok(!text.includes(token), 'the raw token is never written');
  assert.ok(text.includes(hashToken(token)));
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(invites.list(), [invite]);
  assert.ok(!JSON.stringify(invites.list()).includes('token_hash'), 'listing never includes the hash');
  assert.deepEqual(invites.find(token), invite);
  assert.equal(invites.find(hashToken(token)), null, 'the stored hash is not a token');
  assert.equal(invites.find(invite.id), null, 'the public id is not a token');
});

test('invites: find refuses malformed tokens without reading anything', () => {
  const { root, file } = layout();
  const invites = openInviteStore({ file, root });
  const { token } = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  for (const bad of [undefined, null, 42, {}, '', `${token}=`, `${token}A`, token.slice(1), `${token.slice(0, -1)}!`, ` ${token.slice(1)}`]) {
    assert.equal(invites.find(bad), null, String(bad));
    assert.equal(invites.spend(bad, 'inv_AAAAAAAAAAAAAAAAAAAAAA'), null);
  }
  assert.equal(invites.find(`${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`), null);
});

test('invites: spend is single use and requires the matching invite id', () => {
  const { root, file } = layout();
  const invites = openInviteStore({ file, root });
  const a = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  const b = invites.create({ displayName: 'Other Member', createdBy: OWNER });
  assert.equal(invites.spend(a.token, b.invite.id), null, "a token cannot spend another invite's id");
  assert.equal(invites.list().length, 2, 'a mismatched spend changes nothing');
  assert.deepEqual(invites.spend(a.token, a.invite.id), a.invite);
  assert.equal(invites.spend(a.token, a.invite.id), null, 'replay: the second spend gets nothing');
  assert.equal(invites.find(a.token), null);
  assert.deepEqual(invites.list(), [b.invite]);
  assert.ok(!fs.readFileSync(file, 'utf8').includes(hashToken(a.token)), 'a spent invite is deleted');
});

test('invites: expiry is checked against the clock, and expired invites are pruned on the next write', () => {
  const { root, file } = layout();
  const c = clock();
  const invites = openInviteStore({ file, root, now: c.now, lifetimeMs: HOUR });
  const old = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  c.at += HOUR - 1;
  assert.deepEqual(invites.find(old.token), old.invite, 'live until the expiry instant');
  c.at += 1;
  assert.equal(invites.find(old.token), null, 'expired at expires_at');
  assert.deepEqual(invites.list(), []);
  assert.equal(invites.spend(old.token, old.invite.id), null);
  assert.ok(!fs.readFileSync(file, 'utf8').includes(old.invite.id), 'the spend attempt pruned it');

  const fresh = invites.create({ displayName: 'Other Member', createdBy: OWNER });
  c.at += 2 * HOUR;
  invites.create({ displayName: 'Third Member', createdBy: OWNER });
  assert.ok(!fs.readFileSync(file, 'utf8').includes(fresh.invite.id), 'expired invites are pruned on create');
});

test('invites: the lifetime is fixed at creation', () => {
  const { root, file } = layout();
  const c = clock();
  const short = openInviteStore({ file, root, now: c.now, lifetimeMs: HOUR });
  const created = short.create({ displayName: 'Test Member', createdBy: OWNER });
  const long = openInviteStore({ file, root, now: c.now, lifetimeMs: 7 * 24 * HOUR });
  c.at += HOUR;
  assert.equal(long.find(created.token), null, 'a longer lifetime later does not extend an existing invite');
});

test('invites: revoke deletes a pending invite; unknown ids return null', () => {
  const { root, file } = layout();
  const invites = openInviteStore({ file, root });
  const { token, invite } = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  assert.equal(invites.revoke('inv_AAAAAAAAAAAAAAAAAAAAAA'), null);
  assert.deepEqual(invites.revoke(invite.id), invite);
  assert.equal(invites.revoke(invite.id), null);
  assert.equal(invites.find(token), null);
  assert.equal(invites.spend(token, invite.id), null);
});

test('invites: at most 32 are pending; expired ones do not count', () => {
  const { root, file } = layout();
  const c = clock();
  const invites = openInviteStore({ file, root, now: c.now, lifetimeMs: HOUR });
  for (let i = 0; i < MAX_PENDING_INVITES; i += 1) invites.create({ displayName: `Member ${i}`, createdBy: OWNER });
  assertCode(() => invites.create({ displayName: 'One Too Many', createdBy: OWNER }), 'too_many_invites');
  c.at += HOUR;
  invites.create({ displayName: 'After Expiry', createdBy: OWNER });
  assert.equal(invites.load().invites.length, 1);
});

test('invites: create validates the display name and creator', () => {
  const { root, file } = layout();
  const invites = openInviteStore({ file, root });
  for (const bad of ['', ' Padded', 'x'.repeat(129), 'Line\nbreak', 'Zero​width', 'Bidi‮flip', 42, undefined]) {
    assertCode(() => invites.create({ displayName: bad, createdBy: OWNER }), 'invalid_argument');
  }
  assertCode(() => invites.create({ displayName: 'Test Member', createdBy: 'short' }), 'invalid_argument');
  assert.equal(fs.existsSync(file), false, 'nothing was written');
  assert.equal(invites.create({ displayName: 'x'.repeat(128), createdBy: OWNER }).invite.display_name.length, 128);
});

test('invites: restore puts a spent invite back only while it is live and unique', () => {
  const { root, file } = layout();
  const c = clock();
  const invites = openInviteStore({ file, root, now: c.now, lifetimeMs: HOUR });
  const { token, invite } = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  const spent = invites.spend(token, invite.id);
  assert.equal(invites.restore(token, spent), true);
  assert.deepEqual(invites.find(token), invite);
  assert.equal(invites.restore(token, spent), false, 'not twice');
  assert.equal(invites.list().length, 1);
  invites.spend(token, invite.id);
  c.at += HOUR;
  assert.equal(invites.restore(token, spent), false, 'not after expiry');
  assert.equal(invites.find(token), null);
});

test('invites: loading fails closed on unknown fields, bad values, and unsupported schema', () => {
  const { root, file } = layout();
  const invites = openInviteStore({ file, root });
  const { invite } = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  const good = JSON.parse(fs.readFileSync(file, 'utf8'));
  const cases = [
    [{ ...good, extra: 1 }, 'invalid_store'],
    [{ ...good, schema_version: 2 }, 'unsupported_schema'],
    [{ ...good, invites: [{ ...good.invites[0], token: 'x' }] }, 'invalid_store'],
    [{ ...good, invites: [{ ...good.invites[0], role: 'owner' }] }, 'invalid_store'],
    [{ ...good, invites: [{ ...good.invites[0], token_hash: 'short' }] }, 'invalid_store'],
    [{ ...good, invites: [{ ...good.invites[0], expires_at: good.invites[0].created_at }] }, 'invalid_store'],
    [{ ...good, invites: [good.invites[0], { ...good.invites[0], id: 'inv_BBBBBBBBBBBBBBBBBBBBBB' }] }, 'duplicate_id'],
    [{ ...good, invites: Array.from({ length: MAX_PENDING_INVITES + 1 }, () => good.invites[0]) }, 'invalid_store'],
  ];
  for (const [doc, code] of cases) {
    writeFile(file, doc);
    assertCode(() => invites.list(), code);
    assertCode(() => invites.find('A'.repeat(43)), code);
    assertCode(() => invites.revoke(invite.id), code);
  }
  fs.writeFileSync(file, '{not json', { mode: 0o600 });
  assert.throws(() => invites.list(), (error) => error instanceof InviteStoreError && !error.message.includes('not json'));
  assert.deepEqual(validateInvitesData(good), good);
});

test('invites: the file must be outside the root, private, and not a symlink', posixOnly, () => {
  const { base, root, file } = layout();
  assertCode(() => openInviteStore({ file: path.join(root, 'invites.json'), root }), 'unsafe_path');
  assertCode(() => openInviteStore({ file: 'relative/invites.json', root }), 'unsafe_path');
  const invites = openInviteStore({ file, root });
  invites.create({ displayName: 'Test Member', createdBy: OWNER });
  fs.chmodSync(file, 0o644);
  assertCode(() => invites.list(), 'unsafe_permissions');
  fs.chmodSync(file, 0o600);
  const target = path.join(base, 'elsewhere.json');
  fs.renameSync(file, target);
  fs.symlinkSync(target, file);
  assertCode(() => invites.list(), 'unsafe_file');
});

test('invites: lifetimes outside 5 minutes to 7 days are refused', () => {
  const { root, file } = layout();
  for (const bad of [5 * 60 * 1000 - 1, 7 * 24 * HOUR + 1, 0, Number.NaN, '24h']) {
    assertCode(() => openInviteStore({ file, root, lifetimeMs: bad }), 'invalid_argument');
  }
  assert.equal(openInviteStore({ file, root, lifetimeMs: 5 * 60 * 1000 }).lifetimeMs, 5 * 60 * 1000);
  assert.equal(openInviteStore({ file, root, lifetimeMs: 7 * 24 * HOUR }).lifetimeMs, 7 * 24 * HOUR);
});

test('invites: a busy lock makes changes fail with store_busy and writes nothing', () => {
  const { root, file } = layout();
  const invites = openInviteStore({ file, root, lockWaitMs: 50 });
  const { token, invite } = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  fs.writeFileSync(`${file}.lock`, 'another-writer', { mode: 0o600 });
  try {
    assertCode(() => invites.spend(token, invite.id), 'store_busy');
    assertCode(() => invites.create({ displayName: 'Other Member', createdBy: OWNER }), 'store_busy');
    assert.deepEqual(invites.find(token), invite, 'reads do not need the lock');
  } finally {
    fs.rmSync(`${file}.lock`, { force: true });
  }
  assert.deepEqual(invites.spend(token, invite.id), invite);
});

test('invites: two processes spending the same invite at once: exactly one wins', async () => {
  const { root, file } = layout();
  const invites = openInviteStore({ file, root });
  const { token, invite } = invites.create({ displayName: 'Test Member', createdBy: OWNER });
  const url = new URL('../skill/lib/identity/invites.mjs', import.meta.url).href;
  // The token reaches the children on stdin, never on a command line.
  const script = `
    import { openInviteStore } from ${JSON.stringify(url)};
    const [file, root, inviteId] = process.argv.slice(1);
    let token = '';
    for await (const chunk of process.stdin) token += chunk;
    const invites = openInviteStore({ file, root, lockWaitMs: 20000 });
    let won = 0;
    for (let i = 0; i < 5; i += 1) if (invites.spend(token, inviteId)) won += 1;
    process.stdout.write(String(won));`;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, file, root, invite.id], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve(Number(stdout)) : reject(new Error(`spender exited ${code}: ${stderr}`))));
    child.stdin.end(token);
  });
  const wins = await Promise.all([run(), run(), run(), run()]);
  assert.equal(wins.reduce((a, b) => a + b, 0), 1, `exactly one spend succeeded: ${wins}`);
  assert.deepEqual(invites.list(), []);
  assert.deepEqual(fs.readdirSync(path.dirname(file)).filter((name) => name !== 'invites.json'), []);
});
