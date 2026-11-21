import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import {
  IDENTITY_SCHEMA_VERSION, IdentityStoreError, MAX_FILE_BYTES, assertOutsideRoot, findCredential, findUser, openIdentityStore, validateIdentityData,
} from '../skill/lib/identity/store.mjs';
import { parseServeConfig } from '../skill/lib/serve-config.mjs';
import { writeConfig } from '../skill/lib/config.mjs';

const posixOnly = { skip: process.platform === 'win32' ? 'POSIX permissions and symlinks only' : false };

function tempDir(prefix) {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function makeLayout() {
  const base = tempDir('cockpit-identity-');
  const root = path.join(base, 'root');
  fs.mkdirSync(path.join(root, '.cockpit'), { recursive: true });
  fs.writeFileSync(path.join(root, '.cockpit', 'sources.toml'), '');
  fs.writeFileSync(path.join(root, 'index.html'), '<h1>Home</h1>');
  const stateDir = path.join(base, 'state');
  return { base, root, stateDir, file: path.join(stateDir, 'identity.json') };
}

// A real COSE_Key (EC2, P-256, ES256) built from a freshly generated key pair.
function coseKey() {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from([0x22, 0x58, 0x20]),
    Buffer.from(jwk.y, 'base64url'),
  ]);
}

function credential(overrides = {}) {
  return { id: crypto.randomBytes(32), publicKey: coseKey(), transports: ['internal', 'hybrid'], label: 'Test laptop', ...overrides };
}

function seeded() {
  const layout = makeLayout();
  let tick = Date.parse('2026-01-02T03:04:05.000Z');
  const store = openIdentityStore({ file: layout.file, root: layout.root, now: () => { tick += 1000; return tick; } });
  const owner = store.createUser({ displayName: 'Ada Example', role: 'owner' });
  const member = store.createUser({ displayName: 'Test Member' });
  return { ...layout, store, owner, member };
}

function validDoc() {
  const key = coseKey().toString('base64url');
  return {
    schema_version: IDENTITY_SCHEMA_VERSION,
    users: [
      {
        id: 'usr_owner0001', display_name: 'Ada Example', role: 'owner', disabled: false, created_at: '2026-01-02T03:04:05.000Z',
        credentials: [{ id: crypto.randomBytes(16).toString('base64url'), public_key: key, counter: 0, transports: ['usb'], created_at: '2026-01-02T03:04:05.000Z', label: '' }],
      },
      { id: 'usr_member001', display_name: 'Test Member', role: 'member', disabled: false, created_at: '2026-01-02T03:04:05.000Z', credentials: [] },
    ],
  };
}

function writeDoc(file, doc, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, typeof doc === 'string' ? doc : JSON.stringify(doc), { mode });
  fs.chmodSync(file, mode);
}

function assertRejects(fn, code, secrets = []) {
  let caught;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  assert.ok(code, 'assertRejects needs the expected error code');
  assert.ok(caught instanceof IdentityStoreError, `expected IdentityStoreError, got ${caught}`);
  assert.equal(caught.code, code, caught.message);
  for (const secret of secrets) assert.ok(!caught.message.includes(secret), `error message echoes stored material: ${caught.message}`);
  return caught;
}

function tempFiles(dir) {
  return fs.readdirSync(dir).filter((name) => /\.(tmp|lock|stale)$/.test(name));
}

test('createUser bootstraps the store with exactly one owner and an owner-only file', () => {
  const { file, root, store, owner, member } = seeded();
  assert.match(owner.id, /^usr_[A-Za-z0-9_-]{22}$/);
  assert.notEqual(owner.id, member.id);
  assert.equal(owner.role, 'owner');
  assert.equal(member.role, 'member');
  assert.equal(member.disabled, false);
  assert.equal(owner.created_at, '2026-01-02T03:04:06.000Z');

  const data = store.load();
  assert.equal(data.schema_version, IDENTITY_SCHEMA_VERSION);
  assert.deepEqual(data.users.map((user) => user.display_name), ['Ada Example', 'Test Member']);
  assert.equal(findUser(data, member.id).display_name, 'Test Member');
  assert.equal(findUser(data, 'usr_nobody0000'), null);
  assert.equal(store.file, file);
  assert.equal(path.relative(root, file).startsWith('..'), true);
  assert.deepEqual(tempFiles(path.dirname(file)), []);
});

test('the store file and a new store directory are owner-only', posixOnly, () => {
  const { file } = seeded();
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o077, 0);
});

test('load fails closed when the store is missing or has no single owner', () => {
  const { file, root } = makeLayout();
  const store = openIdentityStore({ file, root });
  assertRejects(() => store.load(), 'missing');
  assertRejects(() => store.createUser({ displayName: 'Test Member' }), 'owner_required');
  assert.equal(fs.existsSync(file), false);

  const none = validDoc();
  none.users[0].role = 'member';
  writeDoc(file, none);
  assert.match(assertRejects(() => store.load(), 'owner_required').message, /exactly one owner \(found 0\)/);
  assertRejects(() => store.createUser({ displayName: 'Test Member' }), 'owner_required');

  const empty = { schema_version: IDENTITY_SCHEMA_VERSION, users: [] };
  writeDoc(file, empty);
  assertRejects(() => store.load(), 'owner_required');

  const two = validDoc();
  two.users[1].role = 'owner';
  writeDoc(file, two);
  assert.match(assertRejects(() => store.load(), 'owner_required').message, /found 2/);
});

test('createUser rejects a second owner, unknown roles, bad names, and duplicate ids', () => {
  const { store, owner } = seeded();
  assertRejects(() => store.createUser({ displayName: 'Second Owner', role: 'owner' }), 'owner_required');
  assertRejects(() => store.createUser({ displayName: 'Test Admin', role: 'admin' }), 'invalid_role');
  assertRejects(() => store.createUser({ displayName: 'Test Member', id: owner.id }), 'duplicate_id');
  assertRejects(() => store.createUser({ displayName: 'Test Member', id: 'bad id!' }), 'invalid_id');
  assertRejects(() => store.createUser({ displayName: 'short', id: 'usr_1' }), 'invalid_id');
  assert.match(assertRejects(() => store.createUser({ displayName: '' }), 'invalid_argument').message, /1 to 128 characters/);
  assert.match(assertRejects(() => store.createUser({ displayName: ' Padded ' }), 'invalid_argument').message, /whitespace/);
  assert.match(assertRejects(() => store.createUser({ displayName: 'Line\nbreak' }), 'invalid_argument').message, /control characters/);
  assert.match(assertRejects(() => store.createUser({ displayName: 'x'.repeat(129) }), 'invalid_argument').message, /1 to 128 characters/);
  const named = store.createUser({ displayName: 'Test Guest', id: 'usr_guest0001' });
  assert.equal(named.id, 'usr_guest0001');
  assert.equal(store.load().users.length, 3);
});

test('display names and labels reject bidi and invisible formatting characters', () => {
  const { file, store, owner } = seeded();
  const sneaky = ['‎', '‏', '‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩', '​', '‌', '‍', '⁠', '﻿', '؜'];
  for (const char of sneaky) {
    const hex = char.codePointAt(0).toString(16);
    const error = assertRejects(() => store.createUser({ displayName: `Test${char}Member` }), 'invalid_argument');
    assert.match(error.message, /bidirectional or invisible formatting/, hex);
    assertRejects(() => store.addCredential(owner.id, credential({ label: `Phone${char}` })), 'invalid_argument');
  }
  assert.equal(store.createUser({ displayName: 'Zoë Ünïcode 測試' }).display_name, 'Zoë Ünïcode 測試');

  const doc = validDoc();
  doc.users[1].display_name = 'Test‮Member';
  writeDoc(file, doc);
  assertRejects(() => store.load(), 'invalid_store');
  doc.users[1].display_name = 'Test Member';
  doc.users[0].credentials[0].label = '​Laptop';
  writeDoc(file, doc);
  assertRejects(() => store.load(), 'invalid_store');
});

test('addCredential stores base64url credential ids and COSE public keys', () => {
  const { store, owner } = seeded();
  const input = credential();
  const added = store.addCredential(owner.id, input);
  assert.equal(added.id, input.id.toString('base64url'));
  assert.equal(added.public_key, input.publicKey.toString('base64url'));
  assert.equal(added.counter, 0);
  assert.deepEqual(added.transports, ['internal', 'hybrid']);
  assert.equal(added.label, 'Test laptop');
  assert.equal(added.created_at, '2026-01-02T03:04:08.000Z');

  const asString = credential({ id: crypto.randomBytes(16).toString('base64url'), publicKey: coseKey().toString('base64url'), counter: 7, transports: [], label: '' });
  assert.equal(store.addCredential(owner.id, asString).counter, 7);

  const found = findCredential(store.load(), added.id);
  assert.equal(found.user.id, owner.id);
  assert.equal(found.credential.public_key, added.public_key);
  assert.equal(findCredential(store.load(), 'AAAA'), null);
});

test('createUserWithCredential writes a user and their first credential together, or nothing', () => {
  const { root, file } = makeLayout();
  const store = openIdentityStore({ file, root });
  const missing = (error) => error instanceof IdentityStoreError && error.code === 'missing';
  for (const bad of [{ label: 'x'.repeat(65) }, { label: 42 }, { publicKey: 'AAAA' }, { counter: -1 }, { transports: 'usb' }]) {
    assert.throws(() => store.createUserWithCredential({ displayName: 'Ada Example', role: 'owner', credential: credential(bad) }),
      (error) => error instanceof IdentityStoreError && error.code === 'invalid_argument', JSON.stringify(Object.keys(bad)));
    assert.throws(() => store.load(), missing);
  }
  assert.throws(() => store.createUserWithCredential({ displayName: ' ', role: 'owner', credential: credential() }),
    (error) => error instanceof IdentityStoreError && error.code === 'invalid_argument');
  assert.throws(() => store.load(), missing);

  const input = credential();
  const { user, credential: added } = store.createUserWithCredential({ displayName: 'Ada Example', role: 'owner', credential: input });
  assert.equal(user.role, 'owner');
  assert.equal(user.credentials.length, 1);
  assert.equal(added.id, input.id.toString('base64url'));
  assert.deepEqual(store.load().users.map((u) => [u.id, u.credentials.length]), [[user.id, 1]]);
  // A duplicate credential id fails as a whole: the member is not created.
  assert.throws(() => store.createUserWithCredential({ displayName: 'Test Member', credential: input }),
    (error) => error instanceof IdentityStoreError && error.code === 'duplicate_id');
  assert.equal(store.load().users.length, 1);
});

test('addCredential rejects duplicate ids across users and bad input without echoing it', () => {
  const { store, owner, member } = seeded();
  const input = credential();
  const id = input.id.toString('base64url');
  const key = input.publicKey.toString('base64url');
  store.addCredential(owner.id, input);
  const secrets = [id, key];

  assertRejects(() => store.addCredential(member.id, credential({ id: input.id })), 'duplicate_id', secrets);
  assertRejects(() => store.addCredential(owner.id, credential({ id })), 'duplicate_id', secrets);
  assertRejects(() => store.addCredential('usr_nobody0000', credential()), 'not_found');
  assertRejects(() => store.addCredential(owner.id, credential({ id: `${id}=` })), 'invalid_argument', secrets);
  assertRejects(() => store.addCredential(owner.id, credential({ id: 'not base64!' })), 'invalid_argument', secrets);
  assertRejects(() => store.addCredential(owner.id, credential({ id: 'A'.repeat(1400) })), 'invalid_argument');
  assertRejects(() => store.addCredential(owner.id, credential({ id: new Uint8Array(0) })), 'invalid_argument');
  assertRejects(() => store.addCredential(owner.id, credential({ id: 12345 })), 'invalid_argument');
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ id: crypto.randomBytes(1024) })), 'invalid_argument').message, /at most 1023 bytes/);
  assertRejects(() => store.addCredential(owner.id, credential({ publicKey: crypto.randomBytes(32).fill(0x04, 0, 1) })), 'invalid_argument', secrets);
  assertRejects(() => store.addCredential(owner.id, credential({ publicKey: Buffer.from([0x04, 1, 2]).toString('base64url') })), 'invalid_argument');
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ counter: -1 })), 'invalid_argument').message, /integer from 0/);
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ counter: 1.5 })), 'invalid_argument').message, /integer from 0/);
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ transports: ['USB'] })), 'invalid_argument').message, /lowercase transport/);
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ transports: ['usb', 'usb'] })), 'invalid_argument').message, /repeat a transport/);
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ transports: 'usb' })), 'invalid_argument').message, /array of at most 8/);
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ label: 'x'.repeat(65) })), 'invalid_argument').message, /0 to 64 characters/);
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ label: 'tab\there' })), 'invalid_argument').message, /control characters/);
  assert.equal(store.load().users[0].credentials.length, 1);
});

test('updateCounter only moves forward and never echoes credential ids', () => {
  const { store, owner } = seeded();
  const counted = store.addCredential(owner.id, credential({ counter: 5 }));
  const zero = store.addCredential(owner.id, credential());

  assert.equal(store.updateCounter(counted.id, 6).counter, 6);
  assert.equal(store.updateCounter(counted.id, 1000).counter, 1000);
  assertRejects(() => store.updateCounter(counted.id, 1000), 'counter_regression', [counted.id]);
  assertRejects(() => store.updateCounter(counted.id, 3), 'counter_regression', [counted.id]);
  assertRejects(() => store.updateCounter(counted.id, 0), 'counter_regression', [counted.id]);
  assert.match(assertRejects(() => store.updateCounter(counted.id, 2 ** 32), 'invalid_argument').message, /integer from 0/);
  assert.match(assertRejects(() => store.updateCounter(counted.id, '1001'), 'invalid_argument').message, /integer from 0/);
  assert.equal(findCredential(store.load(), counted.id).credential.counter, 1000);

  // Authenticators without a counter always report 0.
  assert.equal(store.updateCounter(zero.id, 0).counter, 0);
  assert.equal(store.updateCounter(zero.id, 1).counter, 1);

  const missing = crypto.randomBytes(16).toString('base64url');
  assertRejects(() => store.updateCounter(missing, 1), 'not_found', [missing]);
});

test('removeCredential deletes one credential by id', () => {
  const { store, owner, member } = seeded();
  const first = store.addCredential(owner.id, credential());
  const second = store.addCredential(member.id, credential());
  assert.equal(store.removeCredential(first.id).id, first.id);
  assert.equal(findCredential(store.load(), first.id), null);
  assert.equal(findCredential(store.load(), second.id).user.id, member.id);
  assertRejects(() => store.removeCredential(first.id), 'not_found', [first.id]);
});

test('disableUser disables members, keeps the owner, and blocks credential changes', () => {
  const { store, owner, member } = seeded();
  const memberKey = store.addCredential(member.id, credential({ counter: 1 }));
  assert.equal(store.disableUser(member.id).disabled, true);
  assert.equal(store.disableUser(member.id).disabled, true);
  assert.equal(findUser(store.load(), member.id).disabled, true);
  assertRejects(() => store.addCredential(member.id, credential()), 'user_disabled');
  assertRejects(() => store.updateCounter(memberKey.id, 2), 'user_disabled');
  assert.equal(store.removeCredential(memberKey.id).id, memberKey.id);
  assertRejects(() => store.disableUser(owner.id), 'owner_required');
  assertRejects(() => store.disableUser('usr_nobody0000'), 'not_found');
});

test('returned objects are copies, not live views of the store', () => {
  const { store, owner } = seeded();
  const data = store.load();
  data.users[0].role = 'member';
  data.users.push({});
  const user = store.createUser({ displayName: 'Test Member Two' });
  user.role = 'owner';
  assert.equal(store.load().users[0].role, 'owner');
  assert.equal(store.load().users.length, 3);
  assert.equal(findUser(store.load(), owner.id).role, 'owner');
});

test('load rejects invalid documents with messages that cite fields, not values', () => {
  const { file, root } = makeLayout();
  const store = openIdentityStore({ file, root });
  const doc = validDoc();
  const credentialId = doc.users[0].credentials[0].id;
  const publicKey = doc.users[0].credentials[0].public_key;
  const secrets = [credentialId, publicKey];
  writeDoc(file, doc);
  assert.equal(store.load().users.length, 2);
  assert.deepEqual(validateIdentityData(structuredClone(doc)), doc);

  const cases = [
    ['unknown role', (d) => { d.users[1].role = 'admin'; }, 'invalid_role'],
    ['bad user id', (d) => { d.users[1].id = 'no spaces allowed'; }, 'invalid_id'],
    ['duplicate user id', (d) => { d.users[1].id = d.users[0].id; }, 'duplicate_id'],
    ['duplicate credential id across users', (d) => { d.users[1].credentials.push({ ...d.users[0].credentials[0] }); }, 'duplicate_id'],
    ['unknown user field', (d) => { d.users[0].password = 'nope'; }, 'invalid_store'],
    ['unknown credential field', (d) => { d.users[0].credentials[0].private_key = 'nope'; }, 'invalid_store'],
    ['unknown top-level field', (d) => { d.extra = true; }, 'invalid_store'],
    ['missing field', (d) => { delete d.users[0].credentials[0].counter; }, 'invalid_store'],
    ['schema version', (d) => { d.schema_version = 2; }, 'unsupported_schema'],
    ['padded credential id', (d) => { d.users[0].credentials[0].id = `${credentialId}=`; }, 'invalid_store'],
    ['standard base64 public key', (d) => { d.users[0].credentials[0].public_key = Buffer.from(publicKey, 'base64url').toString('base64'); }, 'invalid_store'],
    ['non-COSE public key', (d) => { d.users[0].credentials[0].public_key = Buffer.from([0x04, ...crypto.randomBytes(64)]).toString('base64url'); }, 'invalid_store'],
    ['negative counter', (d) => { d.users[0].credentials[0].counter = -1; }, 'invalid_store'],
    ['bad timestamp', (d) => { d.users[0].created_at = '2026-01-02'; }, 'invalid_store'],
    ['disabled not boolean', (d) => { d.users[1].disabled = 'no'; }, 'invalid_store'],
    ['users not array', (d) => { d.users = {}; }, 'invalid_store'],
  ];
  for (const [name, mutate, code] of cases) {
    const broken = structuredClone(doc);
    mutate(broken);
    writeDoc(file, broken);
    const error = assertRejects(() => store.load(), code, secrets);
    assert.match(error.message, /identity store|users\[\d\]/, name);
  }

  writeDoc(file, `{"users": [${JSON.stringify(credentialId)}`);
  const parseError = assertRejects(() => store.load(), 'invalid_store', secrets);
  assert.equal(parseError.message, 'Identity store is not valid JSON');
});

test('load refuses group/world-accessible files and symlinks', posixOnly, () => {
  const { base, file, root } = makeLayout();
  const store = openIdentityStore({ file, root });
  writeDoc(file, validDoc(), 0o640);
  assertRejects(() => store.load(), 'unsafe_permissions');
  fs.chmodSync(file, 0o604);
  assertRejects(() => store.load(), 'unsafe_permissions');
  assertRejects(() => store.createUser({ displayName: 'Test Member' }), 'unsafe_permissions');
  fs.chmodSync(file, 0o600);
  assert.equal(store.load().users.length, 2);

  const real = path.join(base, 'elsewhere.json');
  writeDoc(real, validDoc());
  const link = path.join(base, 'state', 'linked.json');
  fs.symlinkSync(real, link);
  assertRejects(() => openIdentityStore({ file: link, root }).load(), 'unsafe_file');
});

test('a symlinked or group/world-writable store directory is refused', posixOnly, () => {
  const { base, file, root, store } = seeded();
  const dir = path.dirname(file);
  fs.chmodSync(dir, 0o770);
  assertRejects(() => store.load(), 'unsafe_permissions');
  assertRejects(() => store.createUser({ displayName: 'Test Member Two' }), 'unsafe_permissions');
  fs.chmodSync(dir, 0o702);
  assertRejects(() => store.load(), 'unsafe_permissions');
  fs.chmodSync(dir, 0o750);
  assert.equal(store.load().users.length, 2, 'group read and search are fine');
  fs.chmodSync(dir, 0o700);

  const linkedDir = path.join(base, 'linked-state');
  fs.symlinkSync(dir, linkedDir, 'dir');
  const linked = openIdentityStore({ file: path.join(linkedDir, 'identity.json'), root });
  assertRejects(() => linked.load(), 'unsafe_path');
  assertRejects(() => linked.createUser({ displayName: 'Test Member Two' }), 'unsafe_path');
  assert.equal(store.load().users.length, 2);
});

test('load checks and reads the file it opened, not whatever is at the path later', posixOnly, (t) => {
  const { base, file, root } = makeLayout();
  const store = openIdentityStore({ file, root });
  writeDoc(file, validDoc());
  const swapped = validDoc();
  swapped.users.push({ ...swapped.users[1], id: 'usr_member002' });
  const other = path.join(base, 'other.json');
  writeDoc(other, swapped, 0o644);
  const realOpen = fs.openSync;
  t.mock.method(fs, 'openSync', (...args) => {
    const fd = realOpen(...args);
    // Swap a world-readable file in right after the store is opened.
    if (args[0] === file) fs.renameSync(other, file);
    return fd;
  });
  assert.equal(store.load().users.length, 2, 'the opened file was read and checked');
  t.mock.restoreAll();
  assertRejects(() => store.load(), 'unsafe_permissions');
});

test('load bounds the bytes it reads, even if fstat reports a small size', (t) => {
  const { file, root } = makeLayout();
  const store = openIdentityStore({ file, root });
  writeDoc(file, `{"pad": "${'x'.repeat(MAX_FILE_BYTES)}"}`);
  assert.match(assertRejects(() => store.load(), 'invalid_store').message, /larger than 1048576 bytes/);
  const realFstat = fs.fstatSync;
  t.mock.method(fs, 'fstatSync', (...args) => Object.assign(realFstat(...args), { size: 10 }));
  assert.match(assertRejects(() => store.load(), 'invalid_store').message, /larger than 1048576 bytes/);
});

test('load maps open failures to unsafe_file or unreadable without leaking paths', posixOnly, () => {
  const { file, root } = makeLayout();
  const store = openIdentityStore({ file, root });
  fs.mkdirSync(file, { recursive: true, mode: 0o700 });
  assertRejects(() => store.load(), 'unsafe_file', [file]);
  fs.rmdirSync(file);

  fs.symlinkSync(path.join(path.dirname(file), 'missing-target.json'), file);
  assertRejects(() => store.load(), 'unsafe_file', [file]);
  fs.rmSync(file);

  writeDoc(file, validDoc(), 0o000);
  if (process.getuid?.() !== 0) {
    const error = assertRejects(() => store.load(), 'unreadable', [file, path.dirname(file)]);
    assert.equal(error.message, 'Identity store is unreadable');
  }
});

test('a failed mutation leaves the previous file byte-for-byte and no temp files', () => {
  const { file, store, owner } = seeded();
  const before = fs.readFileSync(file);
  assertRejects(() => store.createUser({ displayName: 'Second Owner', role: 'owner' }), 'owner_required');
  assert.match(assertRejects(() => store.addCredential(owner.id, credential({ transports: ['bad transport'] })), 'invalid_argument').message, /lowercase transport/);
  assert.deepEqual(fs.readFileSync(file), before);
  assert.deepEqual(tempFiles(path.dirname(file)), []);
});

test('writes fsync a temp file, and a failed rename keeps the old file intact', (t) => {
  const { file, store, owner } = seeded();
  const before = fs.readFileSync(file);
  const fsynced = [];
  const realFsync = fs.fsyncSync;
  t.mock.method(fs, 'fsyncSync', (fd) => { fsynced.push(fd); return realFsync(fd); });
  const realRename = fs.renameSync;
  t.mock.method(fs, 'renameSync', (from, to) => {
    if (to === file) throw Object.assign(new Error('simulated crash before rename'), { code: 'EIO' });
    return realRename(from, to);
  });
  assert.throws(() => store.addCredential(owner.id, credential()), /simulated crash/);
  assert.ok(fsynced.length >= 1, 'the temp file is fsynced before rename');
  assert.deepEqual(fs.readFileSync(file), before);
  assert.deepEqual(tempFiles(path.dirname(file)), []);
  t.mock.restoreAll();
  assert.equal(store.load().users[0].credentials.length, 0);
  store.addCredential(owner.id, credential());
  assert.equal(store.load().users[0].credentials.length, 1);
});

test('a write over the 1 MiB cap is refused with store_full and the store stays usable', () => {
  const { file, root } = makeLayout();
  const store = openIdentityStore({ file, root });
  const serializedBytes = (doc) => Buffer.byteLength(`${JSON.stringify(doc, null, 2)}\n`);
  // Credentials at the per-field maxima: 1023-byte ids and 2048-byte keys.
  const bigCredential = () => ({
    id: crypto.randomBytes(1023).toString('base64url'),
    public_key: Buffer.concat([Buffer.from([0xa5]), crypto.randomBytes(2047)]).toString('base64url'),
    counter: 0, transports: ['usb'], created_at: '2026-01-02T03:04:05.000Z', label: 'Test key',
  });
  const doc = validDoc();
  doc.users[0].credentials = [];
  for (let index = 0; ; index += 1) {
    let user = doc.users.at(-1);
    if (user.role === 'owner' || user.credentials.length === 32) {
      user = { id: `usr_member${String(index).padStart(4, '0')}`, display_name: 'Test Member', role: 'member', disabled: false, created_at: '2026-01-02T03:04:05.000Z', credentials: [] };
      doc.users.push(user);
    }
    user.credentials.push(bigCredential());
    // Each one serializes to about 4.5 KB. Re-serializing the whole document
    // every step is slow, so measure exactly only near the cap.
    if ((index + 1) * 4400 > MAX_FILE_BYTES - 32 * 1024 && serializedBytes(doc) > MAX_FILE_BYTES) {
      user.credentials.pop();
      break;
    }
  }
  writeDoc(file, JSON.stringify(doc, null, 2));
  assert.ok(fs.statSync(file).size <= MAX_FILE_BYTES);
  const before = fs.readFileSync(file);
  const loaded = store.load();
  const owner = loaded.users[0];

  const big = { id: crypto.randomBytes(1023), publicKey: Buffer.concat([Buffer.from([0xa5]), crypto.randomBytes(2047)]), transports: ['usb'], label: 'Test key' };
  const error = assertRejects(() => store.addCredential(owner.id, big), 'store_full');
  assert.match(error.message, /1048576 bytes/);
  assert.deepEqual(fs.readFileSync(file), before);
  assert.deepEqual(tempFiles(path.dirname(file)), []);

  // The previous file still loads and can still be changed.
  const victim = loaded.users.at(-1).credentials[0];
  assert.equal(store.removeCredential(victim.id).id, victim.id);
  assert.equal(findCredential(store.load(), victim.id), null);
});

function holdLock(file, token, ageMs = 0) {
  const lockFile = `${file}.lock`;
  fs.writeFileSync(lockFile, token, { mode: 0o600 });
  if (ageMs) {
    const old = new Date(Date.now() - ageMs);
    fs.utimesSync(lockFile, old, old);
  }
  return lockFile;
}

test('a stale lock left by a crashed writer is cleared', () => {
  const { file, store } = seeded();
  const lockFile = holdLock(file, 'crashed-writer', 60_000);
  store.createUser({ displayName: 'Test Member Two' });
  assert.equal(fs.existsSync(lockFile), false);
  assert.equal(store.load().users.length, 3);
  assert.deepEqual(tempFiles(path.dirname(file)), []);
});

test('a writer whose lock was taken over writes nothing and leaves the new lock alone', () => {
  const { file, root } = makeLayout();
  const lockFile = `${file}.lock`;
  let takeOver = false;
  const store = openIdentityStore({
    file,
    root,
    // The clock runs inside the locked section, so it can stand in for a
    // second writer that takes the lock over mid-change.
    now: () => {
      if (takeOver) {
        fs.rmSync(lockFile);
        holdLock(file, 'new-owner');
      }
      return Date.parse('2026-01-02T03:04:05.000Z');
    },
  });
  store.createUser({ displayName: 'Ada Example', role: 'owner' });
  const before = fs.readFileSync(file);
  takeOver = true;
  assertRejects(() => store.createUser({ displayName: 'Test Member' }), 'store_busy');
  assert.deepEqual(fs.readFileSync(file), before, 'nothing was written');
  assert.equal(fs.readFileSync(lockFile, 'utf8'), 'new-owner', 'release did not delete the new owner\'s lock');
  assert.deepEqual(tempFiles(path.dirname(file)), ['identity.json.lock'], 'only the new owner\'s lock is left');
});

test('only one writer wins a stale lock; a lock re-taken in between is put back', (t) => {
  const { file, root } = seeded();
  const before = fs.readFileSync(file);
  const lockFile = holdLock(file, 'crashed-writer', 60_000);
  const realRename = fs.renameSync;
  let raced = false;
  t.mock.method(fs, 'renameSync', (from, to) => {
    if (from === lockFile && !raced) {
      // Another writer cleared the same stale lock and took a fresh one
      // between our staleness check and our takeover.
      raced = true;
      fs.rmSync(lockFile);
      holdLock(file, 'writer-a');
    }
    return realRename(from, to);
  });
  const store = openIdentityStore({ file, root, lockWaitMs: 50 });
  assertRejects(() => store.createUser({ displayName: 'Test Member Two' }), 'store_busy');
  t.mock.restoreAll();
  assert.equal(raced, true);
  assert.equal(fs.readFileSync(lockFile, 'utf8'), 'writer-a', 'the fresh lock was restored, not deleted');
  assert.deepEqual(fs.readFileSync(file), before);
  assert.deepEqual(tempFiles(path.dirname(file)), ['identity.json.lock']);
});

test('two processes adding credentials at once do not lose updates', async () => {
  const { file, root, store, owner } = seeded();
  const storeUrl = new URL('../skill/lib/identity/store.mjs', import.meta.url).href;
  const script = `
    import crypto from 'node:crypto';
    import { openIdentityStore } from ${JSON.stringify(storeUrl)};
    const [file, root, userId] = process.argv.slice(1);
    const store = openIdentityStore({ file, root, lockWaitMs: 20000 });
    for (let i = 0; i < 15; i += 1) {
      store.addCredential(userId, { id: crypto.randomBytes(16), publicKey: Buffer.concat([Buffer.from([0xa1]), crypto.randomBytes(8)]) });
    }`;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, file, root, owner.id], { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`writer exited ${code}: ${stderr}`))));
  });
  await Promise.all([run(), run()]);
  assert.equal(store.load().users[0].credentials.length, 30);
  assert.deepEqual(tempFiles(path.dirname(file)), []);
});

test('a fresh lock held by another writer makes mutators throw store_busy after the wait', () => {
  const { file, root, store } = seeded();
  const before = fs.readFileSync(file);
  const lockFile = holdLock(file, 'other-writer');
  const busy = openIdentityStore({ file, root, lockWaitMs: 50 });
  const started = Date.now();
  assertRejects(() => busy.createUser({ displayName: 'Test Member Two' }), 'store_busy');
  assert.ok(Date.now() - started < 2000, 'the shortened wait is honored');
  assert.deepEqual(fs.readFileSync(file), before);
  assert.equal(fs.readFileSync(lockFile, 'utf8'), 'other-writer', 'the other writer keeps its lock');
  assert.equal(store.load().users.length, 2, 'reads do not need the lock');
  assertRejects(() => openIdentityStore({ file, root, lockWaitMs: -1 }), 'invalid_argument');
  assertRejects(() => openIdentityStore({ file, root, lockStaleMs: Number.NaN }), 'invalid_argument');
});

test('the store path must resolve outside the served root', () => {
  const { base, root } = makeLayout();
  assertRejects(() => openIdentityStore({ file: path.join(root, 'identity.json'), root }), 'unsafe_path');
  assertRejects(() => openIdentityStore({ file: path.join(root, '.cockpit', 'identity.json'), root }), 'unsafe_path');
  assertRejects(() => openIdentityStore({ file: path.join(base, 'state', '..', 'root', 'identity.json'), root }), 'unsafe_path');
  assertRejects(() => openIdentityStore({ file: root, root }), 'unsafe_path');
  assertRejects(() => openIdentityStore({ file: 'identity.json', root }), 'unsafe_path');
  assertRejects(() => openIdentityStore({ file: path.join(base, 'identity.json') }), 'invalid_argument');
  assert.equal(assertOutsideRoot(path.join(base, 'state', 'identity.json'), root), path.join(base, 'state', 'identity.json'));
  assert.equal(fs.readdirSync(root).includes('identity.json'), false);
});

test('symlinked directories cannot alias the served root', posixOnly, () => {
  const { base, root } = makeLayout();
  const alias = path.join(base, 'alias');
  fs.symlinkSync(root, alias, 'dir');
  assertRejects(() => openIdentityStore({ file: path.join(alias, 'identity.json'), root }), 'unsafe_path');
  assertRejects(() => openIdentityStore({ file: path.join(root, 'identity.json'), root: alias }), 'unsafe_path');
  const outside = path.join(base, 'outside');
  fs.mkdirSync(outside);
  fs.symlinkSync(outside, path.join(root, 'escape'), 'dir');
  // The real path is outside the root, and serve.mjs refuses to serve paths
  // whose real path leaves the root, but the configured path is still lexically
  // inside it, so it is refused too.
  assertRejects(() => openIdentityStore({ file: path.join(root, 'escape', 'identity.json'), root }), 'unsafe_path');
});

test('serve config resolves the identity store path and refuses one inside the root', () => {
  const { base, root } = makeLayout();
  const env = { ...process.env, HOME: path.join(base, 'home'), XDG_STATE_HOME: path.join(base, 'xdg-state') };
  delete env.COCKPIT_HOME;
  delete env.XDG_CONFIG_HOME;
  writeConfig(env, { cockpit_root: root });
  const serveToml = path.join(root, '.cockpit', 'serve.toml');

  const defaults = parseServeConfig({ argv: [], env });
  assert.equal(path.basename(defaults.identityStore), 'identity.json');
  assert.ok(defaults.identityStore.startsWith(path.join(base, 'xdg-state', 'cockpit-kit')));

  const outside = path.join(base, 'private', 'identity.json');
  assert.equal(parseServeConfig({ argv: ['--identity-store', outside], env }).identityStore, outside);
  assert.equal(parseServeConfig({ argv: [`--identity-store=${outside}`], env }).identityStore, outside);

  fs.writeFileSync(serveToml, 'identity_store = "~/private/identity.json"\n');
  assert.equal(parseServeConfig({ argv: [], env }).identityStore, path.join(base, 'home', 'private', 'identity.json'));

  fs.writeFileSync(serveToml, `identity_store = ${JSON.stringify(path.join(root, 'identity.json'))}\n`);
  assert.throws(() => parseServeConfig({ argv: [], env }), /identity_store must be outside the served Cockpit root/);
  assert.throws(() => parseServeConfig({ argv: ['--identity-store', path.join(root, '..', 'root', 'x.json')], env }), /--identity-store must be outside/);

  fs.writeFileSync(serveToml, 'identity_store = "relative/identity.json"\n');
  assert.throws(() => parseServeConfig({ argv: [], env }), /must be an absolute path/);
  fs.writeFileSync(serveToml, 'identity_store = 42\n');
  assert.throws(() => parseServeConfig({ argv: [], env }), /non-empty path string/);
});

test('serve config refuses a default identity store inside the root', () => {
  const { base, root } = makeLayout();
  const env = { ...process.env, HOME: path.join(base, 'home'), XDG_STATE_HOME: path.join(root, 'state') };
  delete env.COCKPIT_HOME;
  delete env.XDG_CONFIG_HOME;
  writeConfig(env, { cockpit_root: root });
  assert.throws(() => parseServeConfig({ argv: [], env }), /default identity store .* must be outside the served Cockpit root/);

  const inRootHome = { ...env, HOME: path.join(root, 'home') };
  delete inRootHome.XDG_STATE_HOME;
  writeConfig(inRootHome, { cockpit_root: root });
  assert.throws(() => parseServeConfig({ argv: [], env: inRootHome }), /default identity store .* must be outside the served Cockpit root/);

  const outside = path.join(base, 'private', 'identity.json');
  assert.equal(parseServeConfig({ argv: ['--identity-store', outside], env }).identityStore, outside);
});
