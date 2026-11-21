import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  IDENTITY_SCHEMA_VERSION, IdentityStoreError, assertOutsideRoot, findCredential, findUser, openIdentityStore, validateIdentityData,
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
  fs.mkdirSync(path.dirname(file), { recursive: true });
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
  assert.ok(caught instanceof IdentityStoreError, `expected IdentityStoreError, got ${caught}`);
  if (code) assert.equal(caught.code, code, caught.message);
  for (const secret of secrets) assert.ok(!caught.message.includes(secret), `error message echoes stored material: ${caught.message}`);
  return caught;
}

function tempFiles(dir) {
  return fs.readdirSync(dir).filter((name) => name.endsWith('.tmp') || name.endsWith('.lock'));
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
  assertRejects(() => store.createUser({ displayName: '' }));
  assertRejects(() => store.createUser({ displayName: ' Padded ' }));
  assertRejects(() => store.createUser({ displayName: 'Line\nbreak' }));
  assertRejects(() => store.createUser({ displayName: 'x'.repeat(129) }));
  const named = store.createUser({ displayName: 'Test Guest', id: 'usr_guest0001' });
  assert.equal(named.id, 'usr_guest0001');
  assert.equal(store.load().users.length, 3);
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
  assertRejects(() => store.addCredential(owner.id, credential({ id: `${id}=` })), 'invalid_store', secrets);
  assertRejects(() => store.addCredential(owner.id, credential({ id: 'not base64!' })), 'invalid_store', secrets);
  assertRejects(() => store.addCredential(owner.id, credential({ id: new Uint8Array(0) })), 'invalid_argument');
  assertRejects(() => store.addCredential(owner.id, credential({ id: 12345 })), 'invalid_argument');
  assertRejects(() => store.addCredential(owner.id, credential({ id: crypto.randomBytes(1024) })));
  assertRejects(() => store.addCredential(owner.id, credential({ publicKey: crypto.randomBytes(32).fill(0x04, 0, 1) })), 'invalid_store', secrets);
  assertRejects(() => store.addCredential(owner.id, credential({ counter: -1 })));
  assertRejects(() => store.addCredential(owner.id, credential({ counter: 1.5 })));
  assertRejects(() => store.addCredential(owner.id, credential({ transports: ['USB'] })));
  assertRejects(() => store.addCredential(owner.id, credential({ transports: ['usb', 'usb'] })));
  assertRejects(() => store.addCredential(owner.id, credential({ transports: 'usb' })));
  assertRejects(() => store.addCredential(owner.id, credential({ label: 'x'.repeat(65) })));
  assertRejects(() => store.addCredential(owner.id, credential({ label: 'tab\there' })));
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
  assertRejects(() => store.updateCounter(counted.id, 2 ** 32));
  assertRejects(() => store.updateCounter(counted.id, '1001'));
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

test('a failed mutation leaves the previous file byte-for-byte and no temp files', () => {
  const { file, store, owner } = seeded();
  const before = fs.readFileSync(file);
  assertRejects(() => store.createUser({ displayName: 'Second Owner', role: 'owner' }));
  assertRejects(() => store.addCredential(owner.id, credential({ transports: ['bad transport'] })));
  assert.deepEqual(fs.readFileSync(file), before);
  assert.deepEqual(tempFiles(path.dirname(file)), []);
});

test('writes fsync a temp file, and a failed rename keeps the old file intact', (t) => {
  const { file, store, owner } = seeded();
  const before = fs.readFileSync(file);
  const fsynced = [];
  const realFsync = fs.fsyncSync;
  t.mock.method(fs, 'fsyncSync', (fd) => { fsynced.push(fd); return realFsync(fd); });
  t.mock.method(fs, 'renameSync', () => { throw Object.assign(new Error('simulated crash before rename'), { code: 'EIO' }); });
  assert.throws(() => store.addCredential(owner.id, credential()), /simulated crash/);
  assert.ok(fsynced.length >= 1, 'the temp file is fsynced before rename');
  assert.deepEqual(fs.readFileSync(file), before);
  assert.deepEqual(tempFiles(path.dirname(file)), []);
  t.mock.restoreAll();
  assert.equal(store.load().users[0].credentials.length, 0);
  store.addCredential(owner.id, credential());
  assert.equal(store.load().users[0].credentials.length, 1);
});

test('a stale lock left by a crashed writer is cleared', () => {
  const { file, store } = seeded();
  const lockDir = `${file}.lock`;
  fs.mkdirSync(lockDir);
  const old = new Date(Date.now() - 60_000);
  fs.utimesSync(lockDir, old, old);
  store.createUser({ displayName: 'Test Member Two' });
  assert.equal(fs.existsSync(lockDir), false);
  assert.equal(store.load().users.length, 3);
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
