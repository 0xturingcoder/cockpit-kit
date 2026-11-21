// Challenge store and passkey ceremonies with a real identity store.
// Credentials are synthetic, generated at runtime
// (test/support/webauthn-synthetic.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ChallengeError, DEFAULT_CHALLENGE_TTL_MS, DEFAULT_MAX_CHALLENGES, createChallengeStore } from '../skill/lib/identity/challenges.mjs';
import { PasskeyError, createPasskeyCeremonies } from '../skill/lib/identity/passkeys.mjs';
import { IdentityStoreError, openIdentityStore } from '../skill/lib/identity/store.mjs';
import { WebAuthnError, parseCoseKey, verifyAuthentication } from '../skill/lib/identity/webauthn.mjs';
import { authenticationResponse, makeCredential, registrationResponse } from './support/webauthn-synthetic.mjs';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';

const tempDir = (prefix) => fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));

const makeLayout = () => {
  const base = tempDir('cockpit-passkeys-');
  const root = path.join(base, 'root');
  fs.mkdirSync(path.join(root, '.cockpit'), { recursive: true });
  fs.writeFileSync(path.join(root, '.cockpit', 'sources.toml'), '');
  fs.writeFileSync(path.join(root, 'index.html'), '<h1>Home</h1>');
  return { base, root, file: path.join(base, 'state', 'identity.json') };
};

const clock = (start = Date.parse('2026-03-04T05:06:07.000Z')) => {
  let at = start;
  const now = () => at;
  now.advance = (ms) => { at += ms; };
  return now;
};

const errorCode = (Type, expected) => (error) => {
  assert.ok(error instanceof Type, `expected ${Type.name}, got ${error?.name}: ${error?.message}`);
  assert.equal(error.code, expected);
  return true;
};

const userHandleOf = (options) => Buffer.from(options.publicKey.user.id, 'base64url');

// A ceremony harness over a fresh identity store with a controllable clock.
const harness = ({ lockWaitMs = 200, verify } = {}) => {
  const layout = makeLayout();
  const now = clock();
  const store = openIdentityStore({ file: layout.file, root: layout.root, lockWaitMs });
  const challenges = createChallengeStore({ now });
  const ceremonies = createPasskeyCeremonies({ store, rpId: RP_ID, origins: [ORIGIN], challenges, ...(verify ? { verify } : {}) });
  const registerOwner = (credential, { displayName = 'Ada Example', label = '' } = {}) => {
    const options = ceremonies.startRegistration({ displayName });
    const response = registrationResponse({ credential, challenge: Buffer.from(options.publicKey.challenge, 'base64url'), rpId: RP_ID, origin: ORIGIN });
    return { options, result: ceremonies.finishRegistration({ challengeId: options.challengeId, response, label }) };
  };
  const signInResponse = (credential, { userId, signCount = 1, ...rest } = {}) => {
    const options = ceremonies.startAuthentication();
    const response = authenticationResponse({
      credential, challenge: Buffer.from(options.publicKey.challenge, 'base64url'), rpId: RP_ID, origin: ORIGIN, signCount, userHandle: Buffer.from(userId, 'utf8'), ...rest,
    });
    return { challengeId: options.challengeId, response };
  };
  return { ...layout, now, store, challenges, ceremonies, registerOwner, signInResponse };
};

// ---------------------------------------------------------------------------
// Challenge store

test('challenges are random, 32 bytes, and returned with an opaque handle', () => {
  const challenges = createChallengeStore();
  const a = challenges.issue({ ceremony: 'authentication' });
  const b = challenges.issue({ ceremony: 'authentication' });
  assert.equal(a.challenge.length, 32);
  assert.notDeepEqual(a.challenge, b.challenge);
  assert.notEqual(a.id, b.id);
  assert.match(a.id, /^[A-Za-z0-9_-]{43}$/);
  assert.throws(() => challenges.issue({ ceremony: 'other' }), TypeError);
});

test('negative: replayed challenge is rejected by the challenge store (single use)', () => {
  const challenges = createChallengeStore();
  const issued = challenges.issue({ ceremony: 'authentication' });
  assert.deepEqual(challenges.consume(issued.id, 'authentication').challenge, issued.challenge);
  assert.throws(() => challenges.consume(issued.id, 'authentication'), errorCode(ChallengeError, 'challenge_unknown'));
  assert.throws(() => challenges.consume('not-a-handle', 'authentication'), errorCode(ChallengeError, 'challenge_unknown'));
  assert.throws(() => challenges.consume(undefined, 'authentication'), errorCode(ChallengeError, 'challenge_unknown'));
});

test('negative: expired challenge is rejected by the challenge store', () => {
  const now = clock();
  const challenges = createChallengeStore({ ttlMs: 1000, now });
  const issued = challenges.issue({ ceremony: 'registration' });
  now.advance(1000);
  assert.throws(() => challenges.consume(issued.id, 'registration'), errorCode(ChallengeError, 'challenge_expired'));
  assert.throws(() => challenges.consume(issued.id, 'registration'), errorCode(ChallengeError, 'challenge_unknown'));
  const fresh = challenges.issue({ ceremony: 'registration' });
  now.advance(999);
  assert.doesNotThrow(() => challenges.consume(fresh.id, 'registration'));
});

test('negative: wrong ceremony type is rejected by the challenge store, and the challenge is used up', () => {
  const challenges = createChallengeStore();
  const issued = challenges.issue({ ceremony: 'registration', binding: { userId: 'usr_example0001' } });
  assert.throws(() => challenges.consume(issued.id, 'authentication'), errorCode(ChallengeError, 'wrong_ceremony'));
  assert.throws(() => challenges.consume(issued.id, 'registration'), errorCode(ChallengeError, 'challenge_unknown'));
});

test('challenges are bounded in number; expired ones free their slots', () => {
  const now = clock();
  const challenges = createChallengeStore({ ttlMs: 1000, max: 3, now });
  for (let i = 0; i < 3; i += 1) challenges.issue({ ceremony: 'authentication' });
  assert.throws(() => challenges.issue({ ceremony: 'authentication' }), errorCode(ChallengeError, 'too_many_challenges'));
  now.advance(1000);
  assert.doesNotThrow(() => challenges.issue({ ceremony: 'authentication' }));
  assert.equal(challenges.size(), 1);
});

test('the default challenge lifetime is 2 minutes and is the ceremony timeout for both ceremonies', () => {
  assert.equal(DEFAULT_CHALLENGE_TTL_MS, 120000);
  assert.equal(createChallengeStore().ttlMs, 120000);
  const { root, file } = makeLayout();
  const ceremonies = createPasskeyCeremonies({ store: openIdentityStore({ file, root }), rpId: RP_ID, origins: [ORIGIN] });
  assert.equal(ceremonies.startRegistration({ displayName: 'Ada Example' }).publicKey.timeout, 120000);
  assert.equal(ceremonies.startAuthentication().publicKey.timeout, 120000);
});

test('challenge limits are per ceremony: a full sign-in ceremony does not block registration', () => {
  const challenges = createChallengeStore({ max: 3 });
  for (let i = 0; i < 3; i += 1) challenges.issue({ ceremony: 'authentication' });
  assert.throws(() => challenges.issue({ ceremony: 'authentication' }), errorCode(ChallengeError, 'too_many_challenges'));
  for (let i = 0; i < 3; i += 1) challenges.issue({ ceremony: 'registration', binding: { userId: 'usr_example0001' } });
  assert.throws(() => challenges.issue({ ceremony: 'registration' }), errorCode(ChallengeError, 'too_many_challenges'));
  assert.deepEqual([challenges.size('authentication'), challenges.size('registration'), challenges.size()], [3, 3, 6]);
});

test('registration challenges carry their user binding, frozen', () => {
  const challenges = createChallengeStore();
  const issued = challenges.issue({ ceremony: 'registration', binding: { userId: 'usr_example0001', createOwner: false } });
  const { binding } = challenges.consume(issued.id, 'registration');
  assert.equal(binding.userId, 'usr_example0001');
  assert.ok(Object.isFrozen(binding));
});

// ---------------------------------------------------------------------------
// Ceremonies

test('ceremony: first registration creates the owner; ES256 sign-in returns the verified user id and persists the counter', () => {
  const h = harness();
  const credential = makeCredential({ alg: -7 });
  const { options, result } = h.registerOwner(credential, { label: 'Test laptop' });
  assert.equal(result.createdOwner, true);
  assert.equal(options.publicKey.rp.id, RP_ID);
  assert.equal(options.publicKey.attestation, 'none');
  assert.deepEqual(options.publicKey.pubKeyCredParams.map((param) => param.alg), [-7, -257]);
  assert.equal(options.publicKey.authenticatorSelection.userVerification, 'required');
  assert.equal(userHandleOf(options).toString('utf8'), result.userId);

  const data = h.store.load();
  assert.equal(data.users.length, 1);
  assert.equal(data.users[0].role, 'owner');
  assert.equal(data.users[0].display_name, 'Ada Example');
  assert.equal(data.users[0].credentials[0].label, 'Test laptop');
  assert.equal(data.users[0].credentials[0].id, credential.rawId.toString('base64url'));

  const signedIn = h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: result.userId, signCount: 3 }));
  assert.deepEqual({ ...signedIn }, { userId: result.userId, role: 'owner', credentialId: result.credentialId, counter: 3 });
  assert.equal(h.store.load().users[0].credentials[0].counter, 3);
});

test('ceremony: RS256 passkey added to an existing owner signs in', () => {
  const h = harness();
  const first = h.registerOwner(makeCredential());
  const rsa = makeCredential({ alg: -257 });
  const options = h.ceremonies.startRegistration();
  assert.equal(options.publicKey.excludeCredentials.length, 1);
  const response = registrationResponse({ credential: rsa, challenge: Buffer.from(options.publicKey.challenge, 'base64url'), rpId: RP_ID, origin: ORIGIN });
  const result = h.ceremonies.finishRegistration({ challengeId: options.challengeId, response });
  assert.equal(result.createdOwner, false);
  assert.equal(result.userId, first.result.userId);
  assert.equal(h.ceremonies.finishAuthentication(h.signInResponse(rsa, { userId: result.userId })).userId, result.userId);
});

test('ceremony: sign-in options are usernameless and require user verification', () => {
  const h = harness();
  const options = h.ceremonies.startAuthentication();
  assert.deepEqual(options.publicKey.allowCredentials, []);
  assert.equal(options.publicKey.userVerification, 'required');
  assert.equal(options.publicKey.rpId, RP_ID);
});

test('ceremony: sign-in options filling the default challenge limit do not block owner registration', () => {
  const h = harness();
  for (let i = 0; i < DEFAULT_MAX_CHALLENGES; i += 1) h.ceremonies.startAuthentication();
  assert.throws(() => h.ceremonies.startAuthentication(), errorCode(ChallengeError, 'too_many_challenges'));
  const { result } = h.registerOwner(makeCredential());
  assert.equal(result.createdOwner, true);
});

test('ceremony: creating the owner requires a display name', () => {
  const h = harness();
  assert.throws(() => h.ceremonies.startRegistration({}), errorCode(IdentityStoreError, 'invalid_argument'));
  assert.throws(() => h.ceremonies.startRegistration({ displayName: '   ' }), errorCode(IdentityStoreError, 'invalid_argument'));
});

test('negative: replayed challenge is rejected in a sign-in ceremony (same response twice)', () => {
  const h = harness();
  const credential = makeCredential();
  const { result } = h.registerOwner(credential);
  const attempt = h.signInResponse(credential, { userId: result.userId });
  h.ceremonies.finishAuthentication(attempt);
  assert.throws(() => h.ceremonies.finishAuthentication(attempt), errorCode(ChallengeError, 'challenge_unknown'));
});

test('negative: replayed challenge is rejected after a failed attempt (the first try uses it up)', () => {
  const h = harness();
  const credential = makeCredential();
  const { result } = h.registerOwner(credential);
  const good = h.signInResponse(credential, { userId: result.userId });
  const bad = structuredClone(good);
  bad.response.response.signature = Buffer.alloc(70, 1).toString('base64url');
  assert.throws(() => h.ceremonies.finishAuthentication(bad), WebAuthnError);
  assert.throws(() => h.ceremonies.finishAuthentication(good), errorCode(ChallengeError, 'challenge_unknown'));
});

test('negative: expired challenge is rejected in a sign-in ceremony', () => {
  const h = harness();
  const credential = makeCredential();
  const { result } = h.registerOwner(credential);
  const attempt = h.signInResponse(credential, { userId: result.userId });
  h.now.advance(h.challenges.ttlMs);
  assert.throws(() => h.ceremonies.finishAuthentication(attempt), errorCode(ChallengeError, 'challenge_expired'));
});

test('negative: wrong ceremony type is rejected in ceremonies (registration challenge used for sign-in and back)', () => {
  const h = harness();
  const credential = makeCredential();
  const { result } = h.registerOwner(credential);
  const regOptions = h.ceremonies.startRegistration();
  const signIn = authenticationResponse({ credential, challenge: Buffer.from(regOptions.publicKey.challenge, 'base64url'), rpId: RP_ID, origin: ORIGIN, userHandle: Buffer.from(result.userId) });
  assert.throws(() => h.ceremonies.finishAuthentication({ challengeId: regOptions.challengeId, response: signIn }), errorCode(ChallengeError, 'wrong_ceremony'));
  const authOptions = h.ceremonies.startAuthentication();
  const reg = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(authOptions.publicKey.challenge, 'base64url'), rpId: RP_ID, origin: ORIGIN });
  assert.throws(() => h.ceremonies.finishRegistration({ challengeId: authOptions.challengeId, response: reg }), errorCode(ChallengeError, 'wrong_ceremony'));
});

test('negative: unknown credential is rejected in a sign-in ceremony', () => {
  const h = harness();
  const { result } = h.registerOwner(makeCredential());
  const stranger = makeCredential();
  assert.throws(() => h.ceremonies.finishAuthentication(h.signInResponse(stranger, { userId: result.userId })), errorCode(PasskeyError, 'unknown_credential'));
  // Before any store exists, every credential is unknown.
  const empty = harness();
  assert.throws(() => empty.ceremonies.finishAuthentication(empty.signInResponse(stranger, { userId: 'usr_nobody_00001' })), errorCode(PasskeyError, 'unknown_credential'));
});

// Records each verifier call and how it ended, then behaves like the real one.
const verifySpy = () => {
  const calls = [];
  const verify = (input) => {
    const call = { credential: input.credential, error: null };
    calls.push(call);
    try {
      return verifyAuthentication(input);
    } catch (error) {
      call.error = error;
      throw error;
    }
  };
  return { calls, verify };
};

test('negative: an unknown credential does the same signature work as a known one (dummy key of the same algorithm) and still fails generically', () => {
  for (const alg of [-7, -257]) {
    const spy = verifySpy();
    const h = harness({ verify: spy.verify });
    const { result } = h.registerOwner(makeCredential());
    const stranger = makeCredential({ alg });
    const attempt = h.signInResponse(stranger, { userId: result.userId });
    spy.calls.length = 0;
    assert.throws(() => h.ceremonies.finishAuthentication(attempt), errorCode(PasskeyError, 'unknown_credential'), `alg ${alg}`);
    assert.equal(spy.calls.length, 1, `alg ${alg}: verifier ran once`);
    const [call] = spy.calls;
    assert.equal(parseCoseKey(Buffer.from(call.credential.publicKey, 'base64url')).alg, alg, `alg ${alg}: dummy key family`);
    assert.ok(call.error instanceof WebAuthnError && call.error.code === 'bad_signature', `alg ${alg}: reached the signature check`);
  }
  // With no store yet, the dummy verification still runs.
  const spy = verifySpy();
  const empty = harness({ verify: spy.verify });
  assert.throws(() => empty.ceremonies.finishAuthentication(empty.signInResponse(makeCredential(), { userId: 'usr_nobody_00001' })), errorCode(PasskeyError, 'unknown_credential'));
  assert.equal(spy.calls.length, 1);
  assert.equal(spy.calls[0].error.code, 'bad_signature');
});

test('ceremony: a disabled user is refused only after the signature is verified', () => {
  const spy = verifySpy();
  const h = harness({ verify: spy.verify });
  h.registerOwner(makeCredential());
  const member = h.store.createUser({ displayName: 'Test Member' });
  const credential = makeCredential();
  h.store.addCredential(member.id, { id: credential.rawId, publicKey: credential.cose });
  h.store.disableUser(member.id);
  spy.calls.length = 0;
  assert.throws(() => h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: member.id, signCount: 2 })), errorCode(PasskeyError, 'user_disabled'));
  assert.equal(spy.calls.length, 1);
  assert.equal(spy.calls[0].error, null);
  assert.equal(h.store.load().users[1].credentials[0].counter, 0);
});

test('negative: lower or equal signCount is rejected in a sign-in ceremony and the stored counter is unchanged', () => {
  const h = harness();
  const credential = makeCredential();
  const { result } = h.registerOwner(credential);
  h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: result.userId, signCount: 10 }));
  for (const signCount of [10, 9, 0]) {
    assert.throws(() => h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: result.userId, signCount })), errorCode(WebAuthnError, 'counter_regression'));
  }
  assert.equal(h.store.load().users[0].credentials[0].counter, 10);
  h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: result.userId, signCount: 11 }));
  assert.equal(h.store.load().users[0].credentials[0].counter, 11);
});

test('ceremony: a user handle for a different user is rejected, and one is required', () => {
  const h = harness();
  const credential = makeCredential();
  h.registerOwner(credential);
  assert.throws(() => h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: 'usr_someone_else' })), errorCode(WebAuthnError, 'user_handle_mismatch'));
  const options = h.ceremonies.startAuthentication();
  const response = authenticationResponse({ credential, challenge: Buffer.from(options.publicKey.challenge, 'base64url'), rpId: RP_ID, origin: ORIGIN });
  assert.throws(() => h.ceremonies.finishAuthentication({ challengeId: options.challengeId, response }), errorCode(WebAuthnError, 'user_handle_mismatch'));
});

test('ceremony: disabled users cannot sign in', () => {
  const h = harness();
  h.registerOwner(makeCredential());
  const member = h.store.createUser({ displayName: 'Test Member' });
  const credential = makeCredential();
  h.store.addCredential(member.id, { id: credential.rawId, publicKey: credential.cose });
  assert.equal(h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: member.id })).role, 'member');
  h.store.disableUser(member.id);
  assert.throws(() => h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: member.id, signCount: 2 })), errorCode(PasskeyError, 'user_disabled'));
});

test('ceremony: registering the same credential twice fails with duplicate_id; bad labels fail with invalid_argument', () => {
  const h = harness();
  const credential = makeCredential();
  h.registerOwner(credential);
  const options = h.ceremonies.startRegistration();
  const response = registrationResponse({ credential, challenge: Buffer.from(options.publicKey.challenge, 'base64url'), rpId: RP_ID, origin: ORIGIN });
  assert.throws(() => h.ceremonies.finishRegistration({ challengeId: options.challengeId, response }), errorCode(IdentityStoreError, 'duplicate_id'));
  assert.throws(() => h.registerOwner(makeCredential(), { label: 'x'.repeat(65) }), errorCode(IdentityStoreError, 'invalid_argument'));
});

test('ceremony: a failed first registration leaves no store, and a later valid registration creates the owner', () => {
  const h = harness({ lockWaitMs: 50 });
  const missing = errorCode(IdentityStoreError, 'missing');
  for (const label of ['x'.repeat(65), 42, ['laptop'], 'bad\u202Elabel']) {
    assert.throws(() => h.registerOwner(makeCredential(), { displayName: 'Wrong Name', label }), errorCode(IdentityStoreError, 'invalid_argument'));
    assert.throws(() => h.store.load(), missing);
  }
  fs.mkdirSync(path.dirname(h.file), { recursive: true });
  fs.writeFileSync(`${h.file}.lock`, 'held-by-another-writer');
  assert.throws(() => h.registerOwner(makeCredential(), { displayName: 'Wrong Name' }), errorCode(IdentityStoreError, 'store_busy'));
  fs.rmSync(`${h.file}.lock`);
  assert.throws(() => h.store.load(), missing);

  const credential = makeCredential();
  const { result } = h.registerOwner(credential, { label: 'Test laptop' });
  assert.equal(result.createdOwner, true);
  const [owner] = h.store.load().users;
  assert.equal(owner.display_name, 'Ada Example');
  assert.deepEqual(owner.credentials.map((c) => c.label), ['Test laptop']);
  assert.equal(h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: result.userId })).userId, result.userId);
});

test('ceremony: a busy identity store surfaces store_busy instead of blocking for long', () => {
  const h = harness({ lockWaitMs: 50 });
  const credential = makeCredential();
  const { result } = h.registerOwner(credential);
  fs.writeFileSync(`${h.file}.lock`, 'held-by-another-writer');
  const started = Date.now();
  assert.throws(() => h.ceremonies.finishAuthentication(h.signInResponse(credential, { userId: result.userId, signCount: 4 })), errorCode(IdentityStoreError, 'store_busy'));
  assert.ok(Date.now() - started < 2000);
  fs.rmSync(`${h.file}.lock`);
});

test('ceremony: bad relying-party config fails at construction', () => {
  const { root, file } = makeLayout();
  const store = openIdentityStore({ file, root });
  assert.throws(() => createPasskeyCeremonies({ store, rpId: 'example.com', origins: ['https://evil.example'] }), errorCode(WebAuthnError, 'invalid_argument'));
});
