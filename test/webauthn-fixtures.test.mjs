// Recorded real-browser WebAuthn fixtures: one JSON file per browser and
// authenticator in test/fixtures/webauthn/ (format in that folder's
// README.md). Each fixture's registration is verified, then each
// authentication in order with the counter carried forward and persisted
// through the identity store, then negative mutations of the real data.
//
// The expected challenge comes from the fixture (injected), since challenge
// issuing is a separate layer. When the folder has no fixtures, the
// per-fixture test is skipped; the harness itself is still exercised below
// with a synthetic fixture built at runtime.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openIdentityStore } from '../skill/lib/identity/store.mjs';
import { WebAuthnError, verifyAuthentication, verifyRegistration } from '../skill/lib/identity/webauthn.mjs';
import { authenticationResponse, makeCredential, registrationResponse } from './support/webauthn-synthetic.mjs';

const fixtureDir = path.join(import.meta.dirname, 'fixtures', 'webauthn');

// Fixtures are public: only reserved or local names may appear as the rp id.
const RESERVED_HOST_RE = /(^|\.)(example\.(com|net|org)|example|test|localhost|invalid)$/;

const isB64u = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value);

const checkFixtureShape = (fixture, name) => {
  const where = (field) => `${name}: ${field}`;
  const p = fixture.provenance;
  assert.ok(p && typeof p === 'object', where('provenance'));
  for (const field of ['browser', 'browser_version', 'os', 'authenticator', 'captured', 'method']) {
    assert.equal(typeof p[field], 'string', where(`provenance.${field}`));
    assert.ok(p[field].length > 0, where(`provenance.${field}`));
  }
  assert.match(p.captured, /^\d{4}-\d{2}-\d{2}$/, where('provenance.captured'));
  assert.equal(typeof fixture.rp_id, 'string', where('rp_id'));
  assert.match(fixture.rp_id, RESERVED_HOST_RE, where('rp_id must be a reserved example or local name'));
  const origin = new URL(fixture.origin);
  assert.equal(origin.origin, fixture.origin, where('origin must be exactly scheme://host[:port]'));
  assert.match(origin.hostname, RESERVED_HOST_RE, where('origin host must be a reserved example or local name'));
  assert.ok(isB64u(fixture.user?.id), where('user.id'));
  assert.ok(isB64u(fixture.registration?.challenge), where('registration.challenge'));
  assert.equal(fixture.registration?.response?.type, 'public-key', where('registration.response.type'));
  assert.ok(Array.isArray(fixture.authentications) && fixture.authentications.length > 0, where('authentications'));
  fixture.authentications.forEach((auth, index) => {
    assert.ok(isB64u(auth.challenge), where(`authentications[${index}].challenge`));
    assert.equal(auth.response?.type, 'public-key', where(`authentications[${index}].response.type`));
  });
};

const rejectsWith = (fn, expected, label) => assert.throws(fn, (error) => {
  assert.ok(error instanceof WebAuthnError, `${label}: expected WebAuthnError, got ${error?.name}`);
  assert.equal(error.code, expected, label);
  return true;
});

const tempStore = () => {
  const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cockpit-webauthn-fixture-')));
  const root = path.join(base, 'root');
  fs.mkdirSync(root);
  return openIdentityStore({ file: path.join(base, 'state', 'identity.json'), root });
};

/**
 * Verify one fixture: registration, authentications in order, then negative
 * mutations derived from the recorded data.
 */
const runFixture = (fixture, name) => {
  checkFixtureShape(fixture, name);
  const rpId = fixture.rp_id;
  const origins = [fixture.origin];
  const challengeOf = (value) => Buffer.from(value, 'base64url');
  const userHandle = Buffer.from(fixture.user.id, 'base64url');

  // Registration.
  const registered = verifyRegistration({ response: fixture.registration.response, expectedChallenge: challengeOf(fixture.registration.challenge), rpId, origins });
  assert.equal(registered.credentialId, fixture.registration.response.rawId, `${name}: credential id`);
  assert.ok([-7, -257].includes(registered.alg), `${name}: algorithm`);

  // Persist it like serve does, so real ids, keys, and transports pass the store's rules.
  const store = tempStore();
  const owner = store.createUser({ displayName: 'Ada Example', role: 'owner' });
  store.addCredential(owner.id, { id: registered.credentialId, publicKey: registered.publicKey, counter: registered.counter, transports: registered.transports });

  // Authentications in order; counters must behave.
  const stored = () => {
    const credential = store.load().users[0].credentials[0];
    return { id: credential.id, publicKey: credential.public_key, counter: credential.counter };
  };
  for (const [index, auth] of fixture.authentications.entries()) {
    const before = stored();
    const hasHandle = typeof auth.response.response?.userHandle === 'string' && auth.response.response.userHandle !== '';
    const result = verifyAuthentication({
      response: auth.response,
      expectedChallenge: challengeOf(auth.challenge),
      rpId,
      origins,
      credential: before,
      expectedUserHandle: hasHandle ? userHandle : undefined,
    });
    assert.equal(result.credentialId, registered.credentialId, `${name}: authentications[${index}] credential`);
    if (before.counter !== 0 || result.counter !== 0) {
      assert.ok(result.counter > before.counter, `${name}: authentications[${index}] counter increases`);
      store.updateCounter(result.credentialId, result.counter);
    }
  }

  // Negative mutations of real data.
  const [first] = fixture.authentications;
  const firstArgs = (overrides = {}) => ({
    response: first.response,
    expectedChallenge: challengeOf(first.challenge),
    rpId,
    origins,
    credential: { ...stored(), counter: registered.counter },
    ...overrides,
  });

  const flipped = structuredClone(first.response);
  const sig = Buffer.from(flipped.response.signature, 'base64url');
  sig[Math.floor(sig.length / 2)] ^= 0x01;
  flipped.response.signature = sig.toString('base64url');
  rejectsWith(() => verifyAuthentication(firstArgs({ response: flipped })), 'bad_signature', `${name}: flipped signature byte`);

  const data = structuredClone(first.response);
  const authData = Buffer.from(data.response.authenticatorData, 'base64url');
  authData[authData.length - 1] ^= 0x01;
  data.response.authenticatorData = authData.toString('base64url');
  assert.throws(() => verifyAuthentication(firstArgs({ response: data })), WebAuthnError, `${name}: tampered authenticatorData`);

  rejectsWith(() => verifyAuthentication(firstArgs({ origins: ['https://wrong.example.com'] })), 'origin_mismatch', `${name}: wrong origin config`);
  rejectsWith(() => verifyAuthentication(firstArgs({ rpId: 'wrong.example.com' })), 'rp_id_mismatch', `${name}: wrong rpId config`);
  rejectsWith(() => verifyRegistration({
    response: fixture.registration.response, expectedChallenge: challengeOf(fixture.registration.challenge), rpId, origins: ['https://wrong.example.com'],
  }), 'origin_mismatch', `${name}: registration with wrong origin config`);
  rejectsWith(() => verifyRegistration({
    response: fixture.registration.response, expectedChallenge: challengeOf(fixture.registration.challenge), rpId: 'wrong.example.com', origins,
  }), 'rp_id_mismatch', `${name}: registration with wrong rpId config`);

  // Replay: the recorded response cannot satisfy a fresh challenge, and once
  // the counter has moved on (if the authenticator keeps one) it is stale.
  rejectsWith(() => verifyAuthentication(firstArgs({ expectedChallenge: crypto.randomBytes(32) })), 'challenge_mismatch', `${name}: replay against a new challenge`);
  rejectsWith(() => verifyRegistration({
    response: fixture.registration.response, expectedChallenge: crypto.randomBytes(32), rpId, origins,
  }), 'challenge_mismatch', `${name}: registration replay against a new challenge`);
  const finalCounter = stored().counter;
  if (finalCounter !== 0) {
    rejectsWith(() => verifyAuthentication(firstArgs({ credential: stored() })), 'counter_regression', `${name}: replay after the counter moved on`);
  }

  // Wrong ceremony: a registration clientDataJSON cannot sign in.
  const crossed = structuredClone(first.response);
  crossed.response.clientDataJSON = fixture.registration.response.response.clientDataJSON;
  rejectsWith(() => verifyAuthentication(firstArgs({ response: crossed, expectedChallenge: challengeOf(fixture.registration.challenge) })), 'wrong_type', `${name}: registration clientData used to sign in`);

  // Unknown credential: the response does not belong to another stored credential.
  const other = makeCredential();
  rejectsWith(() => verifyAuthentication(firstArgs({
    credential: { id: other.rawId.toString('base64url'), publicKey: other.cose.toString('base64url'), counter: 0 },
  })), 'credential_id_mismatch', `${name}: unknown credential`);

  return { registered, authentications: fixture.authentications.length, finalCounter };
};

const fixtureFiles = fs.existsSync(fixtureDir)
  ? fs.readdirSync(fixtureDir).filter((file) => file.endsWith('.json')).sort()
  : [];

if (fixtureFiles.length === 0) {
  test('recorded real-browser WebAuthn fixtures verify', { skip: `no recorded fixtures in ${path.relative(process.cwd(), fixtureDir) || fixtureDir} yet` }, () => {});
}

for (const file of fixtureFiles) {
  test(`recorded fixture ${file}: registration, authentications in order, and negative mutations`, () => {
    const fixture = JSON.parse(fs.readFileSync(path.join(fixtureDir, file), 'utf8'));
    runFixture(fixture, file);
  });
}

// ---------------------------------------------------------------------------
// Harness self-test with a SYNTHETIC fixture (generated at runtime, never
// written to disk), so the fixture code path is covered before real
// recordings exist.

const syntheticFixture = ({ alg, counters }) => {
  const credential = makeCredential({ alg });
  const rpId = 'example.com';
  const origin = 'https://example.com';
  const user = Buffer.from('usr_synthetic_ada', 'utf8');
  const regChallenge = crypto.randomBytes(32);
  return {
    provenance: {
      browser: 'synthetic', browser_version: '0', os: 'none', authenticator: `synthetic ${alg === -7 ? 'ES256' : 'RS256'}`, captured: '2026-01-01', method: 'generated at test runtime', notes: 'not a real recording',
    },
    rp_id: rpId,
    origin,
    user: { id: user.toString('base64url'), name: 'ada@example.com', display_name: 'Ada Example' },
    registration: {
      challenge: regChallenge.toString('base64url'),
      response: registrationResponse({ credential, challenge: regChallenge, rpId, origin, signCount: counters[0] }),
    },
    authentications: counters.slice(1).map((signCount) => {
      const challenge = crypto.randomBytes(32);
      return { challenge: challenge.toString('base64url'), response: authenticationResponse({ credential, challenge, rpId, origin, signCount, userHandle: user }) };
    }),
  };
};

test('fixture harness self-test: synthetic ES256 fixture with counters', () => {
  const result = runFixture(syntheticFixture({ alg: -7, counters: [0, 1, 2, 5] }), 'synthetic-es256');
  assert.equal(result.authentications, 3);
  assert.equal(result.finalCounter, 5);
});

test('fixture harness self-test: synthetic RS256 fixture without a counter (always 0)', () => {
  const result = runFixture(syntheticFixture({ alg: -257, counters: [0, 0, 0] }), 'synthetic-rs256');
  assert.equal(result.finalCounter, 0);
});

test('fixture harness self-test: a fixture with a non-increasing counter fails', () => {
  assert.throws(() => runFixture(syntheticFixture({ alg: -7, counters: [0, 3, 3] }), 'synthetic-bad-counter'), WebAuthnError);
});

test('fixture harness self-test: fixtures must use reserved example or local host names', () => {
  const fixture = syntheticFixture({ alg: -7, counters: [0, 1] });
  assert.throws(() => checkFixtureShape({ ...fixture, rp_id: 'cockpit.realcompany.io' }, 'bad'), /reserved/);
  assert.throws(() => checkFixtureShape({ ...fixture, origin: 'https://cockpit.realcompany.io' }, 'bad'), /reserved/);
  assert.throws(() => checkFixtureShape({ ...fixture, provenance: { ...fixture.provenance, captured: 'yesterday' } }, 'bad'));
  assert.doesNotThrow(() => checkFixtureShape(fixture, 'ok'));
});
