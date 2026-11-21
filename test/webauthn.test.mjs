// Verifier tests with synthetic credentials generated at runtime (see
// test/support/webauthn-synthetic.mjs). No recorded browser data here.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  LIMITS, WebAuthnError, derToRawEcdsa, normalizeRelyingParty, parseAuthenticatorData, parseCoseKey, verifyAuthentication, verifyRegistration,
} from '../skill/lib/identity/webauthn.mjs';
import {
  FLAGS, ORIGIN, RP_ID, RawCbor, authData, authenticationResponse, cbor, clientData, coseMapFor, makeCredential, registrationResponse, sign,
  storedCredential,
} from './support/webauthn-synthetic.mjs';

const challenge = () => crypto.randomBytes(32);
const origins = [ORIGIN];
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

const code = (expected) => (error) => {
  assert.ok(error instanceof WebAuthnError, `expected WebAuthnError, got ${error?.name}: ${error?.message}`);
  assert.equal(error.code, expected);
  return true;
};

const register = (credential, overrides = {}) => {
  const expectedChallenge = overrides.expectedChallenge ?? challenge();
  const response = registrationResponse({ credential, challenge: expectedChallenge, ...overrides });
  return () => verifyRegistration({ response, expectedChallenge, rpId: overrides.verifyRpId ?? RP_ID, origins: overrides.verifyOrigins ?? origins });
};

const authenticate = (credential, overrides = {}) => {
  const expectedChallenge = overrides.expectedChallenge ?? challenge();
  const response = overrides.response ?? authenticationResponse({ credential, challenge: overrides.signedChallenge ?? expectedChallenge, ...overrides });
  return () => verifyAuthentication({
    response,
    expectedChallenge,
    rpId: overrides.verifyRpId ?? RP_ID,
    origins: overrides.verifyOrigins ?? origins,
    credential: overrides.stored ?? storedCredential(credential, overrides.storedCounter ?? 0),
    expectedUserHandle: overrides.expectedUserHandle,
    requireUserHandle: overrides.requireUserHandle,
  });
};

const es256 = makeCredential({ alg: -7 });
const rs256 = makeCredential({ alg: -257 });

// ---------------------------------------------------------------------------
// Happy paths

test('synthetic ES256 registration and sign-in verify end to end', () => {
  const registered = register(es256, { signCount: 0 })();
  assert.equal(registered.alg, -7);
  assert.equal(registered.credentialId, b64u(es256.rawId));
  assert.equal(registered.publicKey, b64u(es256.cose));
  assert.equal(registered.counter, 0);
  assert.equal(registered.aaguid, '00000000-0000-0000-0000-000000000000');
  assert.deepEqual(registered.transports, ['internal']);

  const userHandle = Buffer.from('usr_example0001', 'utf8');
  const first = authenticate(es256, { signCount: 1, userHandle, expectedUserHandle: userHandle, requireUserHandle: true })();
  assert.equal(first.credentialId, registered.credentialId);
  assert.equal(first.counter, 1);
  assert.equal(first.userHandle, b64u(userHandle));
  const second = authenticate(es256, { signCount: 2, storedCounter: 1 })();
  assert.equal(second.counter, 2);
});

test('synthetic RS256 registration and sign-in verify end to end (2048- and 4096-bit keys)', () => {
  for (const credential of [rs256, makeCredential({ alg: -257, rsaBits: 4096 })]) {
    const registered = register(credential)();
    assert.equal(registered.alg, -257);
    const result = authenticate(credential, { signCount: 5 })();
    assert.equal(result.counter, 5);
  }
});

test('authenticators without a counter (always 0) are accepted', () => {
  assert.equal(authenticate(es256, { signCount: 0, storedCounter: 0 })().counter, 0);
});

test('high-S ES256 signatures are accepted', () => {
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const expectedChallenge = challenge();
  const data = authData({ signCount: 3 });
  const client = clientData({ type: 'webauthn.get', challenge: expectedChallenge });
  const der = sign(es256, Buffer.concat([data, sha256(client)]));
  const raw = derToRawEcdsa(der);
  const r = BigInt(`0x${raw.subarray(0, 32).toString('hex')}`);
  let s = BigInt(`0x${raw.subarray(32).toString('hex')}`);
  if (s <= n / 2n) s = n - s; // force high-S
  const int = (value) => {
    let bytes = Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
    while (bytes.length > 1 && bytes[0] === 0 && !(bytes[1] & 0x80)) bytes = bytes.subarray(1);
    if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
    return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
  };
  const body = Buffer.concat([int(r), int(s)]);
  const highS = Buffer.concat([Buffer.from([0x30, body.length]), body]);
  const response = authenticationResponse({ credential: es256, challenge: expectedChallenge, authDataBytes: data, clientDataBytes: client, signature: highS });
  assert.equal(authenticate(es256, { expectedChallenge, response })().counter, 3);
});

test('unknown clientDataJSON members are ignored, as the spec requires', () => {
  assert.doesNotThrow(register(es256, { clientDataExtra: { other_keys_can_be_added_here: 'do not compare clientDataJSON against a template' } }));
});

// ---------------------------------------------------------------------------
// Issue #8 negative tests (one per listed item)

test('negative: bad signature is rejected', () => {
  const expectedChallenge = challenge();
  const response = authenticationResponse({ credential: es256, challenge: expectedChallenge });
  const sig = Buffer.from(response.response.signature, 'base64url');
  sig[sig.length - 1] ^= 0x01;
  response.response.signature = b64u(sig);
  assert.throws(authenticate(es256, { expectedChallenge, response }), code('bad_signature'));
  // Signed by a different key.
  const other = makeCredential();
  const forged = authenticationResponse({ credential: { ...other, rawId: es256.rawId }, challenge: expectedChallenge });
  assert.throws(authenticate(es256, { expectedChallenge, response: forged }), code('bad_signature'));
  // RS256 too.
  const rsResponse = authenticationResponse({ credential: rs256, challenge: expectedChallenge });
  const rsSig = Buffer.from(rsResponse.response.signature, 'base64url');
  rsSig[10] ^= 0xff;
  rsResponse.response.signature = b64u(rsSig);
  assert.throws(authenticate(rs256, { expectedChallenge, response: rsResponse }), code('bad_signature'));
});

test('negative: a signature over tampered authenticatorData or clientDataJSON is rejected', () => {
  const expectedChallenge = challenge();
  const response = authenticationResponse({ credential: es256, challenge: expectedChallenge, signCount: 7 });
  const data = Buffer.from(response.response.authenticatorData, 'base64url');
  data.writeUInt32BE(8, 33); // bump the counter after signing
  response.response.authenticatorData = b64u(data);
  assert.throws(authenticate(es256, { expectedChallenge, response }), code('bad_signature'));
});

test('negative: wrong origin is rejected (registration and sign-in)', () => {
  assert.throws(register(es256, { origin: 'https://evil.example' }), code('origin_mismatch'));
  assert.throws(register(es256, { origin: 'https://example.com:8443' }), code('origin_mismatch'));
  assert.throws(register(es256, { origin: 'http://example.com' }), code('origin_mismatch'));
  assert.throws(register(es256, { origin: 'https://sub.example.com' }), code('origin_mismatch'));
  assert.throws(register(es256, { origin: 'https://example.com/' }), code('origin_mismatch'));
  assert.throws(authenticate(es256, { origin: 'https://evil.example' }), code('origin_mismatch'));
  assert.throws(authenticate(es256, { verifyOrigins: ['https://other.example.com'] }), code('origin_mismatch'));
});

test('negative: replayed challenge is rejected (a response for one challenge cannot satisfy another)', () => {
  // Single use itself is enforced by the challenge store (passkeys tests);
  // here the verifier refuses a response signed over a different challenge.
  assert.throws(register(es256, { challenge: challenge(), expectedChallenge: challenge() }), code('challenge_mismatch'));
  assert.throws(authenticate(es256, { signedChallenge: challenge() }), code('challenge_mismatch'));
  // Same length, one bit different.
  const expectedChallenge = challenge();
  const flipped = Buffer.from(expectedChallenge);
  flipped[0] ^= 1;
  assert.throws(authenticate(es256, { expectedChallenge, signedChallenge: flipped }), code('challenge_mismatch'));
  // Padded base64 of the right bytes is not the same challenge string.
  const padded = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: `${b64u(expectedChallenge)}=`, origin: ORIGIN }));
  const response = authenticationResponse({ credential: es256, challenge: expectedChallenge, clientDataBytes: padded });
  assert.throws(authenticate(es256, { expectedChallenge, response }), code('challenge_mismatch'));
});

test('negative: wrong rpId is rejected (registration and sign-in)', () => {
  assert.throws(register(es256, { rpId: 'evil.example' }), code('rp_id_mismatch'));
  assert.throws(register(es256, { verifyRpId: 'other.example' }), code('rp_id_mismatch'));
  assert.throws(authenticate(es256, { rpId: 'evil.example' }), code('rp_id_mismatch'));
  assert.throws(authenticate(es256, { rpId: 'sub.example.com' }), code('rp_id_mismatch'));
});

test('negative: wrong ceremony type in clientDataJSON is rejected', () => {
  assert.throws(register(es256, { type: 'webauthn.get' }), code('wrong_type'));
  assert.throws(authenticate(es256, { type: 'webauthn.create' }), code('wrong_type'));
  assert.throws(authenticate(es256, { type: 'payment.get' }), code('wrong_type'));
});

test('negative: unknown credential (rawId does not match the stored credential) is rejected', () => {
  const other = makeCredential();
  assert.throws(authenticate(es256, { stored: storedCredential(other) }), code('credential_id_mismatch'));
});

test('negative: lower or equal signCount is rejected', () => {
  assert.throws(authenticate(es256, { signCount: 4, storedCounter: 5 }), code('counter_regression'));
  assert.throws(authenticate(es256, { signCount: 5, storedCounter: 5 }), code('counter_regression'));
  assert.throws(authenticate(es256, { signCount: 0, storedCounter: 5 }), code('counter_regression'));
  assert.doesNotThrow(authenticate(es256, { signCount: 6, storedCounter: 5 }));
  assert.doesNotThrow(authenticate(es256, { signCount: 1, storedCounter: 0 }));
});

// ---------------------------------------------------------------------------
// Attestation, algorithms, and keys

test('attestation formats other than none are rejected', () => {
  for (const fmt of ['packed', 'fido-u2f', 'tpm', 'android-key', 'android-safetynet', 'apple']) {
    assert.throws(register(es256, { fmt }), code('unsupported_attestation'), fmt);
  }
  // Self attestation (packed, alg + sig, no x5c) is rejected too.
  assert.throws(register(es256, { fmt: 'packed', attStmt: new Map([['alg', -7], ['sig', Buffer.alloc(70)]]) }), code('unsupported_attestation'));
});

test('none attestation with a non-empty attStmt is rejected', () => {
  assert.throws(register(es256, { attStmt: new Map([['sig', Buffer.alloc(8)]]) }), code('unsupported_attestation'));
});

test('malformed attestation objects are rejected', () => {
  const data = authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.AT, attested: { credentialId: es256.rawId, cose: es256.cose } });
  const variants = [
    cbor(new Map([['fmt', 'none'], ['attStmt', new Map()]])),
    cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', data], ['extra', 1]])),
    cbor(new Map([['fmt', 1], ['attStmt', new Map()], ['authData', data]])),
    cbor(new Map([['fmt', 'none'], ['attStmt', []], ['authData', data]])),
    cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', 'text']])),
    cbor([1, 2, 3]),
    Buffer.concat([cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', data]])), Buffer.from([0])]),
    Buffer.from([0xbf]),
  ];
  for (const attestation of variants) assert.throws(register(es256, { attestation }), code('invalid_attestation'));
});

test('algorithms other than ES256 (-7) and RS256 (-257) are rejected at registration', () => {
  const ed = crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const keys = [
    new Map([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(ed.x, 'base64url')]]), // EdDSA
    new Map([[1, 2], [3, -35], [-1, 2], [-2, Buffer.alloc(48, 1)], [-3, Buffer.alloc(48, 2)]]), // ES384
    new Map([[1, 3], [3, -37], [-1, rs256.coseMap.get(-1)], [-2, rs256.coseMap.get(-2)]]), // PS256
    new Map([[1, 3], [3, -65535], [-1, rs256.coseMap.get(-1)], [-2, rs256.coseMap.get(-2)]]), // RS1
  ];
  for (const map of keys) {
    const credential = { ...es256, cose: cbor(map) };
    assert.throws(register(credential), code('unsupported_algorithm'));
    assert.throws(() => parseCoseKey(cbor(map)), code('unsupported_algorithm'));
  }
});

test('COSE keys must have consistent kty, alg, and crv and exact parameters', () => {
  const m = (entries) => cbor(new Map(entries));
  const { coseMap: ec } = es256;
  const x = ec.get(-2);
  const y = ec.get(-3);
  const n = rs256.coseMap.get(-1);
  const e = rs256.coseMap.get(-2);
  const bad = [
    m([[1, 3], [3, -7], [-1, 1], [-2, x], [-3, y]]), // RSA kty with ES256
    m([[1, 2], [3, -257], [-1, n], [-2, e]]), // EC2 kty with RS256
    m([[1, 2], [3, -7], [-1, 2], [-2, x], [-3, y]]), // P-384 crv
    m([[1, 2], [3, -7], [-1, 1], [-2, x.subarray(1)], [-3, y]]), // short x
    m([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, Buffer.concat([y, Buffer.from([0])])]]), // long y
    m([[1, 2], [3, -7], [-1, 1], [-2, x]]), // missing y
    m([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, 1]]), // compressed point
    m([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y], [-4, Buffer.alloc(32, 1)]]), // private d
    m([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y], [2, Buffer.from('kid')]]), // extra label
    m([[1, 2], [3, -7], [-1, 1], [-2, Buffer.alloc(32, 1)], [-3, Buffer.alloc(32, 2)]]), // not on curve
    m([[1, 2], [3, -7], [-1, 1], [-2, Buffer.alloc(32, 0xff)], [-3, y]]), // x >= p
    m([[1, 3], [3, -257], [-1, n], [-2, Buffer.from([0x03])]]), // e = 3
    m([[1, 3], [3, -257], [-1, n], [-2, Buffer.from([0x00, 0x01, 0x00, 0x01])]]), // e with leading zero
    m([[1, 3], [3, -257], [-1, Buffer.concat([Buffer.from([0]), n])], [-2, e]]), // n with leading zero
    m([[1, 3], [3, -257], [-1, n.subarray(0, 128)], [-2, e]]), // 1024-bit modulus
    m([[1, 3], [3, -257], [-1, Buffer.alloc(513, 0xff)], [-2, e]]), // > 4096-bit modulus
    m([[1, 3], [3, -257], [-1, Buffer.concat([n.subarray(0, 255), Buffer.from([0x02])])], [-2, e]]), // even modulus
    m([[1, 3], [3, -257], [-1, n]]), // missing e
    m([[1, 2], [3, '-7'], [-1, 1], [-2, x], [-3, y]]), // alg as text
    cbor([1, 2]),
    Buffer.concat([es256.cose, Buffer.from([0])]), // trailing byte
  ];
  for (const [index, cose] of bad.entries()) {
    assert.throws(() => parseCoseKey(cose), (error) => error instanceof WebAuthnError && ['invalid_public_key', 'unsupported_algorithm'].includes(error.code), `case ${index}`);
  }
  for (const cose of bad.slice(0, 11)) assert.throws(register({ ...es256, cose }), WebAuthnError);
});

test('parseCoseKey imports valid ES256 and RS256 keys through node:crypto', () => {
  const ec = parseCoseKey(es256.cose);
  assert.equal(ec.alg, -7);
  assert.equal(ec.key.asymmetricKeyType, 'ec');
  const rsa = parseCoseKey(rs256.cose);
  assert.equal(rsa.alg, -257);
  assert.equal(rsa.key.asymmetricKeyType, 'rsa');
  assert.equal(rsa.signatureSize, 256);
});

// ---------------------------------------------------------------------------
// DER signatures

test('ES256 signatures must be strict DER', () => {
  const expectedChallenge = challenge();
  const data = authData({ signCount: 1 });
  const client = clientData({ type: 'webauthn.get', challenge: expectedChallenge });
  // Re-sign until the DER signature is at most 71 bytes, so wrong_seq_len
  // (one byte longer) stays within the 72-byte limit and reaches the
  // sequence-length check instead of the overall length check.
  let der;
  do der = sign(es256, Buffer.concat([data, sha256(client)])); while (der.length > 71);
  const respond = (signature) => authenticate(es256, {
    expectedChallenge,
    response: authenticationResponse({ credential: es256, challenge: expectedChallenge, authDataBytes: data, clientDataBytes: client, signature }),
  });
  assert.doesNotThrow(respond(der));

  const raw = derToRawEcdsa(der);
  const variants = {
    raw_p1363: raw,
    trailing_byte: Buffer.concat([der, Buffer.from([0])]),
    wrong_seq_len: Buffer.concat([Buffer.from([0x30, der[1] + 1]), der.subarray(2), Buffer.from([0])]),
    long_form_len: Buffer.concat([Buffer.from([0x30, 0x81, der[1]]), der.subarray(2)]),
    wrong_tag: Buffer.concat([Buffer.from([0x31]), der.subarray(1)]),
    truncated: der.subarray(0, der.length - 1),
  };
  // Extra leading zero on r (non-minimal INTEGER).
  const rLen = der[3];
  const rBody = der.subarray(4, 4 + rLen);
  const rest = der.subarray(4 + rLen);
  const padded = Buffer.concat([Buffer.from([0x02, rLen + 1, 0x00]), rBody, rest]);
  variants.non_minimal_r = Buffer.concat([Buffer.from([0x30, padded.length]), padded]);
  // Negative r (sign bit set without the 0x00 pad).
  if (rBody[0] === 0) {
    const neg = Buffer.concat([Buffer.from([0x02, rLen - 1]), rBody.subarray(1), rest]);
    variants.negative_r = Buffer.concat([Buffer.from([0x30, neg.length]), neg]);
  }
  // r = 0 and s = n are out of range.
  const zeroR = Buffer.concat([Buffer.from([0x02, 0x01, 0x00]), rest]);
  variants.zero_r = Buffer.concat([Buffer.from([0x30, zeroR.length]), zeroR]);
  const nBytes = Buffer.from('00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 'hex');
  const sIsN = Buffer.concat([der.subarray(2, 4 + rLen), Buffer.from([0x02, nBytes.length]), nBytes]);
  variants.s_equals_n = Buffer.concat([Buffer.from([0x30, sIsN.length]), sIsN]);

  assert.ok(variants.wrong_seq_len.length <= 72);
  for (const [name, signature] of Object.entries(variants)) {
    assert.throws(respond(signature), code('bad_signature'), name);
    assert.throws(() => derToRawEcdsa(signature), code('bad_signature'), name);
  }
});

test('RS256 signatures must be exactly the modulus length', () => {
  const expectedChallenge = challenge();
  const response = authenticationResponse({ credential: rs256, challenge: expectedChallenge });
  const sig = Buffer.from(response.response.signature, 'base64url');
  response.response.signature = b64u(Buffer.concat([Buffer.from([0]), sig]));
  assert.throws(authenticate(rs256, { expectedChallenge, response }), code('bad_signature'));
});

// ---------------------------------------------------------------------------
// clientDataJSON

test('clientDataJSON must be UTF-8 JSON with string type, challenge, and origin', () => {
  const expectedChallenge = challenge();
  const bodies = [
    Buffer.from('not json'),
    Buffer.from('[]'),
    Buffer.from('null'),
    Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(expectedChallenge), origin: ORIGIN }))]),
    Buffer.from([0x7b, 0xff, 0x7d]),
    Buffer.from(JSON.stringify({ type: 'webauthn.get', origin: ORIGIN })),
    Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: 5, origin: ORIGIN })),
    Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(expectedChallenge), origin: ORIGIN, crossOrigin: 'false' })),
    Buffer.alloc(LIMITS.clientDataJSON + 1, 0x20),
  ];
  for (const [index, clientDataBytes] of bodies.entries()) {
    const response = authenticationResponse({ credential: es256, challenge: expectedChallenge, clientDataBytes });
    assert.throws(authenticate(es256, { expectedChallenge, response }), (error) => error instanceof WebAuthnError
      && ['invalid_client_data', 'malformed_response'].includes(error.code), `case ${index}`);
  }
});

test('crossOrigin true and any topOrigin are rejected', () => {
  assert.throws(authenticate(es256, { clientDataExtra: { crossOrigin: true } }), code('cross_origin'));
  assert.throws(authenticate(es256, { clientDataExtra: { topOrigin: ORIGIN } }), code('cross_origin'));
  assert.throws(register(es256, { clientDataExtra: { crossOrigin: true, topOrigin: 'https://evil.example' } }), code('cross_origin'));
});

// ---------------------------------------------------------------------------
// authenticatorData

test('UP and UV flags are required', () => {
  assert.throws(register(es256, { flags: FLAGS.UV | FLAGS.AT }), code('user_not_present'));
  assert.throws(register(es256, { flags: FLAGS.UP | FLAGS.AT }), code('user_not_verified'));
  assert.throws(authenticate(es256, { flags: FLAGS.UV }), code('user_not_present'));
  assert.throws(authenticate(es256, { flags: FLAGS.UP }), code('user_not_verified'));
});

test('registration requires attested credential data; sign-in refuses it', () => {
  assert.throws(register(es256, { flags: FLAGS.UP | FLAGS.UV, authDataBytes: authData({ flags: FLAGS.UP | FLAGS.UV }) }), code('invalid_authenticator_data'));
  const withAt = authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.AT, signCount: 1, attested: { credentialId: es256.rawId, cose: es256.cose } });
  assert.throws(authenticate(es256, { authDataBytes: withAt }), code('invalid_authenticator_data'));
});

test('authenticatorData parsing enforces exact lengths', () => {
  const at = FLAGS.UP | FLAGS.UV | FLAGS.AT;
  const ok = authData({ flags: at, attested: { credentialId: es256.rawId, cose: es256.cose } });
  assert.equal(parseAuthenticatorData(ok).attested.credentialId.length, 32);
  const bad = {
    too_short: Buffer.alloc(36),
    empty: Buffer.alloc(0),
    trailing_after_37: Buffer.concat([authData(), Buffer.from([0])]),
    trailing_after_key: Buffer.concat([ok, Buffer.from([0])]),
    at_without_data: authData({ flags: at }),
    at_cut_in_aaguid: authData({ flags: at }).subarray(0, 37 + 10),
    cred_len_zero: authData({ flags: at, attested: { credentialId: Buffer.alloc(0), cose: es256.cose } }),
    cred_len_over_1023: authData({ flags: at, attested: { credentialId: Buffer.alloc(1024, 1), cose: es256.cose } }),
    cred_len_past_end: authData({ flags: at, attested: { credentialId: es256.rawId, idLength: 400, cose: es256.cose } }),
    missing_key: authData({ flags: at, attested: { credentialId: es256.rawId, cose: Buffer.alloc(0) } }),
    key_not_map: authData({ flags: at, attested: { credentialId: es256.rawId, cose: cbor([1]) } }),
    key_truncated: authData({ flags: at, attested: { credentialId: es256.rawId, cose: es256.cose.subarray(0, 20) } }),
    key_nested_too_deep: authData({ flags: at, attested: { credentialId: es256.rawId, cose: cbor(new Map([[1, [1]]])) } }),
    ed_without_data: authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.ED }),
    ed_not_map: authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.ED, extensions: cbor([1]) }),
    ed_int_keys: authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.ED, extensions: cbor(new Map([[1, 1]])) }),
    ed_trailing: authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.ED, extensions: Buffer.concat([cbor(new Map([['credProtect', 2]])), Buffer.from([0])]) }),
    ed_tagged: authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.ED, extensions: Buffer.from([0xc0, 0xa0]) }),
    extensions_without_ed: authData({ extensions: cbor(new Map([['credProtect', 2]])) }),
    backed_up_not_eligible: authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.BS }),
    oversized: Buffer.alloc(LIMITS.authenticatorData + 1),
  };
  for (const [name, bytes] of Object.entries(bad)) {
    assert.throws(() => parseAuthenticatorData(bytes), code('invalid_authenticator_data'), name);
  }
  assert.throws(() => parseAuthenticatorData('not bytes'), code('invalid_authenticator_data'));
});

test('well-formed extension outputs (ED) are parsed and ignored', () => {
  const extensions = cbor(new Map([['credProtect', 2], ['hmac-secret', new RawCbor([0x01])]]));
  const ed = FLAGS.UP | FLAGS.UV | FLAGS.ED;
  const parsed = parseAuthenticatorData(authData({ flags: ed, signCount: 9, extensions }));
  assert.equal(parsed.signCount, 9);
  assert.equal(parsed.flags.extensionData, true);
  assert.equal(authenticate(es256, { authDataBytes: authData({ flags: ed, signCount: 9, extensions }) })().counter, 9);
  const both = authData({ flags: ed | FLAGS.AT, attested: { credentialId: es256.rawId, cose: es256.cose }, extensions });
  assert.equal(parseAuthenticatorData(both).attested.publicKey.length, es256.cose.length);
});

test('the credential id in authenticatorData must equal rawId', () => {
  const other = crypto.randomBytes(32);
  const data = authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.AT, attested: { credentialId: other, cose: es256.cose } });
  assert.throws(register(es256, { authDataBytes: data }), code('credential_id_mismatch'));
});

// ---------------------------------------------------------------------------
// Response envelope, credential ids, user handles

test('id and rawId must be the same canonical base64url', () => {
  const expectedChallenge = challenge();
  const base = () => registrationResponse({ credential: es256, challenge: expectedChallenge });
  const check = (response, expected) => assert.throws(() => verifyRegistration({ response, expectedChallenge, rpId: RP_ID, origins }), code(expected));
  check({ ...base(), id: b64u(crypto.randomBytes(32)) }, 'credential_id_mismatch');
  check({ ...base(), rawId: `${base().rawId}=` }, 'malformed_response');
  // Change the first character: every bit of it is significant, so the result
  // stays canonical (changing the last one could set stray low bits).
  check({ ...base(), rawId: base().rawId.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) }, 'credential_id_mismatch');
  check({ ...base(), type: 'password' }, 'malformed_response');
  check({ ...base(), response: null }, 'malformed_response');
  check(null, 'malformed_response');
  check({ ...base(), rawId: b64u(Buffer.alloc(1024, 1)), id: b64u(Buffer.alloc(1024, 1)) }, 'malformed_response');
  // Non-canonical base64url (stray low bits in the last character).
  const raw = b64u(Buffer.from([1, 2]));
  check({ ...base(), rawId: raw.replace(/.$/, 'J'), id: raw.replace(/.$/, 'J') }, 'malformed_response');
});

test('base64url fields reject padding, standard base64, and oversize values', () => {
  const expectedChallenge = challenge();
  const response = authenticationResponse({ credential: es256, challenge: expectedChallenge });
  for (const [field, value] of [
    ['signature', `${response.response.signature}=`],
    ['signature', `+${response.response.signature.slice(1)}`],
    ['clientDataJSON', ''],
    ['authenticatorData', 'a'.repeat(30000)],
    ['signature', 5],
  ]) {
    const mutated = { ...response, response: { ...response.response, [field]: value } };
    assert.throws(authenticate(es256, { expectedChallenge, response: mutated }), code('malformed_response'), field);
  }
});

test('the user handle must match the credential owner when present, and can be required', () => {
  const owner = Buffer.from('usr_owner_000001', 'utf8');
  assert.throws(authenticate(es256, { userHandle: Buffer.from('usr_someone_else', 'utf8'), expectedUserHandle: owner }), code('user_handle_mismatch'));
  assert.throws(authenticate(es256, { expectedUserHandle: owner, requireUserHandle: true }), code('user_handle_mismatch'));
  assert.doesNotThrow(authenticate(es256, { expectedUserHandle: owner }));
  assert.doesNotThrow(authenticate(es256, { userHandle: owner, expectedUserHandle: owner, requireUserHandle: true }));
});

test('verifier arguments are checked', () => {
  const response = registrationResponse({ credential: es256, challenge: challenge() });
  assert.throws(() => verifyRegistration({ response, expectedChallenge: Buffer.alloc(8), rpId: RP_ID, origins }), code('invalid_argument'));
  assert.throws(() => verifyRegistration({ response, expectedChallenge: 'abc', rpId: RP_ID, origins }), code('invalid_argument'));
  assert.throws(() => verifyRegistration({ response, expectedChallenge: challenge(), rpId: '', origins }), code('invalid_argument'));
  assert.throws(() => verifyRegistration({ response, expectedChallenge: challenge(), rpId: RP_ID, origins: [] }), code('invalid_argument'));
  assert.throws(() => verifyRegistration(), code('invalid_argument'));
  assert.throws(authenticate(es256, { stored: { ...storedCredential(es256), counter: -1 } }), code('invalid_argument'));
  assert.throws(authenticate(es256, { stored: { ...storedCredential(es256), publicKey: 'pQ==' } }), code('invalid_public_key'));
});

test('a stored public key that no longer parses fails sign-in', () => {
  const stored = { ...storedCredential(es256), publicKey: b64u(cbor(new Map([[1, 2], [3, -7]]))) };
  assert.throws(authenticate(es256, { stored }), code('invalid_public_key'));
});

test('error messages never echo request data', () => {
  const marker = 'MARKER-should-not-appear';
  try {
    register(es256, { origin: `https://${marker}.example` })();
    assert.fail('expected a throw');
  } catch (error) {
    assert.ok(error instanceof WebAuthnError);
    assert.doesNotMatch(error.message, /MARKER/);
  }
});

// ---------------------------------------------------------------------------
// Relying-party config

test('normalizeRelyingParty accepts matching rp ids and origins only', () => {
  assert.deepEqual(normalizeRelyingParty({ rpId: 'example.com', origins: ['https://example.com', 'https://cockpit.example.com:8443'] }).origins,
    ['https://example.com', 'https://cockpit.example.com:8443']);
  assert.equal(normalizeRelyingParty({ rpId: 'localhost', origins: ['http://localhost:18765'] }).rpId, 'localhost');
  const bad = [
    { rpId: 'Example.com', origins: ['https://example.com'] },
    { rpId: 'example.com.', origins: ['https://example.com'] },
    { rpId: '127.0.0.1', origins: ['https://127.0.0.1'] },
    { rpId: 'https://example.com', origins: ['https://example.com'] },
    { rpId: 'example.com:443', origins: ['https://example.com'] },
    { rpId: 'example.com', origins: ['http://example.com'] },
    { rpId: 'example.com', origins: ['https://evil.example'] },
    { rpId: 'example.com', origins: ['https://notexample.com'] },
    { rpId: 'example.com', origins: ['https://example.com/path'] },
    { rpId: 'example.com', origins: ['https://example.com/'] },
    { rpId: 'example.com', origins: [] },
    { rpId: 'localhost', origins: ['http://127.0.0.1:18765'] },
  ];
  for (const input of bad) assert.throws(() => normalizeRelyingParty(input), code('invalid_argument'), JSON.stringify(input));
});
