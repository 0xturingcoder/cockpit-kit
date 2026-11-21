// WebAuthn (passkey) response verification on node:crypto, deliberately
// narrow. Design and API: docs/passkeys.md.
//
// Supported subset:
// - Attestation: only fmt "none" with an empty attStmt. Every other format is
//   rejected ("unsupported_attestation"); there are no trust chains.
// - Algorithms: ES256 (COSE -7, EC2 on P-256) and RS256 (COSE -257,
//   RSASSA-PKCS1-v1_5 with SHA-256, 2048- to 4096-bit modulus, e = 65537).
// - User presence and user verification are always required.
//
// The verifier is pure: the caller supplies the expected challenge bytes, the
// relying-party id, the allowed origins, and (for sign-in) the stored
// credential. Challenge issuing and single use live in challenges.mjs, and
// persistence in store.mjs, so recorded browser fixtures can be verified with
// an injected challenge.
//
// Every failure throws WebAuthnError with a stable `code` and a fixed
// message. Messages never include request data.
import crypto from 'node:crypto';
import { CborError, decodeCbor, decodeCborPrefix } from './cbor.mjs';

export const COSE_ALG_ES256 = -7;
export const COSE_ALG_RS256 = -257;
export const SUPPORTED_ALGORITHMS = Object.freeze([COSE_ALG_ES256, COSE_ALG_RS256]);

export const LIMITS = Object.freeze({
  clientDataJSON: 4096,
  attestationObject: 16 * 1024,
  authenticatorData: 16 * 1024,
  signature: 1024,
  credentialId: 1023,
  publicKey: 2048,
  userHandle: 64,
  minChallenge: 16,
  transports: 8,
});

const MESSAGES = Object.freeze({
  malformed_response: 'The credential response is malformed.',
  invalid_client_data: 'clientDataJSON is not valid.',
  wrong_type: 'clientDataJSON has the wrong ceremony type.',
  challenge_mismatch: 'The challenge does not match.',
  origin_mismatch: 'The origin is not allowed.',
  cross_origin: 'Cross-origin ceremonies are not supported.',
  invalid_authenticator_data: 'authenticatorData is not valid.',
  rp_id_mismatch: 'The relying party id does not match.',
  user_not_present: 'The authenticator did not report user presence.',
  user_not_verified: 'The authenticator did not report user verification.',
  invalid_attestation: 'The attestation object is not valid.',
  unsupported_attestation: 'Only "none" attestation is supported.',
  unsupported_algorithm: 'Only ES256 (-7) and RS256 (-257) credentials are supported.',
  invalid_public_key: 'The credential public key is not valid.',
  credential_id_mismatch: 'The credential id does not match.',
  user_handle_mismatch: 'The user handle does not match.',
  bad_signature: 'The signature is not valid.',
  counter_regression: 'The signature counter did not increase.',
  invalid_argument: 'Invalid verifier argument.',
});

export const WEBAUTHN_ERROR_CODES = Object.freeze(Object.keys(MESSAGES));

export class WebAuthnError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? 'WebAuthn verification failed.');
    this.name = 'WebAuthnError';
    this.code = code;
  }
}

const fail = (code) => { throw new WebAuthnError(code); };

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

// Constant-time equality for byte buffers. Unequal lengths compare false
// without touching the contents (lengths here are public).
const bytesEqual = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);

const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

// Strict, canonical, unpadded base64url to bytes.
const fromBase64url = (value, { code = 'malformed_response', min = 1, max }) => {
  if (typeof value !== 'string' || !BASE64URL_RE.test(value)) fail(code);
  // 4 base64 characters per 3 bytes; reject before decoding anything huge.
  if (value.length > Math.ceil((max * 4) / 3)) fail(code);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || bytes.length < min || bytes.length > max) fail(code);
  return bytes;
};

const toBuffer = (value, code) => {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  return fail(code);
};

// ---------------------------------------------------------------------------
// Relying-party configuration (from config, never from request headers).

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Validate a relying-party id and its allowed origins.
 *
 * The rp id is a lowercase DNS name (no scheme, port, path, trailing dot, or
 * IP address). Each origin must be exactly scheme://host[:port], use https
 * (http only for the host "localhost"), and have a host equal to the rp id
 * or a subdomain of it.
 *
 * @param {{ rpId: string, origins: string[] }} input
 * @returns {{ rpId: string, origins: readonly string[] }}
 */
export const normalizeRelyingParty = ({ rpId, origins }) => {
  const bad = () => fail('invalid_argument');
  if (typeof rpId !== 'string' || rpId.length === 0 || rpId.length > 253) bad();
  const labels = rpId.split('.');
  if (!labels.every((label) => LABEL_RE.test(label))) bad();
  if (/^[0-9]+$/.test(labels[labels.length - 1])) bad(); // IPv4-looking
  if (!Array.isArray(origins) || origins.length === 0) bad();
  const normalized = origins.map((origin) => {
    let url;
    try {
      url = new URL(origin);
    } catch {
      return bad();
    }
    if (url.origin !== origin) bad(); // exact scheme://host[:port], nothing else
    const host = url.hostname;
    if (url.protocol === 'http:' ? host !== 'localhost' : url.protocol !== 'https:') bad();
    if (host !== rpId && !host.endsWith(`.${rpId}`)) bad();
    return origin;
  });
  return Object.freeze({ rpId, origins: Object.freeze([...new Set(normalized)]) });
};

// ---------------------------------------------------------------------------
// clientDataJSON

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Parse and check clientDataJSON. Order follows the spec: type, challenge,
 * origin, then the cross-origin fields. Unknown members are ignored, as the
 * spec requires (browsers add some on purpose).
 */
export const checkClientData = (bytes, { type, expectedChallenge, origins }) => {
  if (bytes.length === 0 || bytes.length > LIMITS.clientDataJSON) fail('invalid_client_data');
  let data;
  try {
    data = JSON.parse(utf8.decode(bytes));
  } catch {
    fail('invalid_client_data');
  }
  if (!isPlainObject(data)) fail('invalid_client_data');
  if (typeof data.type !== 'string' || typeof data.challenge !== 'string' || typeof data.origin !== 'string') fail('invalid_client_data');
  if (data.type !== type) fail('wrong_type');
  const expected = Buffer.from(expectedChallenge.toString('base64url'), 'utf8');
  if (!bytesEqual(Buffer.from(data.challenge, 'utf8'), expected)) fail('challenge_mismatch');
  if (!origins.includes(data.origin)) fail('origin_mismatch');
  if (data.crossOrigin !== undefined && typeof data.crossOrigin !== 'boolean') fail('invalid_client_data');
  // Only top-level, same-origin ceremonies are supported, so a topOrigin
  // (only present for cross-origin iframes) is rejected too.
  if (data.crossOrigin === true || data.topOrigin !== undefined) fail('cross_origin');
  return Object.freeze({ type: data.type, origin: data.origin });
};

// ---------------------------------------------------------------------------
// authenticatorData

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

/**
 * Parse authenticatorData with exact length accounting:
 * rpIdHash(32) | flags(1) | signCount(4) [| aaguid(16) | credIdLen(2) |
 * credentialId | COSE_Key] [| extensions map], and nothing after that.
 *
 * Extensions (ED) must be a well-formed CBOR map with text keys; their
 * contents are ignored because the kit requests no authenticator extensions.
 * RFU flag bits are ignored, as the spec requires.
 *
 * @param {Uint8Array} input
 */
export const parseAuthenticatorData = (input) => {
  const bytes = toBuffer(input, 'invalid_authenticator_data');
  if (bytes.length < 37 || bytes.length > LIMITS.authenticatorData) fail('invalid_authenticator_data');
  const flagsByte = bytes[32];
  const flags = Object.freeze({
    userPresent: (flagsByte & FLAG_UP) !== 0,
    userVerified: (flagsByte & FLAG_UV) !== 0,
    backupEligible: (flagsByte & FLAG_BE) !== 0,
    backedUp: (flagsByte & FLAG_BS) !== 0,
    attestedCredentialData: (flagsByte & FLAG_AT) !== 0,
    extensionData: (flagsByte & FLAG_ED) !== 0,
  });
  // A credential cannot be backed up without being backup eligible.
  if (flags.backedUp && !flags.backupEligible) fail('invalid_authenticator_data');
  const result = {
    rpIdHash: bytes.subarray(0, 32),
    flags,
    signCount: bytes.readUInt32BE(33),
    attested: null,
  };
  let offset = 37;
  try {
    if (flags.attestedCredentialData) {
      if (bytes.length < offset + 18) fail('invalid_authenticator_data');
      const aaguid = bytes.subarray(offset, offset + 16);
      const idLength = bytes.readUInt16BE(offset + 16);
      offset += 18;
      if (idLength < 1 || idLength > LIMITS.credentialId || idLength > bytes.length - offset) fail('invalid_authenticator_data');
      const credentialId = bytes.subarray(offset, offset + idLength);
      offset += idLength;
      if (offset >= bytes.length) fail('invalid_authenticator_data');
      const key = decodeCborPrefix(bytes.subarray(offset), { maxBytes: LIMITS.authenticatorData, maxDepth: 1 });
      if (!(key.value instanceof Map)) fail('invalid_authenticator_data');
      const publicKey = bytes.subarray(offset, offset + key.length);
      offset += key.length;
      result.attested = Object.freeze({ aaguid, credentialId, publicKey });
    }
    if (flags.extensionData) {
      if (offset >= bytes.length) fail('invalid_authenticator_data');
      const extensions = decodeCborPrefix(bytes.subarray(offset), { maxBytes: LIMITS.authenticatorData, maxDepth: 4 });
      if (!(extensions.value instanceof Map) || [...extensions.value.keys()].some((key) => typeof key !== 'string')) fail('invalid_authenticator_data');
      offset += extensions.length;
    }
  } catch (error) {
    if (error instanceof CborError) fail('invalid_authenticator_data');
    throw error;
  }
  if (offset !== bytes.length) fail('invalid_authenticator_data');
  return Object.freeze(result);
};

// ---------------------------------------------------------------------------
// COSE keys

// P-256 domain parameters (SEC 2 / FIPS 186-4).
const P256 = Object.freeze({
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
});

const toBigInt = (bytes) => (bytes.length === 0 ? 0n : BigInt(`0x${bytes.toString('hex')}`));

const mod = (value, m) => ((value % m) + m) % m;

const onP256 = (x, y) => {
  const { p, b } = P256;
  if (x >= p || y >= p) return false;
  return mod(y * y, p) === mod(x * x * x - 3n * x + b, p);
};

const sameKeys = (map, labels) => map.size === labels.length && labels.every((label) => map.has(label));

const RSA_E_65537 = Buffer.from([0x01, 0x00, 0x01]);

const parseEc2 = (map) => {
  if (!sameKeys(map, [1, 3, -1, -2, -3])) fail('invalid_public_key');
  const crv = map.get(-1);
  const x = map.get(-2);
  const y = map.get(-3);
  if (crv !== 1 || !Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== 32 || y.length !== 32) fail('invalid_public_key');
  if (!onP256(toBigInt(x), toBigInt(y))) fail('invalid_public_key');
  return { jwk: { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') }, type: 'ec', size: 32 };
};

const parseRsa = (map) => {
  if (!sameKeys(map, [1, 3, -1, -2])) fail('invalid_public_key');
  const n = map.get(-1);
  const e = map.get(-2);
  if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e)) fail('invalid_public_key');
  // Unsigned big-endian without leading zero bytes (RFC 8230).
  if (n.length === 0 || n[0] === 0) fail('invalid_public_key');
  const bits = (n.length - 1) * 8 + (32 - Math.clz32(n[0]));
  if (bits < 2048 || bits > 4096 || (n[n.length - 1] & 1) === 0) fail('invalid_public_key');
  if (!e.equals(RSA_E_65537)) fail('invalid_public_key');
  return { jwk: { kty: 'RSA', n: n.toString('base64url'), e: e.toString('base64url') }, type: 'rsa', size: n.length };
};

/**
 * Decode and import a COSE_Key. Accepts exactly the labels each key type
 * needs (EC2: 1, 3, -1, -2, -3; RSA: 1, 3, -1, -2) and nothing else, so a
 * key carrying private parameters or extra fields is refused.
 *
 * @param {Uint8Array} input COSE_Key bytes.
 * @returns {{ alg: number, key: crypto.KeyObject, signatureSize: number }}
 */
export const parseCoseKey = (input) => {
  const bytes = toBuffer(input, 'invalid_public_key');
  if (bytes.length > LIMITS.publicKey) fail('invalid_public_key');
  let map;
  try {
    map = decodeCbor(bytes, { maxBytes: LIMITS.publicKey, maxDepth: 1 });
  } catch (error) {
    if (error instanceof CborError) fail('invalid_public_key');
    throw error;
  }
  if (!(map instanceof Map)) fail('invalid_public_key');
  const kty = map.get(1);
  const alg = map.get(3);
  if (!Number.isInteger(kty) || !Number.isInteger(alg)) fail('invalid_public_key');
  if (!SUPPORTED_ALGORITHMS.includes(alg)) fail('unsupported_algorithm');
  // kty must agree with alg: EC2 (2) for ES256, RSA (3) for RS256.
  if ((alg === COSE_ALG_ES256 && kty !== 2) || (alg === COSE_ALG_RS256 && kty !== 3)) fail('invalid_public_key');
  const parsed = alg === COSE_ALG_ES256 ? parseEc2(map) : parseRsa(map);
  let key;
  try {
    key = crypto.createPublicKey({ key: parsed.jwk, format: 'jwk' });
  } catch {
    fail('invalid_public_key');
  }
  if (key.asymmetricKeyType !== parsed.type) fail('invalid_public_key');
  if (parsed.type === 'ec' && key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') fail('invalid_public_key');
  return Object.freeze({ alg, key, signatureSize: parsed.size });
};

// ---------------------------------------------------------------------------
// Signatures

const readDerInteger = (sig, offset) => {
  if (offset + 2 > sig.length || sig[offset] !== 0x02) fail('bad_signature');
  const length = sig[offset + 1];
  const start = offset + 2;
  if (length < 1 || length > 33 || start + length > sig.length) fail('bad_signature');
  const value = sig.subarray(start, start + length);
  if (value[0] & 0x80) fail('bad_signature'); // negative
  if (length > 1 && value[0] === 0 && (value[1] & 0x80) === 0) fail('bad_signature'); // non-minimal
  const unsigned = value[0] === 0 && length > 1 ? value.subarray(1) : value;
  if (unsigned.length > 32) fail('bad_signature');
  const integer = toBigInt(unsigned);
  if (integer < 1n || integer >= P256.n) fail('bad_signature');
  return { bytes: unsigned, offset: start + length };
};

/**
 * Strict DER ECDSA-Sig-Value (SEQUENCE of two INTEGERs) to raw r || s.
 * Only the shortest definite-length encoding is accepted: short-form lengths,
 * no leading zero bytes beyond the one a sign bit needs, no negative values,
 * 1 <= r, s < n, and no bytes after the sequence.
 *
 * High-S signatures are accepted. WebAuthn does not require low-S, and
 * authenticators produce either; malleability does not matter here because a
 * signature is never used as an identifier and every challenge is single use.
 *
 * @param {Uint8Array} input
 * @returns {Buffer} 64 bytes, r then s.
 */
export const derToRawEcdsa = (input) => {
  const sig = toBuffer(input, 'bad_signature');
  if (sig.length < 8 || sig.length > 72) fail('bad_signature');
  if (sig[0] !== 0x30 || sig[1] !== sig.length - 2) fail('bad_signature');
  const r = readDerInteger(sig, 2);
  const s = readDerInteger(sig, r.offset);
  if (s.offset !== sig.length) fail('bad_signature');
  const raw = Buffer.alloc(64);
  r.bytes.copy(raw, 32 - r.bytes.length);
  s.bytes.copy(raw, 64 - s.bytes.length);
  return raw;
};

const verifySignature = ({ alg, key, signatureSize }, data, signature) => {
  let ok = false;
  try {
    if (alg === COSE_ALG_ES256) {
      ok = crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, derToRawEcdsa(signature));
    } else {
      if (signature.length !== signatureSize) fail('bad_signature');
      ok = crypto.verify('sha256', data, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
    }
  } catch (error) {
    if (error instanceof WebAuthnError) throw error;
    fail('bad_signature');
  }
  if (!ok) fail('bad_signature');
};

// ---------------------------------------------------------------------------
// Ceremonies

const checkArguments = ({ expectedChallenge, rpId, origins }) => {
  if (!(expectedChallenge instanceof Uint8Array) || expectedChallenge.length < LIMITS.minChallenge) fail('invalid_argument');
  if (typeof rpId !== 'string' || rpId === '' || !Array.isArray(origins) || origins.length === 0) fail('invalid_argument');
  return toBuffer(expectedChallenge, 'invalid_argument');
};

// Common PublicKeyCredential JSON checks: type, and id === rawId (canonical
// base64url of the same bytes).
const readCredentialEnvelope = (response) => {
  if (!isPlainObject(response) || response.type !== 'public-key' || !isPlainObject(response.response)) fail('malformed_response');
  const rawId = fromBase64url(response.rawId, { max: LIMITS.credentialId });
  if (response.id !== response.rawId) fail('credential_id_mismatch');
  return { rawId, inner: response.response };
};

const checkAuthenticatorFlags = (authData, rpId) => {
  if (!bytesEqual(Buffer.from(authData.rpIdHash), sha256(rpId))) fail('rp_id_mismatch');
  if (!authData.flags.userPresent) fail('user_not_present');
  if (!authData.flags.userVerified) fail('user_not_verified');
};

const TRANSPORT_RE = /^[a-z][a-z0-9-]{0,31}$/;

// Transports are browser hints: keep well-formed distinct names, drop the rest.
const cleanTransports = (value) => (Array.isArray(value)
  ? [...new Set(value.filter((item) => typeof item === 'string' && TRANSPORT_RE.test(item)))].slice(0, LIMITS.transports)
  : []);

const formatAaguid = (bytes) => {
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

/**
 * Verify a registration (navigator.credentials.create) response.
 *
 * @param {object} input
 * @param {object} input.response PublicKeyCredential JSON (base64url fields).
 * @param {Uint8Array} input.expectedChallenge Challenge bytes the server issued.
 * @param {string} input.rpId Relying-party id from config.
 * @param {string[]} input.origins Allowed origins from config (exact match).
 * @returns {Readonly<{ credentialId: string, publicKey: string, counter: number, alg: number,
 *   aaguid: string, transports: string[], backupEligible: boolean, backedUp: boolean }>}
 */
export const verifyRegistration = ({ response, expectedChallenge, rpId, origins } = {}) => {
  const challenge = checkArguments({ expectedChallenge, rpId, origins });
  const { rawId, inner } = readCredentialEnvelope(response);
  const clientDataJSON = fromBase64url(inner.clientDataJSON, { max: LIMITS.clientDataJSON });
  const attestationObject = fromBase64url(inner.attestationObject, { max: LIMITS.attestationObject });

  checkClientData(clientDataJSON, { type: 'webauthn.create', expectedChallenge: challenge, origins });

  let attestation;
  try {
    attestation = decodeCbor(attestationObject, { maxBytes: LIMITS.attestationObject });
  } catch (error) {
    if (error instanceof CborError) fail('invalid_attestation');
    throw error;
  }
  if (!(attestation instanceof Map) || !sameKeys(attestation, ['fmt', 'attStmt', 'authData'])) fail('invalid_attestation');
  const fmt = attestation.get('fmt');
  const attStmt = attestation.get('attStmt');
  const authDataBytes = attestation.get('authData');
  if (typeof fmt !== 'string' || !(attStmt instanceof Map) || !Buffer.isBuffer(authDataBytes)) fail('invalid_attestation');
  if (fmt !== 'none' || attStmt.size !== 0) fail('unsupported_attestation');

  const authData = parseAuthenticatorData(authDataBytes);
  checkAuthenticatorFlags(authData, rpId);
  if (!authData.attested) fail('invalid_authenticator_data');
  if (!authData.attested.credentialId.equals(rawId)) fail('credential_id_mismatch');
  const { alg } = parseCoseKey(authData.attested.publicKey);

  return Object.freeze({
    credentialId: rawId.toString('base64url'),
    publicKey: Buffer.from(authData.attested.publicKey).toString('base64url'),
    counter: authData.signCount,
    alg,
    aaguid: formatAaguid(Buffer.from(authData.attested.aaguid)),
    transports: cleanTransports(inner.transports),
    backupEligible: authData.flags.backupEligible,
    backedUp: authData.flags.backedUp,
  });
};

/**
 * Verify a sign-in (navigator.credentials.get) response against a stored
 * credential, including the signature counter rule: if either the stored or
 * the new counter is non-zero, the new one must be strictly greater.
 *
 * @param {object} input
 * @param {object} input.response PublicKeyCredential JSON (base64url fields).
 * @param {Uint8Array} input.expectedChallenge Challenge bytes the server issued.
 * @param {string} input.rpId Relying-party id from config.
 * @param {string[]} input.origins Allowed origins from config (exact match).
 * @param {{ id: string, publicKey: string, counter: number }} input.credential Stored credential (base64url id and COSE key).
 * @param {Uint8Array} [input.expectedUserHandle] The credential owner's user handle.
 * @param {boolean} [input.requireUserHandle=false] Fail when the response carries no user handle.
 * @returns {Readonly<{ credentialId: string, counter: number, userHandle: string | null, backedUp: boolean }>}
 */
export const verifyAuthentication = ({
  response, expectedChallenge, rpId, origins, credential, expectedUserHandle, requireUserHandle = false,
} = {}) => {
  const challenge = checkArguments({ expectedChallenge, rpId, origins });
  if (!isPlainObject(credential) || typeof credential.id !== 'string' || typeof credential.publicKey !== 'string'
    || !Number.isInteger(credential.counter) || credential.counter < 0 || credential.counter > 0xffffffff) fail('invalid_argument');
  if (expectedUserHandle !== undefined && !(expectedUserHandle instanceof Uint8Array)) fail('invalid_argument');

  const { rawId, inner } = readCredentialEnvelope(response);
  if (response.rawId !== credential.id) fail('credential_id_mismatch');
  const clientDataJSON = fromBase64url(inner.clientDataJSON, { max: LIMITS.clientDataJSON });
  const authDataBytes = fromBase64url(inner.authenticatorData, { max: LIMITS.authenticatorData });
  const signature = fromBase64url(inner.signature, { max: LIMITS.signature });
  const hasUserHandle = inner.userHandle !== undefined && inner.userHandle !== null && inner.userHandle !== '';
  const userHandle = hasUserHandle ? fromBase64url(inner.userHandle, { max: LIMITS.userHandle }) : null;

  checkClientData(clientDataJSON, { type: 'webauthn.get', expectedChallenge: challenge, origins });

  const authData = parseAuthenticatorData(authDataBytes);
  checkAuthenticatorFlags(authData, rpId);
  // Assertions never carry attested credential data.
  if (authData.attested) fail('invalid_authenticator_data');

  if (userHandle && expectedUserHandle && !userHandle.equals(toBuffer(expectedUserHandle, 'invalid_argument'))) fail('user_handle_mismatch');
  if (!userHandle && requireUserHandle) fail('user_handle_mismatch');

  const key = parseCoseKey(fromBase64url(credential.publicKey, { code: 'invalid_public_key', max: LIMITS.publicKey }));
  verifySignature(key, Buffer.concat([authDataBytes, sha256(clientDataJSON)]), signature);

  const stored = credential.counter;
  const next = authData.signCount;
  if ((stored !== 0 || next !== 0) && next <= stored) fail('counter_regression');

  return Object.freeze({
    credentialId: rawId.toString('base64url'),
    counter: next,
    userHandle: userHandle ? userHandle.toString('base64url') : null,
    backedUp: authData.flags.backedUp,
  });
};
