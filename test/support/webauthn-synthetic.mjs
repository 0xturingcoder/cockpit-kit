// Synthetic WebAuthn authenticator for tests. Everything here is generated at
// runtime with node:crypto: key pairs, credential ids, COSE keys,
// authenticatorData, attestation objects, clientDataJSON, and signatures.
// Nothing is recorded from a real browser or authenticator; recorded
// fixtures live in test/fixtures/webauthn/ and are tested separately.
import crypto from 'node:crypto';

export const RP_ID = 'example.com';
export const ORIGIN = 'https://example.com';

// ---------------------------------------------------------------------------
// Minimal CBOR encoder (test-only). Supports what the tests need, plus raw
// byte injection for malformed inputs.

export class RawCbor {
  constructor(bytes) { this.bytes = Buffer.from(bytes); }
}

const head = (major, value) => {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value < 0x100) return Buffer.from([(major << 5) | 24, value]);
  if (value < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(value, 1);
    return b;
  }
  if (value < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(value, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = (major << 5) | 27;
  b.writeBigUInt64BE(BigInt(value), 1);
  return b;
};

export const cbor = (value) => {
  if (value instanceof RawCbor) return value.bytes;
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) {
    return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  }
  throw new TypeError('unsupported test CBOR value');
};

// ---------------------------------------------------------------------------
// Credentials

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

export const coseMapFor = (publicKey, alg) => {
  const jwk = publicKey.export({ format: 'jwk' });
  if (alg === -7) {
    return new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]);
  }
  return new Map([[1, 3], [3, -257], [-1, Buffer.from(jwk.n, 'base64url')], [-2, Buffer.from(jwk.e, 'base64url')]]);
};

/**
 * Generate a synthetic credential (ES256 by default, or RS256).
 * @param {{ alg?: -7 | -257, rsaBits?: number, idLength?: number }} [options]
 */
export const makeCredential = ({ alg = -7, rsaBits = 2048, idLength = 32 } = {}) => {
  const { privateKey, publicKey } = alg === -7
    ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    : crypto.generateKeyPairSync('rsa', { modulusLength: rsaBits });
  const coseMap = coseMapFor(publicKey, alg);
  return { alg, privateKey, publicKey, coseMap, cose: cbor(coseMap), rawId: crypto.randomBytes(idLength) };
};

export const FLAGS = Object.freeze({ UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 });

/**
 * Build authenticatorData bytes.
 */
export const authData = ({
  rpId = RP_ID, flags = FLAGS.UP | FLAGS.UV, signCount = 0, attested = null, extensions = null, rpIdHash = null, trailing = null,
} = {}) => {
  const count = Buffer.alloc(4);
  count.writeUInt32BE(signCount);
  const parts = [rpIdHash ?? crypto.createHash('sha256').update(rpId).digest(), Buffer.from([flags]), count];
  if (attested) {
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(attested.idLength ?? attested.credentialId.length);
    parts.push(attested.aaguid ?? Buffer.alloc(16), idLength, attested.credentialId, attested.cose);
  }
  if (extensions) parts.push(extensions);
  if (trailing) parts.push(trailing);
  return Buffer.concat(parts);
};

export const clientData = ({ type, challenge, origin = ORIGIN, extra = {} }) => Buffer.from(JSON.stringify({
  type, challenge: b64u(challenge), origin, crossOrigin: false, ...extra,
}), 'utf8');

/**
 * A registration response (PublicKeyCredential JSON) from `credential`.
 */
export const registrationResponse = ({
  credential, challenge, rpId = RP_ID, origin = ORIGIN, flags = FLAGS.UP | FLAGS.UV | FLAGS.AT, signCount = 0,
  fmt = 'none', attStmt = new Map(), clientDataBytes = null, authDataBytes = null, attestation = null, transports = ['internal'],
  clientDataExtra = {}, type = 'webauthn.create',
}) => {
  const data = authDataBytes ?? authData({ rpId, flags, signCount, attested: { credentialId: credential.rawId, cose: credential.cose } });
  const attestationObject = attestation ?? cbor(new Map([['fmt', fmt], ['attStmt', attStmt], ['authData', data]]));
  const id = b64u(credential.rawId);
  return {
    id,
    rawId: id,
    type: 'public-key',
    response: {
      clientDataJSON: b64u(clientDataBytes ?? clientData({ type, challenge, origin, extra: clientDataExtra })),
      attestationObject: b64u(attestationObject),
      transports,
    },
    authenticatorAttachment: 'platform',
    clientExtensionResults: {},
  };
};

export const sign = (credential, data) => (credential.alg === -7
  ? crypto.sign('sha256', data, { key: credential.privateKey, dsaEncoding: 'der' })
  : crypto.sign('sha256', data, { key: credential.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }));

/**
 * An authentication response (PublicKeyCredential JSON) signed by `credential`.
 */
export const authenticationResponse = ({
  credential, challenge, rpId = RP_ID, origin = ORIGIN, flags = FLAGS.UP | FLAGS.UV, signCount = 1, userHandle = null,
  clientDataBytes = null, authDataBytes = null, type = 'webauthn.get', clientDataExtra = {}, signature = null,
}) => {
  const data = authDataBytes ?? authData({ rpId, flags, signCount });
  const client = clientDataBytes ?? clientData({ type, challenge, origin, extra: clientDataExtra });
  const sig = signature ?? sign(credential, Buffer.concat([data, crypto.createHash('sha256').update(client).digest()]));
  const id = b64u(credential.rawId);
  return {
    id,
    rawId: id,
    type: 'public-key',
    response: {
      clientDataJSON: b64u(client),
      authenticatorData: b64u(data),
      signature: b64u(sig),
      userHandle: userHandle === null ? null : b64u(userHandle),
    },
    authenticatorAttachment: 'platform',
    clientExtensionResults: {},
  };
};

/** Stored-credential shape the verifier expects for sign-in. */
export const storedCredential = (credential, counter = 0) => ({ id: b64u(credential.rawId), publicKey: b64u(credential.cose), counter });
