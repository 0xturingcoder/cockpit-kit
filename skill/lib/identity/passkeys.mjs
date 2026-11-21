// Passkey ceremonies: glue between the challenge store (challenges.mjs), the
// pure verifier (webauthn.mjs), and the identity store (store.mjs).
// Transport-free; the HTTP routes live in passkey-http.mjs. See
// docs/passkeys.md.
//
// - Registration adds a passkey for the owner. If the store does not exist
//   yet, the first registration creates the owner. Members get passkeys
//   through invites (#10), not here.
// - Sign-in is usernameless (discoverable credentials, empty
//   allowCredentials), so nothing a client sends before signing names a user.
//   A successful sign-in returns the verified user id; the caller decides
//   what session to grant.
// - An unknown credential id is verified against a dummy key of the
//   response's algorithm family before it is refused, so a failed sign-in
//   costs about the same whether or not the id is registered.
import crypto from 'node:crypto';
import { createChallengeStore } from './challenges.mjs';
import { IdentityStoreError, findCredential } from './store.mjs';
import { COSE_ALG_ES256, COSE_ALG_RS256, WebAuthnError, normalizeRelyingParty, verifyAuthentication, verifyRegistration } from './webauthn.mjs';

export const DEFAULT_RP_NAME = 'Cockpit';

const CREDENTIAL_ID_RE = /^[A-Za-z0-9_-]{1,1364}$/;

export class PasskeyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PasskeyError';
    this.code = code;
  }
}

const loadOrNull = (store) => {
  try {
    return store.load();
  } catch (error) {
    if (error instanceof IdentityStoreError && error.code === 'missing') return null;
    throw error;
  }
};

// Dummy public keys for the unknown-credential path, generated once per
// process. The private halves are discarded, so nothing can sign for them.
const coseEc2 = ({ x, y }) => Buffer.concat([
  Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), Buffer.from(x, 'base64url'),
  Buffer.from([0x22, 0x58, 0x20]), Buffer.from(y, 'base64url'),
]);
const coseRsa2048 = ({ n, e }) => Buffer.concat([
  Buffer.from([0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20, 0x59, 0x01, 0x00]), Buffer.from(n, 'base64url'),
  Buffer.from([0x21, 0x43]), Buffer.from(e, 'base64url'),
]);
const publicJwk = (pair) => pair.publicKey.export({ format: 'jwk' });

let dummyKeys = null;
const getDummyKeys = () => {
  dummyKeys ??= Object.freeze({
    es256: coseEc2(publicJwk(crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }))).toString('base64url'),
    rs256: coseRsa2048(publicJwk(crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }))).toString('base64url'),
  });
  return dummyKeys;
};

// ES256 DER signatures are at most 72 bytes (96 base64url characters); RSA
// signatures are at least 256 bytes. Anything else picks ES256.
const RSA_SIGNATURE_MIN_CHARS = 342;
const dummyKeyFor = (response) => {
  const signature = response?.response?.signature;
  const keys = getDummyKeys();
  return typeof signature === 'string' && signature.length >= RSA_SIGNATURE_MIN_CHARS ? keys.rs256 : keys.es256;
};

const checkDisplayName = (value) => {
  if (typeof value !== 'string' || value.trim() === '' || value.length > 128) {
    throw new IdentityStoreError('display_name is required to create the owner (1 to 128 characters)', 'invalid_argument');
  }
  return value;
};

/**
 * @param {object} options
 * @param {import('./store.mjs').IdentityStore} options.store Identity store.
 * @param {string} options.rpId Relying-party id (config).
 * @param {string[] | (() => string[])} options.origins Allowed origins (config), or a function for a port bound later.
 * @param {string} [options.rpName] Shown by the browser during registration.
 * @param {ReturnType<typeof createChallengeStore>} [options.challenges]
 * @param {typeof verifyAuthentication} [options.verify] Sign-in verifier (tests).
 */
export const createPasskeyCeremonies = ({
  store, rpId, origins, rpName = DEFAULT_RP_NAME, challenges = createChallengeStore(), verify = verifyAuthentication,
}) => {
  if (!store) throw new TypeError('createPasskeyCeremonies requires an identity store');
  const relyingParty = () => normalizeRelyingParty({ rpId, origins: typeof origins === 'function' ? origins() : origins });
  relyingParty(); // fail at startup on bad config
  getDummyKeys(); // generate before the first sign-in, not during it

  const startRegistration = ({ displayName } = {}) => {
    const data = loadOrNull(store);
    const owner = data?.users.find((user) => user.role === 'owner');
    const binding = owner
      ? { userId: owner.id, displayName: owner.display_name, createOwner: false }
      : { userId: `usr_${crypto.randomBytes(16).toString('base64url')}`, displayName: checkDisplayName(displayName), createOwner: true };
    const issued = challenges.issue({ ceremony: 'registration', binding });
    return {
      challengeId: issued.id,
      publicKey: {
        rp: { id: rpId, name: rpName },
        user: { id: Buffer.from(binding.userId, 'utf8').toString('base64url'), name: binding.displayName, displayName: binding.displayName },
        challenge: issued.challenge.toString('base64url'),
        pubKeyCredParams: [{ type: 'public-key', alg: COSE_ALG_ES256 }, { type: 'public-key', alg: COSE_ALG_RS256 }],
        timeout: challenges.ttlMs,
        attestation: 'none',
        authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
        excludeCredentials: (owner?.credentials ?? []).map((credential) => ({ type: 'public-key', id: credential.id, transports: credential.transports })),
      },
    };
  };

  const finishRegistration = ({ challengeId, response, label = '' } = {}) => {
    const { challenge, binding } = challenges.consume(challengeId, 'registration');
    const rp = relyingParty();
    const verified = verifyRegistration({ response, expectedChallenge: challenge, rpId: rp.rpId, origins: [...rp.origins] });
    const input = {
      id: verified.credentialId,
      publicKey: verified.publicKey,
      counter: verified.counter,
      transports: verified.transports,
      label,
    };
    // The owner and their first passkey are written together, so a failed
    // first registration leaves no store behind.
    const credential = binding.createOwner
      ? store.createUserWithCredential({ id: binding.userId, displayName: binding.displayName, role: 'owner', credential: input }).credential
      : store.addCredential(binding.userId, input);
    return Object.freeze({ userId: binding.userId, credentialId: credential.id, createdOwner: binding.createOwner });
  };

  const startAuthentication = () => {
    const issued = challenges.issue({ ceremony: 'authentication' });
    return {
      challengeId: issued.id,
      publicKey: {
        challenge: issued.challenge.toString('base64url'),
        rpId,
        timeout: challenges.ttlMs,
        userVerification: 'required',
        allowCredentials: [],
      },
    };
  };

  /**
   * Verify a sign-in and record the new signature counter. Every failure
   * throws; callers that face the network must map all of them to one
   * generic error so a response never shows whether a credential or user
   * exists.
   *
   * @returns {Readonly<{ userId: string, role: 'owner' | 'member', credentialId: string, credentialLabel: string, counter: number }>}
   */
  const finishAuthentication = ({ challengeId, response } = {}) => {
    const { challenge } = challenges.consume(challengeId, 'authentication');
    const rawId = response?.rawId;
    if (typeof rawId !== 'string' || !CREDENTIAL_ID_RE.test(rawId)) throw new WebAuthnError('malformed_response');
    const data = loadOrNull(store);
    const hit = data && findCredential(data, rawId);
    const rp = relyingParty();
    const check = { response, expectedChallenge: challenge, rpId: rp.rpId, origins: [...rp.origins], requireUserHandle: true };
    if (!hit) {
      // Do the same parsing and signature work as a known credential, then
      // refuse regardless of the outcome.
      try {
        verify({ ...check, credential: { id: rawId, publicKey: dummyKeyFor(response), counter: 0 } });
      } catch (error) {
        if (!(error instanceof WebAuthnError)) throw error;
      }
      throw new PasskeyError('unknown_credential', 'No such credential.');
    }
    const verified = verify({
      ...check,
      credential: { id: hit.credential.id, publicKey: hit.credential.public_key, counter: hit.credential.counter },
      expectedUserHandle: Buffer.from(hit.user.id, 'utf8'),
    });
    // Checked after verification so a disabled user costs the same as any other.
    if (hit.user.disabled) throw new PasskeyError('user_disabled', 'The user is disabled.');
    // The store re-checks the counter under its lock, so two concurrent
    // sign-ins with the same counter cannot both succeed. 0 -> 0 (an
    // authenticator without a counter) needs no write.
    if (verified.counter !== 0 || hit.credential.counter !== 0) store.updateCounter(hit.credential.id, verified.counter);
    return Object.freeze({
      userId: hit.user.id, role: hit.user.role, credentialId: hit.credential.id, credentialLabel: hit.credential.label, counter: verified.counter,
    });
  };

  return Object.freeze({ startRegistration, finishRegistration, startAuthentication, finishAuthentication });
};
