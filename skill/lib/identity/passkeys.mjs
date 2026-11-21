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
 */
export const createPasskeyCeremonies = ({ store, rpId, origins, rpName = DEFAULT_RP_NAME, challenges = createChallengeStore() }) => {
  if (!store) throw new TypeError('createPasskeyCeremonies requires an identity store');
  const relyingParty = () => normalizeRelyingParty({ rpId, origins: typeof origins === 'function' ? origins() : origins });
  relyingParty(); // fail at startup on bad config

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
    if (binding.createOwner) store.createUser({ id: binding.userId, displayName: binding.displayName, role: 'owner' });
    const credential = store.addCredential(binding.userId, {
      id: verified.credentialId,
      publicKey: verified.publicKey,
      counter: verified.counter,
      transports: verified.transports,
      label,
    });
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
   * @returns {Readonly<{ userId: string, role: 'owner' | 'member', credentialId: string, counter: number }>}
   */
  const finishAuthentication = ({ challengeId, response } = {}) => {
    const { challenge } = challenges.consume(challengeId, 'authentication');
    const rawId = response?.rawId;
    if (typeof rawId !== 'string' || !CREDENTIAL_ID_RE.test(rawId)) throw new WebAuthnError('malformed_response');
    const data = loadOrNull(store);
    const hit = data && findCredential(data, rawId);
    if (!hit) throw new PasskeyError('unknown_credential', 'No such credential.');
    if (hit.user.disabled) throw new PasskeyError('user_disabled', 'The user is disabled.');
    const rp = relyingParty();
    const verified = verifyAuthentication({
      response,
      expectedChallenge: challenge,
      rpId: rp.rpId,
      origins: [...rp.origins],
      credential: { id: hit.credential.id, publicKey: hit.credential.public_key, counter: hit.credential.counter },
      expectedUserHandle: Buffer.from(hit.user.id, 'utf8'),
      requireUserHandle: true,
    });
    // The store re-checks the counter under its lock, so two concurrent
    // sign-ins with the same counter cannot both succeed. 0 -> 0 (an
    // authenticator without a counter) needs no write.
    if (verified.counter !== 0 || hit.credential.counter !== 0) store.updateCounter(hit.credential.id, verified.counter);
    return Object.freeze({ userId: hit.user.id, role: hit.user.role, credentialId: hit.credential.id, counter: verified.counter });
  };

  return Object.freeze({ startRegistration, finishRegistration, startAuthentication, finishAuthentication });
};
