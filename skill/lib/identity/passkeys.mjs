// Passkey ceremonies: glue between the challenge store (challenges.mjs), the
// pure verifier (webauthn.mjs), and the identity store (store.mjs).
// Transport-free; the HTTP routes live in passkey-http.mjs. See
// docs/passkeys.md.
//
// - Registration adds a passkey for the owner. If the store does not exist
//   yet, the first registration creates the owner. Members get passkeys
//   through invites (invitation, below), not here.
// - Invitation enrolls a new member from a one-time invite (invites.mjs):
//   the challenge is bound to the invite and its pre-generated user, the
//   invite is spent only after the response verifies, and the member and
//   their first passkey are then written together.
// - Sign-in is usernameless (discoverable credentials, empty
//   allowCredentials), so nothing a client sends before signing names a user.
//   A successful sign-in returns the verified user id; the caller decides
//   what session to grant.
// - An unknown credential id is verified against a dummy key of the
//   response's algorithm family before it is refused, so a failed sign-in
//   costs about the same whether or not the id is registered.
// - Step-up is a fresh user-verified assertion from one of the owner's
//   passkeys by an already signed-in owner session (docs/recovery.md). The
//   challenge is bound to that session and user, so it cannot be finished by
//   another session; the caller records the step-up on the session.
import crypto from 'node:crypto';
import { createChallengeStore } from './challenges.mjs';
import { IdentityStoreError, findCredential, isSafeLabel } from './store.mjs';
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

// Identity store failures after an invite was spent that leave no user and
// that the invitee can retry; the invite is put back for them.
const RETRYABLE_ENROLLMENT = new Set(['store_busy', 'store_full']);

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
 * @param {import('./invites.mjs').InviteStore} [options.invites] Invites store; without it, invitations are refused.
 */
export const createPasskeyCeremonies = ({
  store, rpId, origins, rpName = DEFAULT_RP_NAME, challenges = createChallengeStore(), verify = verifyAuthentication, invites = null,
}) => {
  if (!store) throw new TypeError('createPasskeyCeremonies requires an identity store');
  const relyingParty = () => normalizeRelyingParty({ rpId, origins: typeof origins === 'function' ? origins() : origins });
  relyingParty(); // fail at startup on bad config
  getDummyKeys(); // generate before the first sign-in, not during it

  const creationOptions = (binding, issued, exclude) => ({
    rp: { id: rpId, name: rpName },
    user: { id: Buffer.from(binding.userId, 'utf8').toString('base64url'), name: binding.displayName, displayName: binding.displayName },
    challenge: issued.challenge.toString('base64url'),
    pubKeyCredParams: [{ type: 'public-key', alg: COSE_ALG_ES256 }, { type: 'public-key', alg: COSE_ALG_RS256 }],
    timeout: challenges.ttlMs,
    attestation: 'none',
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    excludeCredentials: exclude.map((credential) => ({ type: 'public-key', id: credential.id, transports: credential.transports })),
  });

  /**
   * Start a registration. With `sessionId` (and the owner's `userId`), it adds
   * a passkey to the owner and the challenge is bound to that session. With
   * `firstOwner`, it creates the owner and refuses if one exists. With
   * neither, it does whichever applies (library use; the HTTP routes always
   * pass one).
   */
  const startRegistration = ({ displayName, userId, sessionId, firstOwner = false } = {}) => {
    const data = loadOrNull(store);
    const owner = data?.users.find((user) => user.role === 'owner');
    if (sessionId !== undefined && (!owner || owner.id !== userId)) throw new PasskeyError('not_owner', 'Only the owner can add a passkey.');
    if (firstOwner && owner) throw new PasskeyError('owner_exists', 'The owner already exists.');
    const binding = owner
      ? { userId: owner.id, displayName: owner.display_name, createOwner: false, ...(sessionId !== undefined ? { sessionId } : {}) }
      : { userId: `usr_${crypto.randomBytes(16).toString('base64url')}`, displayName: checkDisplayName(displayName), createOwner: true };
    const issued = challenges.issue({ ceremony: 'registration', binding });
    return { challengeId: issued.id, publicKey: creationOptions(binding, issued, owner?.credentials ?? []) };
  };

  // Verify a registration response against a consumed challenge and shape
  // it for the identity store.
  const verifiedCredential = (response, challenge, label) => {
    const rp = relyingParty();
    const verified = verifyRegistration({ response, expectedChallenge: challenge, rpId: rp.rpId, origins: [...rp.origins] });
    return {
      id: verified.credentialId,
      publicKey: verified.publicKey,
      counter: verified.counter,
      transports: verified.transports,
      label,
    };
  };

  /**
   * Finish a registration. With `sessionId`, the challenge must have been
   * issued to that session; with `firstOwner`, it must have been issued to
   * create the owner. So a challenge cannot move between sessions, or between
   * a session and the recovery-token setup.
   */
  const finishRegistration = ({ challengeId, response, label = '', sessionId, firstOwner = false } = {}) => {
    const { challenge, binding } = challenges.consume(challengeId, 'registration');
    const wrongBinding = sessionId !== undefined ? binding.sessionId !== sessionId : firstOwner && (!binding.createOwner || binding.sessionId !== undefined);
    if (wrongBinding) throw new PasskeyError('wrong_session', 'The registration was started by another session.');
    const input = verifiedCredential(response, challenge, label);
    // The owner and their first passkey are written together, so a failed
    // first registration leaves no store behind.
    const credential = binding.createOwner
      ? store.createUserWithCredential({ id: binding.userId, displayName: binding.displayName, role: 'owner', credential: input }).credential
      : store.addCredential(binding.userId, input);
    return Object.freeze({ userId: binding.userId, credentialId: credential.id, createdOwner: binding.createOwner });
  };

  const inviteInvalid = () => new PasskeyError('invite_invalid', 'The invite is not valid.');

  const requireInvites = () => {
    if (!invites) throw new PasskeyError('invites_disabled', 'Invites are not enabled.');
    return invites;
  };

  /**
   * Start enrolling the member an invite was created for. The client sends
   * only the invite token; the user id, name, and role come from the invite.
   * An unknown, spent, revoked, expired, or malformed token throws
   * PasskeyError "invite_invalid".
   */
  const startInvitation = ({ token } = {}) => {
    const invite = requireInvites().find(token);
    if (!invite) throw inviteInvalid();
    const binding = { inviteId: invite.id, userId: invite.user_id, displayName: invite.display_name };
    const issued = challenges.issue({ ceremony: 'invitation', binding });
    return { challengeId: issued.id, publicKey: creationOptions(binding, issued, []) };
  };

  /**
   * Finish an invitation: verify the response, claim the invite, create
   * the member with this passkey in one identity store write, then delete
   * the invite.
   *
   * The token must hash to the invite the challenge was issued for, so a
   * challenge from one invite cannot be finished with another invite's
   * token. The invite is claimed under its lock, so concurrent or replayed
   * finishes cannot both get it, and the pre-generated user id makes the
   * identity write single-winner as well. A failed verification leaves the
   * invite pending. If the identity write fails with a retryable error
   * (store_busy, store_full) no user exists, so the claim is cleared, unless
   * the owner revoked the invite meanwhile; any other failure leaves it
   * claimed until the claim lease runs out and it is pruned.
   *
   * @returns {Readonly<{ userId: string, role: 'member', credentialId: string, credentialLabel: string, inviteId: string }>}
   */
  const finishInvitation = ({ token, challengeId, response, label = '' } = {}) => {
    const pending = requireInvites();
    if (!isSafeLabel(label)) throw new PasskeyError('invalid_label', 'The label is not valid.');
    const { challenge, binding } = challenges.consume(challengeId, 'invitation');
    const input = verifiedCredential(response, challenge, label);
    const invite = pending.spend(token, binding.inviteId);
    if (!invite) throw inviteInvalid();
    let created;
    try {
      created = store.createUserWithCredential({ id: invite.user_id, displayName: invite.display_name, role: 'member', credential: input });
    } catch (error) {
      if (error instanceof IdentityStoreError && RETRYABLE_ENROLLMENT.has(error.code)) {
        try {
          pending.restore(token, invite.id);
        } catch {
          // The invite stays claimed until it is pruned; the owner can create a new one.
        }
      }
      throw error;
    }
    try {
      pending.complete(token, invite.id);
    } catch {
      // The member exists. The claim hides the invite until it is pruned.
    }
    return Object.freeze({
      userId: created.user.id, role: created.user.role, credentialId: created.credential.id, credentialLabel: created.credential.label, inviteId: invite.id,
    });
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

  const ownerOf = (data, userId) => {
    const owner = data?.users.find((user) => user.role === 'owner');
    if (!owner || owner.id !== userId || owner.disabled) throw new PasskeyError('not_owner', 'Only the owner can step up.');
    return owner;
  };

  /**
   * Start a step-up for the owner's session `sessionId`. The options list the
   * owner's passkeys and require user verification.
   */
  const startStepUp = ({ userId, sessionId } = {}) => {
    if (typeof sessionId !== 'string' || sessionId === '') throw new PasskeyError('session_required', 'A session is required.');
    const owner = ownerOf(loadOrNull(store), userId);
    if (owner.credentials.length === 0) throw new PasskeyError('no_passkey', 'The owner has no passkey.');
    const issued = challenges.issue({ ceremony: 'step-up', binding: { userId, sessionId } });
    return {
      challengeId: issued.id,
      publicKey: {
        challenge: issued.challenge.toString('base64url'),
        rpId,
        timeout: challenges.ttlMs,
        userVerification: 'required',
        allowCredentials: owner.credentials.map((credential) => ({ type: 'public-key', id: credential.id, transports: credential.transports })),
      },
    };
  };

  /**
   * Finish a step-up: the challenge must have been issued to this session and
   * user, and the assertion must come from one of the owner's passkeys with
   * user verification. Stores the new signature counter. Every failure
   * throws; network-facing callers map them all to one error.
   *
   * @returns {Readonly<{ userId: string, credentialId: string, counter: number }>}
   */
  const finishStepUp = ({ challengeId, response, userId, sessionId } = {}) => {
    const { challenge, binding } = challenges.consume(challengeId, 'step-up');
    if (binding.sessionId !== sessionId || binding.userId !== userId) throw new PasskeyError('wrong_session', 'The step-up was started by another session.');
    const rawId = response?.rawId;
    if (typeof rawId !== 'string' || !CREDENTIAL_ID_RE.test(rawId)) throw new WebAuthnError('malformed_response');
    const owner = ownerOf(loadOrNull(store), userId);
    const credential = owner.credentials.find((item) => item.id === rawId);
    if (!credential) throw new PasskeyError('unknown_credential', 'No such credential.');
    const rp = relyingParty();
    const verified = verify({
      response,
      expectedChallenge: challenge,
      rpId: rp.rpId,
      origins: [...rp.origins],
      credential: { id: credential.id, publicKey: credential.public_key, counter: credential.counter },
      expectedUserHandle: Buffer.from(owner.id, 'utf8'),
    });
    if (verified.counter !== 0 || credential.counter !== 0) store.updateCounter(credential.id, verified.counter);
    return Object.freeze({ userId: owner.id, credentialId: credential.id, counter: verified.counter });
  };

  return Object.freeze({
    startRegistration, finishRegistration, startInvitation, finishInvitation, startAuthentication, finishAuthentication, startStepUp, finishStepUp,
  });
};
