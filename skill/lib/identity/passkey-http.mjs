// Same-origin JSON routes for passkey registration, invite enrollment,
// sign-in, recovery-token sign-in, and step-up under /auth/passkey. The
// transport adapter (serve.mjs) supplies session authorization for
// registration and step-up, the recovery token check and audit log, and
// decides what a successful sign-in grants. This module enforces exact
// Origin, JSON bodies, body limits, rate limits, and the error mapping in
// docs/passkeys.md, docs/invites.md, and docs/recovery.md.
import { ChallengeError } from './challenges.mjs';
import { InviteStoreError } from './invites.mjs';
import { PasskeyError } from './passkeys.mjs';
import { RecoveryStoreError } from './recovery.mjs';
import { IdentityStoreError, isSafeLabel } from './store.mjs';
import { WebAuthnError } from './webauthn.mjs';

export const PASSKEY_PREFIX = '/auth/passkey';
const BODY_LIMIT = 64 * 1024;
const BODY_TIMEOUT_MS = 10000;
// Token buckets, shared by all clients: a loopback server behind a proxy
// cannot tell clients apart without trusting forwarded headers. Sign-in,
// registration, invite enrollment, and step-up have separate buckets, so
// anonymous sign-in or invite traffic cannot rate-limit the owner out of
// adding a passkey, or each other. Recovery-token attempts (sign-in and
// first-owner setup) share one small bucket, and every attempt takes a token.
const RATES = Object.freeze({
  options: { perMinute: 30, burst: 10 },
  failures: { perMinute: 10, burst: 10 },
  recovery: { perMinute: 5, burst: 5 },
});
const CEREMONY_BUCKETS = Object.freeze(['login', 'register', 'invite', 'step-up']);
// Recovery sessions last at most this long, however long --session-lifetime is.
export const RECOVERY_SESSION_MAX_MS = 12 * 60 * 60 * 1000;

export const PASSKEY_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const privateHeaders = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': PASSKEY_CSP,
  Vary: 'Cookie',
};

export class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const sendJson = (res, status, body, extra = {}) => {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { ...privateHeaders, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text), ...extra });
  res.end(text);
};

export const readBody = (req) => new Promise((resolve, reject) => {
  let size = 0;
  const chunks = [];
  const timer = setTimeout(() => {
    reject(new HttpError(408, 'body_timeout', 'Request body took too long.'));
    req.destroy();
  }, BODY_TIMEOUT_MS);
  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > BODY_LIMIT) {
      clearTimeout(timer);
      reject(new HttpError(413, 'body_too_large', 'Request body is too large.'));
      req.removeAllListeners('data');
      req.resume();
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => {
    clearTimeout(timer);
    resolve(Buffer.concat(chunks));
  });
  req.on('error', (error) => {
    clearTimeout(timer);
    reject(error);
  });
});

export const parseJson = (buffer) => {
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
  } catch {
    throw new HttpError(400, 'invalid_request', 'Body must be a UTF-8 JSON object.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new HttpError(400, 'invalid_request', 'Body must be a UTF-8 JSON object.');
  return value;
};

const createBucket = ({ perMinute, burst }, now) => {
  let tokens = burst;
  let at = now();
  const refill = () => {
    const current = now();
    tokens = Math.min(burst, tokens + ((current - at) / 60000) * perMinute);
    at = current;
  };
  const limited = () => new HttpError(429, 'rate_limited', 'Too many attempts; retry shortly.', {
    'Retry-After': String(Math.max(1, Math.ceil(((1 - tokens) * 60) / perMinute))),
  });
  return {
    // Throw when no token is left, without taking one.
    check: () => {
      refill();
      if (tokens < 1) throw limited();
    },
    take: () => {
      refill();
      if (tokens < 1) throw limited();
      tokens -= 1;
    },
    spend: () => {
      refill();
      tokens = Math.max(0, tokens - 1);
    },
  };
};

const STORE_STATUS = Object.freeze({
  invalid_argument: [400, 'invalid_argument'],
  duplicate_id: [409, 'credential_exists'],
  owner_required: [409, 'owner_conflict'],
  not_found: [409, 'user_missing'],
  user_disabled: [403, 'user_disabled'],
  store_full: [507, 'store_full'],
  store_busy: [503, 'store_busy'],
});

const STORE_MESSAGES = Object.freeze({
  credential_exists: 'That passkey is already registered.',
  owner_conflict: 'The owner changed during registration; start again.',
  user_missing: 'The user no longer exists; start again.',
  user_disabled: 'The user is disabled.',
  store_full: 'The identity store is full; remove unused passkeys first.',
  store_busy: 'The identity store is busy; retry shortly.',
});

const REGISTRATION_PASSKEY_ERRORS = Object.freeze({
  owner_exists: () => new HttpError(409, 'owner_exists', 'The owner already exists; sign in, then add a passkey from the settings page.'),
  not_owner: () => new HttpError(403, 'forbidden', 'Only the owner can add a passkey here.'),
  wrong_session: () => new HttpError(400, 'wrong_session', 'This registration was started by another session or sign-in; start again.'),
});

// Registration is owner-only, so specific reasons help and leak nothing.
const registrationError = (error) => {
  if (error instanceof WebAuthnError || error instanceof ChallengeError) return new HttpError(400, error.code, error.message);
  if (error instanceof PasskeyError && REGISTRATION_PASSKEY_ERRORS[error.code]) return REGISTRATION_PASSKEY_ERRORS[error.code]();
  if (error instanceof IdentityStoreError && STORE_STATUS[error.code]) {
    const [status, code] = STORE_STATUS[error.code];
    // invalid_argument messages name the field and rule, never the value.
    const message = code === 'invalid_argument' ? error.message : STORE_MESSAGES[code];
    return new HttpError(status, code, message, code === 'store_busy' ? { 'Retry-After': '2' } : {});
  }
  return error;
};

// Sign-in: every verification failure looks the same, so a response never
// shows whether a credential or user exists, or why it was refused.
const SIGN_IN_FAILED = () => new HttpError(401, 'sign_in_failed', 'Sign-in failed.');
const SIGN_IN_REASONS = new Set(['missing', 'not_found', 'user_disabled', 'counter_regression']);

const signInError = (error) => {
  if (error instanceof WebAuthnError || error instanceof ChallengeError || error instanceof PasskeyError) return SIGN_IN_FAILED();
  if (error instanceof IdentityStoreError) {
    if (SIGN_IN_REASONS.has(error.code)) return SIGN_IN_FAILED();
    if (error.code === 'store_busy') return new HttpError(503, 'store_busy', STORE_MESSAGES.store_busy, { 'Retry-After': '2' });
  }
  return error;
};

// Invite enrollment: a spent, expired, revoked, unknown, malformed, or
// mismatched token, and every challenge or verifier failure, look the same,
// so a response never shows whether an invite exists or why it was refused.
// Only retryable server conditions differ.
const INVITE_INVALID = () => new HttpError(400, 'invite_invalid', 'This invite link is not valid. Ask the owner for a new one.');
const INVITE_REASONS = new Set(['duplicate_id', 'owner_required', 'not_found', 'invalid_argument', 'invalid_id', 'invalid_role', 'user_disabled']);

const inviteError = (error) => {
  if (error instanceof WebAuthnError || error instanceof ChallengeError || error instanceof PasskeyError) return INVITE_INVALID();
  if (error instanceof IdentityStoreError || error instanceof InviteStoreError) {
    if (error.code === 'store_busy') return new HttpError(503, 'store_busy', 'The store is busy; retry shortly.', { 'Retry-After': '2' });
    if (error.code === 'store_full') return new HttpError(507, 'store_full', 'The identity store is full; ask the owner to remove unused passkeys.');
    if (error instanceof IdentityStoreError && INVITE_REASONS.has(error.code)) return INVITE_INVALID();
  }
  return error;
};

// Step-up: every failure looks the same, like sign-in.
const STEP_UP_FAILED = () => new HttpError(401, 'step_up_failed', 'The passkey check failed; try again.');

const stepUpError = (error) => {
  if (error instanceof WebAuthnError || error instanceof ChallengeError || error instanceof PasskeyError) return STEP_UP_FAILED();
  if (error instanceof IdentityStoreError) {
    if (error.code === 'store_busy') return new HttpError(503, 'store_busy', STORE_MESSAGES.store_busy, { 'Retry-After': '2' });
    if (SIGN_IN_REASONS.has(error.code)) return STEP_UP_FAILED();
  }
  return error;
};

// Recovery token: a wrong, malformed, or missing token all look the same.
const RECOVERY_FAILED = () => new HttpError(401, 'recovery_failed', 'The recovery token is not valid.');

const challengeIssueError = (error) => (error instanceof ChallengeError
  ? new HttpError(503, error.code, error.message, { 'Retry-After': '10' })
  : error);

/**
 * @param {object} options
 * @param {ReturnType<import('./passkeys.mjs').createPasskeyCeremonies>} options.ceremonies
 * @param {() => Iterable<string>} options.allowedOrigins Exact origins (config).
 * @param {(req) => { userId: string, sessionId: string } | null} [options.authorizeRegistration]
 *   The live owner session allowed to add a passkey (CSRF and step-up checked), or null when the request has no
 *   session; throws HttpError to refuse (a member session, a bad CSRF token, a stale step-up). With null, only the
 *   first owner can be created, with the recovery token in the body.
 * @param {(req) => { userId: string, sessionId: string }} [options.authorizeStepUp]
 *   The live owner session (CSRF checked) that may step up; throws HttpError to refuse.
 * @param {(session: { userId: string, sessionId: string }) => string} [options.onStepUp]
 *   Records a verified step-up on the session and returns its new step_up_at; throws HttpError to refuse.
 * @param {(result, session: { userId: string, sessionId: string }) => void} [options.onRegistered]
 *   Called after a session added a passkey.
 * @param {{ check: (token: unknown) => boolean, owner: () => { id: string } | null, record: (event: string, result: string) => void }} [options.recovery]
 *   The recovery token check, the current owner, and the audit log. Without it the recovery routes return 404
 *   and the first owner cannot be created.
 * @param {(owner: { userId: string }, context: { origin: string, req: import('node:http').IncomingMessage }) => Record<string, string>} [options.onRecoverySignIn]
 *   Creates the owner's recovery session after a valid recovery token; returns response headers.
 * @param {(result, context: { origin: string, req: import('node:http').IncomingMessage }) => Record<string, string>} options.onSignIn
 *   Called after a verified sign-in with { userId, role, credentialId, credentialLabel, counter }, and after an
 *   invite enrollment with { userId, role, credentialId, credentialLabel, inviteId }; returns extra response
 *   headers (e.g. Set-Cookie) or throws HttpError to refuse. After an enrollment a throw does not undo it: the
 *   response is then 201 with signed_in false.
 * @param {(message: string) => void} [options.log] Receives error codes, never request data.
 * @param {() => number} [options.now] Clock for rate limits (tests).
 */
export const createPasskeyApi = ({
  ceremonies, allowedOrigins, authorizeRegistration = () => null, authorizeStepUp = null, onStepUp = () => null, onRegistered = () => {},
  recovery = null, onRecoverySignIn = null, onSignIn, log = () => {}, now = Date.now,
}) => {
  const buckets = Object.fromEntries(CEREMONY_BUCKETS.map((ceremony) => [ceremony, {
    options: createBucket(RATES.options, now),
    failures: createBucket(RATES.failures, now),
  }]));
  const recoveryBucket = createBucket(RATES.recovery, now);

  const checkRequest = (req) => {
    const origin = req.headers.origin;
    if (!origin || !new Set(allowedOrigins()).has(origin)) throw new HttpError(403, 'origin_denied', 'Origin not allowed.');
    const site = req.headers['sec-fetch-site'];
    if (site && site !== 'same-origin') throw new HttpError(403, 'origin_denied', 'Cross-site request denied.');
    const type = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/json') throw new HttpError(415, 'unsupported_media_type', 'Use application/json.');
    if (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity') throw new HttpError(415, 'unsupported_media_type', 'Compressed bodies are not accepted.');
    return origin;
  };

  // Audit a refused recovery attempt; a failed write is logged, not fatal.
  const auditQuietly = (event, result) => {
    try {
      recovery.record(event, result);
    } catch (error) {
      log(`audit write failed (${error?.code ?? error?.name})`);
    }
  };

  // Every recovery-token attempt takes a token from the shared bucket.
  const takeRecoveryAttempt = (event) => {
    try {
      recoveryBucket.take();
    } catch (error) {
      auditQuietly(event, 'rate_limited');
      log(`passkey rate_limited (${event})`);
      throw error;
    }
  };

  const checkRecoveryToken = (event, token) => {
    if (recovery.check(token)) return;
    auditQuietly(event, 'invalid');
    log(`passkey recovery_failed (${event})`);
    throw RECOVERY_FAILED();
  };

  // Without a session, registration can only create the first owner, and
  // only with the recovery token in the body.
  const requireFirstOwnerToken = (body) => {
    if (!recovery || body.recovery_token === undefined) {
      throw new HttpError(401, 'authentication_required', 'Sign in as the owner (with a passkey or the recovery token) before adding a passkey.');
    }
    takeRecoveryAttempt('first_owner');
    checkRecoveryToken('first_owner', body.recovery_token);
    if (recovery.owner()) {
      auditQuietly('first_owner', 'owner_exists');
      throw REGISTRATION_PASSKEY_ERRORS.owner_exists();
    }
  };

  const requireStepUpSession = (req) => {
    if (!authorizeStepUp) throw new HttpError(404, 'not_found', 'Unknown passkey route.');
    return authorizeStepUp(req);
  };

  // The invite token is checked by the invites store; a missing or malformed
  // one gets the same invite_invalid as any other bad token.
  const inviteToken = (body) => (typeof body.token === 'string' ? body.token : '');

  const verifyFields = (body) => {
    if (typeof body.challenge_id !== 'string' || !body.credential || typeof body.credential !== 'object' || Array.isArray(body.credential)) {
      throw new HttpError(400, 'invalid_request', 'Expected challenge_id and credential.');
    }
    return { challengeId: body.challenge_id, response: body.credential };
  };

  // Run a verification step; failures spend a token from that ceremony's bucket.
  const attempt = (bucket, fn, mapError) => {
    bucket.check();
    try {
      return fn();
    } catch (error) {
      bucket.spend();
      const mapped = mapError(error);
      if (mapped instanceof HttpError) log(`passkey ${mapped.code}${error.code && error.code !== mapped.code ? ` (${error.code})` : ''}`);
      throw mapped;
    }
  };

  const routes = {
    '/invite/options': async (req) => {
      checkRequest(req);
      buckets.invite.options.take();
      const body = parseJson(await readBody(req));
      const options = attempt(buckets.invite.failures, () => {
        try {
          return ceremonies.startInvitation({ token: inviteToken(body) });
        } catch (error) {
          throw challengeIssueError(error);
        }
      }, inviteError);
      return { status: 200, body: { challenge_id: options.challengeId, publicKey: options.publicKey } };
    },
    '/invite/verify': async (req) => {
      const origin = checkRequest(req);
      const body = parseJson(await readBody(req));
      const fields = verifyFields(body);
      const label = body.label === undefined ? '' : body.label;
      if (!isSafeLabel(label)) throw new HttpError(400, 'invalid_request', 'label must be 0 to 64 characters without control or formatting characters.');
      const result = attempt(buckets.invite.failures, () => ceremonies.finishInvitation({ ...fields, token: inviteToken(body), label }), inviteError);
      // The member and passkey exist now. If no session can be created,
      // they can still sign in from the login page.
      let headers;
      try {
        headers = onSignIn(result, { origin, req });
      } catch (error) {
        log(`passkey invite session_not_created${error?.code ? ` (${error.code})` : ''}`);
        return { status: 201, body: { enrolled: true, signed_in: false, user_id: result.userId } };
      }
      return { status: 201, body: { enrolled: true, signed_in: true, user_id: result.userId }, headers };
    },
    // A live owner session with a fresh step-up adds a passkey to the owner;
    // without a session, the recovery token creates the first owner. A live
    // session always wins, so a member session with a token is refused.
    '/register/options': async (req) => {
      checkRequest(req);
      const signedIn = authorizeRegistration(req);
      buckets.register.options.take();
      const body = parseJson(await readBody(req));
      if (!signedIn) requireFirstOwnerToken(body);
      try {
        const options = signedIn
          ? ceremonies.startRegistration({ userId: signedIn.userId, sessionId: signedIn.sessionId })
          : ceremonies.startRegistration({ displayName: body.display_name, firstOwner: true });
        return { status: 200, body: { challenge_id: options.challengeId, publicKey: options.publicKey } };
      } catch (error) {
        throw registrationError(challengeIssueError(error));
      }
    },
    // Authorized after the body is read, so the step-up (or recovery
    // enrollment window) is checked right before the passkey is written.
    '/register/verify': async (req) => {
      checkRequest(req);
      const body = parseJson(await readBody(req));
      const signedIn = authorizeRegistration(req);
      const fields = verifyFields(body);
      if (!signedIn) requireFirstOwnerToken(body);
      const label = body.label === undefined ? '' : body.label;
      const bound = signedIn ? { sessionId: signedIn.sessionId } : { firstOwner: true };
      const result = attempt(buckets.register.failures, () => ceremonies.finishRegistration({ ...fields, label, ...bound }), registrationError);
      if (signedIn) onRegistered(result, signedIn);
      else auditQuietly('first_owner', 'ok');
      return { status: 201, body: { registered: true, user_id: result.userId, credential_id: result.credentialId, created_owner: result.createdOwner } };
    },
    // Owner-only: the server's recovery token signs the owner in with a
    // recovery session. Every attempt is rate limited and audited; a
    // successful one is refused if it cannot be audited.
    '/recovery/sign-in': async (req) => {
      const origin = checkRequest(req);
      if (!recovery || !onRecoverySignIn) throw new HttpError(404, 'not_found', 'Unknown passkey route.');
      takeRecoveryAttempt('token_sign_in');
      const body = parseJson(await readBody(req));
      checkRecoveryToken('token_sign_in', body.token);
      const owner = recovery.owner();
      if (!owner) {
        auditQuietly('token_sign_in', 'no_owner');
        throw new HttpError(409, 'no_owner', 'There is no owner yet; create the owner with the recovery token first.');
      }
      try {
        recovery.record('token_sign_in', 'ok');
      } catch (error) {
        log(`audit write failed (${error?.code ?? error?.name})`);
        throw new HttpError(503, 'audit_unavailable', 'The recovery sign-in could not be recorded; retry shortly.', { 'Retry-After': '5' });
      }
      const headers = onRecoverySignIn({ userId: owner.id }, { origin, req });
      return { status: 200, body: { signed_in: true, user_id: owner.id, recovery: true }, headers };
    },
    '/step-up/options': async (req) => {
      checkRequest(req);
      const signedIn = requireStepUpSession(req);
      buckets['step-up'].options.take();
      parseJson(await readBody(req));
      const options = attempt(buckets['step-up'].failures, () => {
        try {
          return ceremonies.startStepUp(signedIn);
        } catch (error) {
          throw challengeIssueError(error);
        }
      }, (error) => (error instanceof HttpError ? error : stepUpError(error)));
      return { status: 200, body: { challenge_id: options.challengeId, publicKey: options.publicKey } };
    },
    '/step-up/verify': async (req) => {
      checkRequest(req);
      const body = parseJson(await readBody(req));
      const signedIn = requireStepUpSession(req);
      const fields = verifyFields(body);
      attempt(buckets['step-up'].failures, () => ceremonies.finishStepUp({ ...fields, ...signedIn }), stepUpError);
      const stepUpAt = onStepUp(signedIn);
      return { status: 200, body: { stepped_up: true, step_up_at: stepUpAt } };
    },
    '/login/options': async (req) => {
      checkRequest(req);
      buckets.login.options.take();
      parseJson(await readBody(req));
      let options;
      try {
        options = ceremonies.startAuthentication();
      } catch (error) {
        throw challengeIssueError(error);
      }
      return { status: 200, body: { challenge_id: options.challengeId, publicKey: options.publicKey } };
    },
    '/login/verify': async (req) => {
      const origin = checkRequest(req);
      const fields = verifyFields(parseJson(await readBody(req)));
      const result = attempt(buckets.login.failures, () => ceremonies.finishAuthentication(fields), signInError);
      const headers = onSignIn(result, { origin, req });
      return { status: 200, body: { signed_in: true, user_id: result.userId }, headers };
    },
  };

  const sendError = (res, error) => {
    if (error instanceof HttpError) return sendJson(res, error.status, { error: { code: error.code, message: error.message } }, error.extra);
    log(`passkey internal_error${error?.code ? ` (${error.code})` : ''}`);
    if (error instanceof IdentityStoreError || error instanceof InviteStoreError || error instanceof RecoveryStoreError) {
      return sendJson(res, 503, { error: { code: 'identity_unavailable', message: 'The identity store is unavailable.' } }, { 'Retry-After': '5' });
    }
    return sendJson(res, 500, { error: { code: 'internal_error', message: 'Internal error.' } });
  };

  // Returns true when the request was a passkey API request (handled).
  const handle = (req, res) => {
    let url;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      return false;
    }
    if (url.pathname !== PASSKEY_PREFIX && !url.pathname.startsWith(`${PASSKEY_PREFIX}/`)) return false;
    (async () => {
      if (url.search) throw new HttpError(400, 'invalid_request', 'Query strings are not accepted.');
      const route = routes[url.pathname.slice(PASSKEY_PREFIX.length)];
      if (!route) throw new HttpError(404, 'not_found', 'Unknown passkey route.');
      if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
      const { status, body, headers = {} } = await route(req);
      sendJson(res, status, body, headers);
    })().catch((error) => {
      if (!res.headersSent) sendError(res, error);
      else res.destroy();
    });
    return true;
  };

  return Object.freeze({ handle });
};
