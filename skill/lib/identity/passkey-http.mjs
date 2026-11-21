// Same-origin JSON routes for passkey registration and sign-in under
// /auth/passkey. The transport adapter (serve.mjs) supplies operator
// authentication for registration and decides what a successful sign-in
// grants. This module enforces exact Origin, JSON bodies, body limits, rate
// limits, and the error mapping in docs/passkeys.md.
import { ChallengeError } from './challenges.mjs';
import { PasskeyError } from './passkeys.mjs';
import { IdentityStoreError } from './store.mjs';
import { WebAuthnError } from './webauthn.mjs';

export const PASSKEY_PREFIX = '/auth/passkey';
const BODY_LIMIT = 64 * 1024;
const BODY_TIMEOUT_MS = 10000;
// Token buckets, shared by all clients: a loopback server behind a proxy
// cannot tell clients apart without trusting forwarded headers. Sign-in and
// registration have separate buckets, so anonymous sign-in traffic cannot
// rate-limit the operator out of adding a passkey.
const RATES = Object.freeze({
  options: { perMinute: 30, burst: 10 },
  failures: { perMinute: 10, burst: 10 },
});
const CEREMONY_BUCKETS = Object.freeze(['login', 'register']);

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

const sendJson = (res, status, body, extra = {}) => {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { ...privateHeaders, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text), ...extra });
  res.end(text);
};

const readBody = (req) => new Promise((resolve, reject) => {
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

const parseJson = (buffer) => {
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

// Registration is operator-only, so specific reasons help and leak nothing.
const registrationError = (error) => {
  if (error instanceof WebAuthnError || error instanceof ChallengeError) return new HttpError(400, error.code, error.message);
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

const challengeIssueError = (error) => (error instanceof ChallengeError
  ? new HttpError(503, error.code, error.message, { 'Retry-After': '10' })
  : error);

/**
 * @param {object} options
 * @param {ReturnType<import('./passkeys.mjs').createPasskeyCeremonies>} options.ceremonies
 * @param {() => Iterable<string>} options.allowedOrigins Exact origins (config).
 * @param {(req) => boolean} options.isOperator True when the request carries operator auth (registration).
 * @param {(result, context: { origin: string }) => Record<string, string>} options.onSignIn
 *   Called after a verified sign-in with { userId, role, credentialId, counter }; returns
 *   extra response headers (e.g. Set-Cookie) or throws HttpError to refuse.
 * @param {(message: string) => void} [options.log] Receives error codes, never request data.
 * @param {() => number} [options.now] Clock for rate limits (tests).
 */
export const createPasskeyApi = ({ ceremonies, allowedOrigins, isOperator, onSignIn, log = () => {}, now = Date.now }) => {
  const buckets = Object.fromEntries(CEREMONY_BUCKETS.map((ceremony) => [ceremony, {
    options: createBucket(RATES.options, now),
    failures: createBucket(RATES.failures, now),
  }]));

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

  const requireOperator = (req) => {
    if (!isOperator(req)) throw new HttpError(401, 'authentication_required', 'Sign in with the server token before adding a passkey.');
  };

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
    '/register/options': async (req) => {
      checkRequest(req);
      requireOperator(req);
      buckets.register.options.take();
      const body = parseJson(await readBody(req));
      try {
        const options = ceremonies.startRegistration({ displayName: body.display_name });
        return { status: 200, body: { challenge_id: options.challengeId, publicKey: options.publicKey } };
      } catch (error) {
        throw registrationError(challengeIssueError(error));
      }
    },
    '/register/verify': async (req) => {
      checkRequest(req);
      requireOperator(req);
      const body = parseJson(await readBody(req));
      const fields = verifyFields(body);
      const label = body.label === undefined ? '' : body.label;
      const result = attempt(buckets.register.failures, () => ceremonies.finishRegistration({ ...fields, label }), registrationError);
      return { status: 201, body: { registered: true, user_id: result.userId, credential_id: result.credentialId, created_owner: result.createdOwner } };
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
      const headers = onSignIn(result, { origin });
      return { status: 200, body: { signed_in: true, user_id: result.userId }, headers };
    },
  };

  const sendError = (res, error) => {
    if (error instanceof HttpError) return sendJson(res, error.status, { error: { code: error.code, message: error.message } }, error.extra);
    log(`passkey internal_error${error?.code ? ` (${error.code})` : ''}`);
    if (error instanceof IdentityStoreError) {
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
