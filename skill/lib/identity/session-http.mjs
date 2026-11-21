// Per-device session cookies, request authentication, the step-up gate, and
// the account API under /auth/account (list and revoke sessions, owner
// administration of users' sessions and passkeys, invites, and the recovery
// audit log). Transport-free: serve.mjs supplies the stores, the allowed
// origins, and the CSRF derivation. See docs/sessions.md, docs/invites.md,
// and docs/recovery.md.
import crypto from 'node:crypto';
import { INVITE_ID_RE, InviteStoreError } from './invites.mjs';
import { HttpError, parseJson, readBody, sendJson } from './passkey-http.mjs';
import { fileSignature } from './private-file.mjs';
import { SessionStoreError } from './sessions.mjs';
import { IdentityStoreError, findCredential, findUser, isSafeDisplayName } from './store.mjs';

export const SESSION_COOKIE = 'cockpit_session';
// The session cookie name when every passkey origin is https. Browsers accept
// a __Host- cookie only with Secure, Path=/, and no Domain, so it cannot be
// set over plain http or by a sibling subdomain.
export const HOST_SESSION_COOKIE = '__Host-cockpit_session';
// How recently a session must have completed a passkey step-up before it may
// add a passkey, create an invite, or (#13) change delegations.
export const DEFAULT_STEP_UP_WINDOW_MS = 5 * 60 * 1000;
export const MIN_STEP_UP_WINDOW_MS = 60 * 1000;
export const MAX_STEP_UP_WINDOW_MS = 60 * 60 * 1000;
export const ACCOUNT_PREFIX = '/auth/account';
// The invite page. The token goes in the URL fragment, which browsers never
// send to a server or put in a Referer.
export const INVITE_PATH = '/auth/invite/';

/** The invite link for `token` on `origin`. */
export const inviteUrl = (origin, token) => `${origin}${INVITE_PATH}#${token}`;

const SESSION_ID_RE = /^ses_[A-Za-z0-9_-]{22}$/;
const CREDENTIAL_ID_RE = /^[A-Za-z0-9_-]{1,1364}$/;

/**
 * Parse a Cookie header into a Map. Later duplicates do not override the
 * first value.
 *
 * @param {string | undefined} header
 * @returns {Map<string, string>}
 */
export const parseCookies = (header) => {
  const cookies = new Map();
  for (const part of String(header ?? '').split(';')) {
    const at = part.indexOf('=');
    if (at === -1) continue;
    const name = part.slice(0, at).trim();
    if (!cookies.has(name)) cookies.set(name, part.slice(at + 1).trim());
  }
  return cookies;
};

/**
 * The session cookie name for a set of passkey origins: __Host-cockpit_session
 * when every origin is https, else cockpit_session.
 *
 * @param {Iterable<string>} origins
 */
export const sessionCookieName = (origins) => {
  const list = [...origins];
  return list.length > 0 && list.every((origin) => origin.startsWith('https:')) ? HOST_SESSION_COOKIE : SESSION_COOKIE;
};

/**
 * The Set-Cookie value for a new session: HttpOnly, SameSite=Strict, Path=/,
 * Max-Age equal to the session lifetime, and Secure on https (always for a
 * __Host- name).
 */
export const sessionCookie = (token, { maxAgeSeconds, secure, name = SESSION_COOKIE }) => (
  `${name}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}${secure || name.startsWith('__Host-') ? '; Secure' : ''}`
);

/** A Set-Cookie value that deletes cookie `name`. */
export const expiredCookie = (name, { secure }) => `${name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure || name.startsWith('__Host-') ? '; Secure' : ''}`;

/**
 * The step-up gate. Throws 403 step_up_required unless the session completed
 * a passkey step-up (a passkey sign-in counts) within the last `windowMs`.
 * Applies to every session kind. Registration and invite creation use it now;
 * delegation approve and revoke (#13) call it too. A step-up time in the
 * future (a clock that went back, or an edited file) does not count.
 *
 * @param {{ session: { step_up_at: string | null } }} signedIn From createSessionAuth().fromRequest().
 * @param {{ now: number, windowMs: number }} options
 */
export const requireFreshStepUp = (signedIn, { now, windowMs }) => {
  const at = Date.parse(signedIn?.session?.step_up_at ?? '');
  const elapsed = now - at;
  if (!(elapsed >= 0 && elapsed <= windowMs)) throw new HttpError(403, 'step_up_required', 'Confirm with your passkey first.');
};

const BROWSERS = [[/Edg\//, 'Edge'], [/Firefox\//, 'Firefox'], [/Chrome\//, 'Chrome'], [/Safari\//, 'Safari']];
const SYSTEMS = [[/iPhone|iPad/, 'iOS'], [/Android/, 'Android'], [/CrOS/, 'ChromeOS'], [/Macintosh|Mac OS X/, 'macOS'], [/Windows/, 'Windows'], [/Linux/, 'Linux']];

/**
 * Device label for a new session: the passkey's label if it has one, else a
 * coarse "Browser on System" picked from a fixed list (never User-Agent text).
 */
export const deviceLabel = ({ credentialLabel = '', userAgent = '' } = {}) => {
  if (credentialLabel) return credentialLabel;
  const ua = String(userAgent ?? '').slice(0, 512);
  const browser = BROWSERS.find(([re]) => re.test(ua))?.[1];
  const system = SYSTEMS.find(([re]) => re.test(ua))?.[1];
  if (browser && system) return `${browser} on ${system}`;
  return browser ?? system ?? 'Unknown device';
};

/**
 * Authenticate requests by their session cookie.
 *
 * fromRequest(req) returns { session, user } for a live session whose user
 * exists and is not disabled, and whose passkey (if it has one) is still on
 * that user, and null otherwise. A recovery session must belong to the owner
 * and be no older than the current recovery token, so rotating the token ends
 * recovery sessions even if revoking them failed. Store errors fail closed
 * (null) and are logged as a code only.
 *
 * @param {object} options
 * @param {ReturnType<import('./sessions.mjs').openSessionStore>} options.sessions
 * @param {import('./store.mjs').IdentityStore} options.identityStore
 * @param {string} [options.cookieName] The only session cookie name read.
 * @param {() => number | null} [options.recoveryNotBefore] Creation time (ms) of the current recovery token; throws to refuse every recovery session.
 * @param {(message: string) => void} [options.log]
 */
export const createSessionAuth = ({
  sessions, identityStore, cookieName = SESSION_COOKIE, recoveryNotBefore = () => null, log = () => {},
}) => {
  // The identity document, re-read only when the file changes.
  let cache = { signature: undefined, data: null };
  const identity = () => {
    const signature = fileSignature(identityStore.file);
    if (signature !== cache.signature) {
      let data = null;
      if (signature !== null) {
        try {
          data = identityStore.load();
        } catch (error) {
          if (!(error instanceof IdentityStoreError && error.code === 'missing')) throw error;
        }
      }
      cache = { signature, data };
    }
    return cache.data;
  };

  const fromRequest = (req) => {
    const token = parseCookies(req.headers.cookie).get(cookieName);
    if (!token) return null;
    try {
      const session = sessions.validate(token);
      if (!session) return null;
      const data = identity();
      const user = data && findUser(data, session.user_id);
      if (!user || user.disabled) return null;
      // A session ends with its passkey, however the passkey was removed.
      // Sessions created without a passkey (credential_id null) are unaffected.
      if (session.credential_id !== null && !user.credentials.some((credential) => credential.id === session.credential_id)) return null;
      if (session.kind === 'recovery') {
        if (user.role !== 'owner') return null;
        const notBefore = recoveryNotBefore();
        if (notBefore !== null && Date.parse(session.created_at) < notBefore) return null;
      }
      return { session, user };
    } catch (error) {
      log(`session check failed (${error?.code ?? error?.name})`);
      return null;
    }
  };

  return Object.freeze({ fromRequest, identity });
};

const accountView = (session, currentId) => ({ ...session, current: session.id === currentId });

const passkeyView = ({ id, label, created_at: createdAt, transports }) => ({ id, label, created_at: createdAt, transports });

const STORE_ERRORS = Object.freeze({
  store_busy: () => new HttpError(503, 'store_busy', 'The store is busy; retry shortly.', { 'Retry-After': '2' }),
  store_full: () => new HttpError(507, 'store_full', 'The sessions store is full.'),
  last_credential: () => new HttpError(409, 'last_passkey', "The owner's last passkey cannot be removed; add another passkey first."),
  not_found: () => new HttpError(404, 'passkey_not_found', 'No such passkey.'),
  too_many_invites: () => new HttpError(409, 'too_many_invites', 'There are too many pending invites; revoke one first.'),
});

const isStoreError = (error) => error instanceof SessionStoreError || error instanceof IdentityStoreError || error instanceof InviteStoreError;

const storeError = (error) => {
  if (isStoreError(error) && STORE_ERRORS[error.code]) return STORE_ERRORS[error.code]();
  return error;
};

const safeEqual = (a, b) => {
  const left = Buffer.from(String(a ?? ''));
  const right = Buffer.from(String(b ?? ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
};

/**
 * @param {object} options
 * @param {ReturnType<typeof createSessionAuth>} options.auth
 * @param {ReturnType<import('./sessions.mjs').openSessionStore>} options.sessions
 * @param {import('./store.mjs').IdentityStore} options.identityStore
 * @param {() => Iterable<string>} options.allowedOrigins Exact origins (config).
 * @param {(principal: string, sessionId: string) => string} options.csrfToken Per-session CSRF token.
 * @param {(secure: boolean) => string[]} options.signOutCookies Set-Cookie values that sign this browser out.
 * @param {import('./invites.mjs').InviteStore} [options.invites] Invites store; without it the invite routes return 404.
 * @param {(message: string) => void} [options.log]
 */
export const createAccountApi = ({ auth, sessions, identityStore, allowedOrigins, csrfToken, signOutCookies, invites = null, log = () => {} }) => {
  const checkPost = (req) => {
    const origin = req.headers.origin;
    if (!origin || !new Set(allowedOrigins()).has(origin)) throw new HttpError(403, 'origin_denied', 'Origin not allowed.');
    const site = req.headers['sec-fetch-site'];
    if (site && site !== 'same-origin') throw new HttpError(403, 'origin_denied', 'Cross-site request denied.');
    const type = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/json') throw new HttpError(415, 'unsupported_media_type', 'Use application/json.');
    if (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity') throw new HttpError(415, 'unsupported_media_type', 'Compressed bodies are not accepted.');
    return origin;
  };

  const checkGet = (req) => {
    const site = req.headers['sec-fetch-site'];
    if (site === 'cross-site' || site === 'same-site') throw new HttpError(403, 'origin_denied', 'Cross-site request denied.');
  };

  const requireSession = (req) => {
    const signedIn = auth.fromRequest(req);
    if (!signedIn) throw new HttpError(401, 'session_required', 'Sign in with a passkey first.');
    return signedIn;
  };

  const requireCsrf = (req, { session, user }) => {
    if (!safeEqual(req.headers['x-cockpit-csrf'], csrfToken(user.id, session.id))) throw new HttpError(403, 'csrf_invalid', 'Missing or invalid CSRF token.');
  };

  const requireOwner = ({ user }) => {
    if (user.role !== 'owner') throw new HttpError(403, 'forbidden', 'Only the owner can do this.');
  };

  const signOutHeaders = (origin) => ({ 'Set-Cookie': signOutCookies(origin.startsWith('https:')) });

  const mutation = async (req, fn) => {
    const origin = checkPost(req);
    const signedIn = requireSession(req);
    requireCsrf(req, signedIn);
    const body = parseJson(await readBody(req));
    try {
      return fn({ ...signedIn, body, origin });
    } catch (error) {
      throw storeError(error);
    }
  };

  const inviteRoutes = invites ? {
    '/invites': {
      // Pending invites only. Tokens are never stored, and hashes never listed.
      GET: (req) => {
        checkGet(req);
        requireOwner(requireSession(req));
        try {
          return { status: 200, body: { invites: invites.list() } };
        } catch (error) {
          throw storeError(error);
        }
      },
      // The one response that carries an invite token, inside the link.
      POST: (req) => mutation(req, ({ user, body, origin }) => {
        requireOwner({ user });
        if (!isSafeDisplayName(body.display_name)) {
          throw new HttpError(400, 'invalid_request', 'display_name must be 1 to 128 characters without surrounding whitespace, control, or formatting characters.');
        }
        const { token, invite } = invites.create({ displayName: body.display_name, createdBy: user.id });
        return { status: 201, body: { invite, url: inviteUrl(origin, token) } };
      }),
    },
    '/invites/revoke': {
      POST: (req) => mutation(req, ({ user, body }) => {
        requireOwner({ user });
        if (typeof body.invite_id !== 'string' || !INVITE_ID_RE.test(body.invite_id)) throw new HttpError(400, 'invalid_request', 'Expected invite_id.');
        if (!invites.revoke(body.invite_id)) throw new HttpError(404, 'invite_not_found', 'No such pending invite.');
        return { status: 200, body: { revoked: true } };
      }),
    },
  } : {};

  const routes = {
    ...inviteRoutes,
    '': {
      GET: (req) => {
        checkGet(req);
        const { session, user } = requireSession(req);
        return {
          status: 200,
          body: {
            user: { id: user.id, display_name: user.display_name, role: user.role },
            session_id: session.id,
            csrf_token: csrfToken(user.id, session.id),
            sessions: sessions.list({ userId: user.id }).map((item) => accountView(item, session.id)),
          },
        };
      },
    },
    '/sign-out': {
      // Signing out works without a session too (it then only clears the
      // cookies), so a browser holding only the server-token cookie can sign out.
      POST: async (req) => {
        const origin = checkPost(req);
        const signedIn = auth.fromRequest(req);
        if (signedIn) requireCsrf(req, signedIn);
        parseJson(await readBody(req));
        if (signedIn) {
          try {
            sessions.revoke(signedIn.session.id);
          } catch (error) {
            throw storeError(error);
          }
        }
        return { status: 200, body: { signed_out: true }, headers: signOutHeaders(origin) };
      },
    },
    '/sessions/revoke': {
      POST: (req) => mutation(req, ({ session, user, body, origin }) => {
        if (typeof body.session_id !== 'string' || !SESSION_ID_RE.test(body.session_id)) throw new HttpError(400, 'invalid_request', 'Expected session_id.');
        const target = sessions.get(body.session_id);
        // Another user's session looks the same as a missing one to non-owners.
        if (!target || (user.role !== 'owner' && target.user_id !== user.id)) throw new HttpError(404, 'session_not_found', 'No such session.');
        sessions.revoke(target.id);
        const current = target.id === session.id;
        return { status: 200, body: { revoked: true, current }, headers: current ? signOutHeaders(origin) : {} };
      }),
    },
    '/users': {
      GET: (req) => {
        checkGet(req);
        const signedIn = requireSession(req);
        requireOwner(signedIn);
        const all = sessions.list();
        const users = (auth.identity()?.users ?? []).map((user) => ({
          id: user.id,
          display_name: user.display_name,
          role: user.role,
          disabled: user.disabled,
          created_at: user.created_at,
          passkeys: user.credentials.map(passkeyView),
          sessions: all.filter((item) => item.user_id === user.id).map((item) => accountView(item, signedIn.session.id)),
        }));
        return { status: 200, body: { users } };
      },
    },
    '/passkeys/remove': {
      POST: (req) => mutation(req, ({ session, user, body, origin }) => {
        requireOwner({ user });
        if (typeof body.credential_id !== 'string' || !CREDENTIAL_ID_RE.test(body.credential_id)) throw new HttpError(400, 'invalid_request', 'Expected credential_id.');
        const data = auth.identity();
        const found = data && findCredential(data, body.credential_id);
        if (!found) throw STORE_ERRORS.not_found();
        if (found.user.role === 'owner' && found.user.credentials.length === 1) throw STORE_ERRORS.last_credential();
        // End the passkey's sessions first, so a failed removal leaves the
        // passkey in place to retry rather than sessions outliving it.
        const revoked = sessions.revokeCredential(body.credential_id);
        identityStore.removeCredential(body.credential_id);
        const current = revoked.some((item) => item.id === session.id);
        return { status: 200, body: { removed: true, sessions_revoked: revoked.length, current }, headers: current ? signOutHeaders(origin) : {} };
      }),
    },
  };

  const sendError = (res, error) => {
    if (error instanceof HttpError) return sendJson(res, error.status, { error: { code: error.code, message: error.message } }, error.extra);
    log(`account internal_error${error?.code ? ` (${error.code})` : ''}`);
    if (isStoreError(error)) {
      return sendJson(res, 503, { error: { code: 'identity_unavailable', message: 'The identity or sessions store is unavailable.' } }, { 'Retry-After': '5' });
    }
    return sendJson(res, 500, { error: { code: 'internal_error', message: 'Internal error.' } });
  };

  // Returns true when the request was an account API request (handled).
  const handle = (req, res) => {
    let url;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      return false;
    }
    if (url.pathname !== ACCOUNT_PREFIX && !url.pathname.startsWith(`${ACCOUNT_PREFIX}/`)) return false;
    (async () => {
      if (url.search) throw new HttpError(400, 'invalid_request', 'Query strings are not accepted.');
      const route = routes[url.pathname.slice(ACCOUNT_PREFIX.length)];
      if (!route) throw new HttpError(404, 'not_found', 'Unknown account route.');
      const method = req.method === 'HEAD' ? 'GET' : req.method;
      if (!route[method]) throw new HttpError(405, 'method_not_allowed', 'Method not allowed.', { Allow: Object.keys(route).join(', ') });
      const { status, body, headers = {} } = await route[method](req);
      sendJson(res, status, body, headers);
    })().catch((error) => {
      if (!res.headersSent) sendError(res, error);
      else res.destroy();
    });
    return true;
  };

  return Object.freeze({ handle });
};
