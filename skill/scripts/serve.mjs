#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseServeConfig } from '../lib/serve-config.mjs';
import { ArgumentError, RootResolutionError, CockpitRootValidationError } from '../lib/config.mjs';
import { assertNode20, expandHome, isPathInside } from '../lib/paths.mjs';
import { IntentError } from '../lib/intents/core.mjs';
import { createIntentsApi, csrfTokenFor, validateWebhookUrl } from '../lib/intents/http.mjs';
import { IntentStore } from '../lib/intents/store.mjs';
import { loadWebhookHeaders } from '../lib/intents/webhook-headers.mjs';
import { openIdentityStore } from '../lib/identity/store.mjs';
import { createPasskeyCeremonies } from '../lib/identity/passkeys.mjs';
import { HttpError, RECOVERY_SESSION_MAX_MS, createPasskeyApi } from '../lib/identity/passkey-http.mjs';
import { SessionStoreError, openSessionStore } from '../lib/identity/sessions.mjs';
import { openInviteStore } from '../lib/identity/invites.mjs';
import { openAuditLog, openRecoveryStore } from '../lib/identity/recovery.mjs';
import {
  DEFAULT_STEP_UP_WINDOW_MS, HOST_SESSION_COOKIE, INVITE_PATH, SESSION_COOKIE, createAccountApi, createSessionAuth, deviceLabel, expiredCookie, parseCookies,
  requireFreshStepUp, sessionCookie, sessionCookieName,
} from '../lib/identity/session-http.mjs';

const tokenCookieName = 'cockpit_serve';
const allowedCockpitPath = '.cockpit/search-index.json';
const loginPath = '/auth/login/';
const settingsPath = '/auth/settings/';
const templatesDir = fileURLToPath(new URL('../templates/', import.meta.url));
// Kit pages served with --passkeys, never files from the knowledge repo.
const kitAssets = new Map([
  ['/auth/login/', 'login/index.html'],
  ['/auth/login/cockpit-login.js', 'login/cockpit-login.js'],
  ['/auth/login/cockpit-login.css', 'login/cockpit-login.css'],
  ['/auth/settings/', 'settings/index.html'],
  ['/auth/settings/cockpit-settings.js', 'settings/cockpit-settings.js'],
  [INVITE_PATH, 'invite/index.html'],
  [`${INVITE_PATH}cockpit-invite.js`, 'invite/cockpit-invite.js'],
]);
const kitRedirects = new Map([['/auth/login', loginPath], ['/auth/settings', settingsPath], ['/auth/invite', INVITE_PATH]]);
// The login, settings, and invite pages load only their own same-origin
// scripts and stylesheet and talk only to this server.
const loginCsp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
// Store writes on sign-in (the signature counter) wait at most this long for
// the identity store lock, so a busy store cannot stall the server for the
// store's default 5 seconds.
const PASSKEY_LOCK_WAIT_MS = 1000;

const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.svg', 'image/svg+xml; charset=utf-8'],
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.gif', 'image/gif'],
  ['.webp', 'image/webp'],
  ['.ico', 'image/x-icon'],
]);

function usage() {
  return `Usage: node scripts/serve.mjs [options]

Options:
  --root <path>       Cockpit root to serve
  --host <host>       Host to bind (default: 127.0.0.1)
  --port <port>       Port to bind (default: 18765)
  --auth              Enable local bearer-token cookie auth (default)
  --no-auth           Disable local bearer-token cookie auth
  --write             Also serve the operator intents API at /api/cockpit/v1
                      (requires auth; state lives outside the root)
  --origin <origin>   Exact browser origin allowed to mutate; repeat once per
                      origin (default: this server's loopback origins)
  --webhook-url <url> POST a content-free wake notification on new intents
                      and replies (or COCKPIT_INTENTS_WEBHOOK_URL)
  --webhook-headers-file <path>
                      Extra webhook headers, one "Name: value" per line,
                      file must be chmod 600 (or
                      COCKPIT_INTENTS_WEBHOOK_HEADERS_FILE)
  --identity-store <path>
                      Users and passkeys file; must be outside the root
                      (default: per-repo state dir, or serve.toml
                      identity_store)
  --passkeys          Enable passkey sign-in at /auth/login/ (requires auth;
                      identity store from the command line or the default)
  --rp-id <domain>    WebAuthn relying-party id (default: localhost); every
                      --origin must be this host or a subdomain of it
  --session-lifetime <duration>
                      Lifetime of a passkey sign-in session, such as 90d,
                      12h, or 30m (default: 90d; requires --passkeys)
  --invite-lifetime <duration>
                      How long a member invite link stays valid, such as
                      24h, 3d, or 30m (default: 24h, at most 7d; requires
                      --passkeys)
  --step-up-window <duration>
                      How recently a session must confirm with a passkey
                      before adding a passkey or creating an invite, such as
                      5m or 15m (default: 5m, from 1m to 60m; requires
                      --passkeys)
  --rotate-token      Replace the owner's recovery token, end every recovery
                      session, print the new token once, and exit (requires
                      --passkeys; does not serve). Refused when stdout is not
                      a terminal, so the token never lands in a journal or log
  --print-token-to-non-tty
                      With --rotate-token, print the new token even when
                      stdout is not a terminal (only if nothing keeps that
                      output)
  --recovery-enroll   For this run only, let a recovery-token session add one
                      owner passkey without a passkey step-up, for 15 minutes
                      or until used (when every owner passkey is lost;
                      requires --passkeys)
  --help              Show this help
`;
}

function timingSafeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function isLoopbackHost(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
}

function hostHeaderValues(host, port) {
  const bases = new Set(['localhost', '127.0.0.1', '[::1]']);
  if (isLoopbackHost(host)) bases.add(host === '::1' ? '[::1]' : host);
  return new Set([...bases].map((value) => `${value}:${port}`));
}

function responseText(res, status, text) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
  res.end(text);
}

function decodedPathname(rawUrl) {
  const rawPath = String(rawUrl ?? '').split(/[?#]/, 1)[0] || '/';
  try {
    return decodeURIComponent(rawPath);
  } catch {
    return undefined;
  }
}

function safeRelativePath(rawUrl) {
  const pathname = decodedPathname(rawUrl);
  if (pathname === undefined || pathname.includes('\0')) return undefined;
  if (pathname.split('/').includes('..')) return undefined;
  const normalized = path.posix.normalize(pathname);
  const relative = normalized.replace(/^\/+/, '');
  if (relative === '..' || relative.startsWith('../') || path.isAbsolute(relative)) return undefined;
  return relative === '' ? 'index.html' : relative;
}

function isCockpitPrivatePath(relative) {
  return relative === '.cockpit' || relative.startsWith('.cockpit/');
}

function isGitPath(relative) {
  return relative.split('/').some((segment) => segment.toLowerCase() === '.git');
}

function resolveServedFile(root, rawUrl) {
  const relative = safeRelativePath(rawUrl);
  if (relative === undefined) return { status: 400 };
  const normalized = relative.endsWith('/') ? `${relative}index.html` : relative;
  if (isCockpitPrivatePath(normalized) && normalized !== allowedCockpitPath) return { status: 404 };
  if (isGitPath(normalized)) return { status: 404 };

  const candidate = path.join(root, ...normalized.split('/'));
  let stat = fs.statSync(candidate, { throwIfNoEntry: false });
  let file = candidate;
  if (stat?.isDirectory()) {
    file = path.join(candidate, 'index.html');
    stat = fs.statSync(file, { throwIfNoEntry: false });
  }
  if (!stat || !stat.isFile()) return { status: 404 };

  const real = fs.realpathSync.native(file);
  if (!isPathInside(real, root)) return { status: 404 };
  // Re-apply the private-path rules to the resolved target so an in-root
  // symlink alias (e.g. `alias -> .git` or `-> .cockpit/x`) cannot expose it.
  const realRelative = path.relative(fs.realpathSync.native(root), real).split(path.sep).join('/');
  if (isGitPath(realRelative)) return { status: 404 };
  if (isCockpitPrivatePath(realRelative) && realRelative !== allowedCockpitPath) return { status: 404 };
  return { status: 200, file: real, size: stat.size };
}

function requestHasAuth(req, token) {
  return timingSafeEqual(parseCookies(req.headers.cookie).get(tokenCookieName) ?? '', token);
}

function requestToken(req) {
  try {
    return new URL(req.url, 'http://localhost').searchParams.get('token');
  } catch {
    return null;
  }
}

// Serve the kit's own login, settings, and invite pages (never a file from
// the knowledge repo). They hold no data; the settings page reads it from the
// account API, which requires a session, and the invite page reads its token
// from the URL fragment, which never reaches this server.
function serveKitAsset(req, res, pathname) {
  if (kitRedirects.has(pathname)) {
    res.writeHead(301, { Location: kitRedirects.get(pathname), 'Cache-Control': 'no-store' });
    res.end();
    return true;
  }
  const name = kitAssets.get(pathname);
  if (!name) return false;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    responseText(res, 405, 'Method not allowed\n');
    return true;
  }
  const body = fs.readFileSync(path.join(templatesDir, name));
  res.writeHead(200, {
    'Content-Type': contentTypes.get(path.extname(name)),
    'Content-Length': String(body.length),
    'Content-Security-Policy': loginCsp,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  });
  res.end(req.method === 'HEAD' ? undefined : body);
  return true;
}

// The server-token cookie set by the tokenized URL. It is not a per-device
// session: it lasts for the browser session and works until the server
// restarts with a new token.
function tokenCookie(token, secure) {
  return `${tokenCookieName}=${token}; HttpOnly; SameSite=Strict; Path=/${secure ? '; Secure' : ''}`;
}

// Secure when every configured origin is https, so the cookie is never sent
// over plain http. Without --origin the server is reached over http.
function tokenCookieSecure(config) {
  return Boolean(config.origins?.length) && config.origins.every((origin) => origin.startsWith('https:'));
}

function boundPort(server, config) {
  const address = server.address();
  return typeof address === 'object' && address ? address.port : config.port;
}

export function resolveWebhookHeaders(webhookUrl, file, env = process.env) {
  if (!file) return {};
  if (!webhookUrl) throw new ArgumentError('--webhook-headers-file requires --webhook-url (or COCKPIT_INTENTS_WEBHOOK_URL)');
  return loadWebhookHeaders(path.resolve(expandHome(file, env)));
}

// authFor(req) returns { kind: 'session', session, user }, { kind: 'token' },
// or null. Passkey sessions of the owner may use every intents route (CSRF is
// bound to the session); member sessions are refused until verified comment
// authors land (#12). The server token keeps working as before.
function intentsPrincipal(auth) {
  if (!auth) return null;
  if (auth.kind === 'token') return 'operator';
  if (auth.user.role !== 'owner') throw new IntentError(403, 'forbidden', 'Only the owner can use the intents API.');
  return { principal: auth.user.id, session: auth.session.id };
}

function createWriteApi(server, config, { authFor, csrfSecret }, env) {
  if (!config.auth) throw new ArgumentError('serve --write requires authentication');
  const store = new IntentStore({ root: config.root, env });
  const webhookUrl = validateWebhookUrl(config.webhookUrl);
  const webhookHeaders = resolveWebhookHeaders(webhookUrl, config.webhookHeadersFile, env);
  const configured = new Set(config.origins ?? []);
  return createIntentsApi({
    root: config.root,
    store,
    // Exact origins come from configuration (or this server's own loopback
    // origins), never from request headers.
    allowedOrigins: () => (configured.size ? configured
      : new Set([...hostHeaderValues(config.host, boundPort(server, config))].map((host) => `http://${host}`))),
    authenticate: (req) => intentsPrincipal(authFor(req)),
    csrfSecret,
    webhookUrl,
    webhookHeaders,
    log: (message) => process.stderr.write(`${message}\n`),
  });
}

// The default passkey origin is this server's own http://localhost:<port>.
// It is the only loopback origin that can use passkeys: browsers do not
// accept an IP address such as 127.0.0.1 as a relying-party id.
function passkeyOrigins(server, config) {
  return config.origins?.length ? config.origins : [`http://localhost:${boundPort(server, config)}`];
}

const storeUnavailable = (error) => (error instanceof SessionStoreError && error.code === 'store_busy'
  ? new HttpError(503, 'store_busy', 'The sessions store is busy; retry shortly.', { 'Retry-After': '2' })
  : new HttpError(503, 'identity_unavailable', 'The sessions store is unavailable.', { 'Retry-After': '5' }));

// The recovery token file and the audit log, next to the identity store.
export function openRecoveryFiles(config, { now = Date.now } = {}) {
  if (!config.recoveryStore || !config.auditStore) throw new ArgumentError('serve --passkeys needs an identity store');
  return {
    recovery: openRecoveryStore({ file: config.recoveryStore, root: config.root, now, lockWaitMs: PASSKEY_LOCK_WAIT_MS }),
    audit: openAuditLog({ file: config.auditStore, root: config.root, now, lockWaitMs: PASSKEY_LOCK_WAIT_MS }),
  };
}

const safeEqual = (a, b) => timingSafeEqual(String(a ?? ''), String(b ?? ''));

// --recovery-enroll: for one run, a recovery session may add one owner
// passkey without a step-up (every owner passkey is lost, so a step-up is
// impossible). It closes after the first success or after 15 minutes.
const RECOVERY_ENROLL_MS = 15 * 60 * 1000;

// Passkey sign-in, recovery, step-up, invites, per-device sessions, and the
// account API.
function createIdentity(server, config, { csrfSecret, log, now }) {
  if (!config.auth) throw new ArgumentError('serve --passkeys requires authentication');
  if (!config.identityStore || !config.sessionStore || !config.inviteStore) throw new ArgumentError('serve --passkeys needs an identity store');
  const store = openIdentityStore({ file: config.identityStore, root: config.root, lockWaitMs: PASSKEY_LOCK_WAIT_MS });
  const sessions = openSessionStore({
    file: config.sessionStore, root: config.root, lockWaitMs: PASSKEY_LOCK_WAIT_MS, now, ...(config.sessionLifetimeMs ? { lifetimeMs: config.sessionLifetimeMs } : {}),
  });
  const invites = openInviteStore({
    file: config.inviteStore, root: config.root, lockWaitMs: PASSKEY_LOCK_WAIT_MS, now, ...(config.inviteLifetimeMs ? { lifetimeMs: config.inviteLifetimeMs } : {}),
  });
  const { recovery, audit } = openRecoveryFiles(config, { now });
  const stepUpWindowMs = config.stepUpWindowMs ?? DEFAULT_STEP_UP_WINDOW_MS;
  const origins = () => passkeyOrigins(server, config);
  // __Host-cockpit_session when every passkey origin is https. Only that
  // name is read, so a plain-named cookie planted over http is ignored.
  const cookieName = sessionCookieName(origins());
  // A recovery session older than the current recovery token is refused, so
  // a rotation ends recovery sessions even if revoking them failed; with no
  // token file, every recovery session is refused.
  const sessionAuth = createSessionAuth({
    sessions, identityStore: store, cookieName, recoveryNotBefore: () => recovery.createdAt() ?? Infinity, log,
  });
  const ceremonies = createPasskeyCeremonies({ store, rpId: config.rpId, origins, invites });
  const csrfToken = (principal, sessionId) => csrfTokenFor(csrfSecret, principal, sessionId);
  const enroll = { open: config.recoveryEnroll === true, until: now() + RECOVERY_ENROLL_MS };
  const enrollOpen = (signedIn) => enroll.open && now() < enroll.until && signedIn.session.kind === 'recovery';

  // A live session wins: a member session is refused even with a recovery
  // token in the body or a leftover server-token cookie. null = no session.
  const ownerSession = (req) => {
    const signedIn = sessionAuth.fromRequest(req);
    if (!signedIn) return null;
    if (signedIn.user.role !== 'owner') throw new HttpError(403, 'forbidden', 'Only the owner can do this.');
    if (!safeEqual(req.headers['x-cockpit-csrf'], csrfToken(signedIn.user.id, signedIn.session.id))) {
      throw new HttpError(403, 'csrf_invalid', 'Missing or invalid CSRF token.');
    }
    return signedIn;
  };
  const sessionRef = ({ session, user }) => ({ userId: user.id, sessionId: session.id });

  const setSession = (created, origin) => ({
    'Set-Cookie': sessionCookie(created.token, { maxAgeSeconds: created.maxAgeSeconds, secure: origin.startsWith('https:'), name: cookieName }),
  });
  const createSession = (input) => {
    try {
      return sessions.create(input);
    } catch (error) {
      log(`session create failed (${error?.code ?? error?.name})`);
      throw storeUnavailable(error);
    }
  };

  const passkeys = createPasskeyApi({
    ceremonies,
    allowedOrigins: origins,
    // Adding a passkey needs a live owner session, its CSRF token, and a
    // fresh step-up (or, with --recovery-enroll, a recovery session while the
    // window is open).
    authorizeRegistration: (req) => {
      const signedIn = ownerSession(req);
      if (!signedIn) return null;
      if (!enrollOpen(signedIn)) requireFreshStepUp(signedIn, { now: now(), windowMs: stepUpWindowMs });
      return sessionRef(signedIn);
    },
    onRegistered: (result, ref) => {
      if (!enroll.open || now() >= enroll.until) return;
      const session = sessions.get(ref.sessionId);
      if (session?.kind !== 'recovery') return;
      enroll.open = false;
      try {
        audit.record('recovery_enroll', 'ok');
      } catch (error) {
        log(`audit write failed (${error?.code ?? error?.name})`);
      }
      log('recovery enrollment used; it is now closed');
    },
    authorizeStepUp: (req) => {
      const signedIn = ownerSession(req);
      if (!signedIn) throw new HttpError(401, 'session_required', 'Sign in first.');
      return sessionRef(signedIn);
    },
    onStepUp: ({ sessionId }) => {
      let updated;
      try {
        updated = sessions.markStepUp(sessionId);
      } catch (error) {
        log(`step-up record failed (${error?.code ?? error?.name})`);
        throw storeUnavailable(error);
      }
      if (!updated) throw new HttpError(401, 'session_required', 'Sign in first.');
      return updated.step_up_at;
    },
    recovery: {
      check: (token) => recovery.check(token),
      owner: () => sessionAuth.identity()?.users.find((user) => user.role === 'owner') ?? null,
      record: (event, result) => audit.record(event, result),
    },
    // The recovery token signs in only the owner, with a recovery session
    // that has no passkey and no step-up, for at most 12 hours.
    onRecoverySignIn: ({ userId }, { origin }) => setSession(createSession({
      userId, kind: 'recovery', label: 'Recovery (server token)', maxLifetimeMs: RECOVERY_SESSION_MAX_MS,
    }), origin),
    // Every passkey sign-in, owner or member, gets its own session, and so
    // does a member who just enrolled through an invite.
    onSignIn: (result, { origin, req }) => setSession(createSession({
      userId: result.userId,
      credentialId: result.credentialId,
      label: deviceLabel({ credentialLabel: result.credentialLabel, userAgent: req.headers['user-agent'] }),
    }), origin),
    log,
    now,
  });
  const account = createAccountApi({
    auth: sessionAuth,
    sessions,
    identityStore: store,
    allowedOrigins: origins,
    csrfToken,
    // Sign-out expires both session cookie names and any old server-token cookie.
    signOutCookies: (secure) => [
      expiredCookie(SESSION_COOKIE, { secure }), ...(secure ? [expiredCookie(HOST_SESSION_COOKIE, { secure })] : []), expiredCookie(tokenCookieName, { secure }),
    ],
    invites,
    audit,
    stepUpWindowMs,
    now,
    log,
  });
  return { passkeys, account, sessionAuth };
}

const logToStderr = (message) => process.stderr.write(`${message}\n`);

// `now` is the clock for sessions, invite expiry, the step-up window, the
// recovery enrollment window, the passkey rate limits, and the audit log (tests).
//
// With --passkeys the per-start token no longer authenticates anything: the
// ?token= URL and the cockpit_serve cookie are ignored, so the token never
// travels in a URL or stands as a cookie. The owner's recovery token
// (recovery.json, docs/recovery.md) signs in through the login page instead.
export function createServeServer(config, {
  token = crypto.randomBytes(32).toString('hex'), env = process.env, log = logToStderr, now = Date.now,
} = {}) {
  let api = null;
  let identity = null;
  // One CSRF secret for the intents and account APIs, so a session has one
  // CSRF token for both. With --passkeys it is random per start; without, it
  // is derived from the server token as before.
  const csrfSecret = config.passkeys
    ? crypto.randomBytes(32)
    : crypto.createHmac('sha256', token).update('cockpit-intents-csrf').digest();
  const tokenAuth = config.auth && !config.passkeys;
  // A live passkey or recovery session; without --passkeys, the server-token cookie.
  const authFor = (req) => {
    const signedIn = identity?.sessionAuth.fromRequest(req);
    if (signedIn) return { kind: 'session', ...signedIn };
    return tokenAuth && requestHasAuth(req, token) ? { kind: 'token' } : null;
  };
  const server = http.createServer((req, res) => {
    const port = boundPort(server, config);
    const allowedHosts = hostHeaderValues(config.host, port);
    if (!allowedHosts.has(req.headers.host ?? '')) return responseText(res, 400, 'Bad Host header\n');
    if (api && api.handle(req, res)) return undefined;
    if (identity && (identity.passkeys.handle(req, res) || identity.account.handle(req, res))) return undefined;

    if (config.auth) {
      const urlToken = tokenAuth ? requestToken(req) : null;
      if (urlToken && timingSafeEqual(urlToken, token)) {
        // Set the cookie and redirect to the token-free URL so the secret
        // does not linger in the address bar, history, or same-origin Referer.
        res.setHeader('Set-Cookie', tokenCookie(token, tokenCookieSecure(config)));
        res.writeHead(302, { Location: String(req.url ?? '/').split('?')[0] || '/' });
        return res.end();
      }
      if (identity && serveKitAsset(req, res, decodedPathname(req.url))) return undefined;
      if (!authFor(req)) {
        return responseText(res, 401, identity ? `Authentication required\nSign in with a passkey at ${loginPath}\n` : 'Authentication required\n');
      }
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return responseText(res, 405, 'Method not allowed\n');
    const resolved = resolveServedFile(config.root, req.url);
    if (resolved.status !== 200) return responseText(res, resolved.status, resolved.status === 400 ? 'Bad path\n' : 'Not found\n');

    let stream;
    if (req.method !== 'HEAD') {
      stream = fs.createReadStream(resolved.file);
      stream.on('error', (error) => {
        if (!res.headersSent) responseText(res, 500, 'File read error\n');
        else res.destroy(error);
      });
    }
    res.writeHead(200, {
      'Content-Type': contentTypes.get(path.extname(resolved.file).toLowerCase()) ?? 'application/octet-stream',
      'Content-Length': String(resolved.size),
      'X-Content-Type-Options': 'nosniff',
    });
    if (req.method === 'HEAD') res.end();
    else stream.pipe(res);
  });
  if (config.passkeys) identity = createIdentity(server, config, { csrfSecret, log, now });
  if (config.write) api = createWriteApi(server, config, { authFor, csrfSecret }, env);
  // With --passkeys the per-start token authenticates nothing, so it is not exposed or printed.
  server.cockpitToken = config.passkeys ? null : token;
  return server;
}

export function servedUrl(config, token = undefined) {
  const host = config.host === '::1' ? '[::1]' : config.host;
  const url = new URL(`http://${host}:${config.port}/`);
  if (config.auth && token) url.searchParams.set('token', token);
  return url.href;
}

const RECOVERY_TOKEN_NOTICE = 'Store it offline (a password manager or paper), never in the repo, shell history, or chat. It is not shown again.';

/**
 * Create the owner's recovery token on the first --passkeys start. The token
 * is returned only when it was created here and `interactive` is true (a
 * terminal), so it is never written to a service journal; otherwise no token
 * is created and the operator runs --rotate-token in a terminal.
 *
 * @returns {{ status: 'exists' } | { status: 'created', token: string } | { status: 'missing' }}
 */
export function ensureRecoveryToken(config, { interactive, now = Date.now } = {}) {
  const { recovery } = openRecoveryFiles(config, { now });
  if (recovery.exists()) return { status: 'exists' };
  if (!interactive) return { status: 'missing' };
  const created = recovery.ensure();
  return created.created ? { status: 'created', token: created.token } : { status: 'exists' };
}

/**
 * --rotate-token: write a new recovery token hash under the lock, revoke every
 * recovery session, and record token_rotated. Returns the new token for the
 * caller to print once. A failed revoke is reported, not fatal: recovery
 * sessions older than the new token are refused anyway.
 */
export function rotateRecoveryToken(config, { now = Date.now } = {}) {
  const { recovery, audit } = openRecoveryFiles(config, { now });
  const { token } = recovery.rotate();
  const warnings = [];
  let revoked = 0;
  try {
    revoked = openSessionStore({ file: config.sessionStore, root: config.root, now }).revokeKind('recovery').length;
  } catch (error) {
    warnings.push(`could not revoke recovery sessions (${error?.code ?? error?.name}); they are refused anyway because they predate the new token`);
  }
  try {
    audit.record('token_rotated', 'ok');
  } catch (error) {
    warnings.push(`could not record the rotation in the audit log (${error?.code ?? error?.name})`);
  }
  return { token, revoked, warnings };
}

async function main() {
  assertNode20();
  const config = parseServeConfig({ argv: process.argv.slice(2), env: process.env, stderr: process.stderr });
  if (config.help) {
    process.stdout.write(usage());
    return;
  }
  if (config.rotateToken) {
    // Checked before anything is written, so a refusal leaves the old token in place.
    if (!process.stdout.isTTY && !config.printTokenToNonTty) {
      throw new ArgumentError('--rotate-token refused (non_tty_stdout): stdout is not a terminal, so the new token could land in a service journal or log file. Nothing was changed. Run it in a terminal, or add --print-token-to-non-tty if nothing keeps this output.');
    }
    const { token, revoked, warnings } = rotateRecoveryToken(config);
    for (const warning of warnings) process.stderr.write(`Warning: ${warning}\n`);
    process.stdout.write(`Recovery token rotated; ${revoked} recovery session(s) ended. The old token no longer works.\n`);
    process.stdout.write(`New recovery token: ${token}\n${RECOVERY_TOKEN_NOTICE}\n`);
    return;
  }
  const recoveryToken = config.passkeys ? ensureRecoveryToken(config, { interactive: Boolean(process.stdout.isTTY) }) : null;
  const server = createServeServer(config);
  server.on('error', (error) => {
    process.stderr.write(`serve.mjs failed to start: ${error.message}\n`);
    process.exitCode = 1;
  });
  // getaddrinfo can't resolve the bracketed literal [::1]; only bare ::1 binds.
  const bindHost = config.host === '[::1]' ? '::1' : config.host;
  server.listen(config.port, bindHost, () => {
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : config.port;
    const boundConfig = { ...config, port };
    process.stdout.write(`Cockpit root: ${config.root}\n`);
    process.stdout.write(`Serving: ${servedUrl(boundConfig, server.cockpitToken)}\n`);
    if (config.write) process.stdout.write('Write mode: operator intents API at /api/cockpit/v1 (state outside the root)\n');
    if (config.passkeys) {
      const [origin] = passkeyOrigins(server, boundConfig);
      process.stdout.write(`Passkeys: sign in at ${origin}${loginPath} (relying party ${config.rpId})\n`);
      process.stdout.write(`Devices, invites, and sign out: ${origin}${settingsPath}\n`);
      if (recoveryToken.status === 'created') {
        process.stdout.write(`Recovery token (create the owner, or recover, at ${origin}${loginPath}): ${recoveryToken.token}\n${RECOVERY_TOKEN_NOTICE}\n`);
      } else if (recoveryToken.status === 'missing') {
        process.stdout.write('No recovery token yet. Run serve.mjs with --passkeys --rotate-token in a terminal to create one; it is needed to create the owner.\n');
      }
      if (config.recoveryEnroll) {
        process.stderr.write('Warning: --recovery-enroll is on. For 15 minutes, or until it is used once, a recovery-token session can add an owner passkey without a passkey step-up.\n');
      }
    }
  });
}

function isCliEntrypoint() {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync.native(process.argv[1]) === fs.realpathSync.native(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isCliEntrypoint()) {
  main().catch((error) => {
    const expected = error instanceof ArgumentError || error instanceof RootResolutionError || error instanceof CockpitRootValidationError;
    process.stderr.write(`${expected ? error.message : `${error.name}: ${error.message}`}\n`);
    process.exitCode = 1;
  });
}
