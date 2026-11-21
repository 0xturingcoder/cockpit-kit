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
import { HttpError, createPasskeyApi } from '../lib/identity/passkey-http.mjs';
import { SessionStoreError, openSessionStore } from '../lib/identity/sessions.mjs';
import {
  SESSION_COOKIE, createAccountApi, createSessionAuth, deviceLabel, expiredCookie, parseCookies, sessionCookie,
} from '../lib/identity/session-http.mjs';

const cookieName = 'cockpit_serve';
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
]);
const kitRedirects = new Map([['/auth/login', loginPath], ['/auth/settings', settingsPath]]);
// The login and settings pages load only their own same-origin scripts and
// stylesheet and talk only to this server.
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
  return timingSafeEqual(parseCookies(req.headers.cookie).get(cookieName) ?? '', token);
}

function requestToken(req) {
  try {
    return new URL(req.url, 'http://localhost').searchParams.get('token');
  } catch {
    return null;
  }
}

// Serve the kit's own login and settings pages (never a file from the
// knowledge repo). They hold no data; the settings page reads it from the
// account API, which requires a session.
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
  return `${cookieName}=${token}; HttpOnly; SameSite=Strict; Path=/${secure ? '; Secure' : ''}`;
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

// Passkey sign-in, per-device sessions, and the account API.
function createIdentity(server, config, { token, csrfSecret, log }) {
  if (!config.auth) throw new ArgumentError('serve --passkeys requires authentication');
  if (!config.identityStore || !config.sessionStore) throw new ArgumentError('serve --passkeys needs an identity store');
  const store = openIdentityStore({ file: config.identityStore, root: config.root, lockWaitMs: PASSKEY_LOCK_WAIT_MS });
  const sessions = openSessionStore({
    file: config.sessionStore, root: config.root, lockWaitMs: PASSKEY_LOCK_WAIT_MS, ...(config.sessionLifetimeMs ? { lifetimeMs: config.sessionLifetimeMs } : {}),
  });
  const sessionAuth = createSessionAuth({ sessions, identityStore: store, log });
  const origins = () => passkeyOrigins(server, config);
  const ceremonies = createPasskeyCeremonies({ store, rpId: config.rpId, origins });
  const passkeys = createPasskeyApi({
    ceremonies,
    allowedOrigins: origins,
    isOperator: (req) => requestHasAuth(req, token),
    // Every passkey sign-in, owner or member, gets its own session.
    onSignIn: (result, { origin, req }) => {
      let created;
      try {
        created = sessions.create({
          userId: result.userId,
          credentialId: result.credentialId,
          label: deviceLabel({ credentialLabel: result.credentialLabel, userAgent: req.headers['user-agent'] }),
        });
      } catch (error) {
        log(`session create failed (${error?.code ?? error?.name})`);
        throw storeUnavailable(error);
      }
      return { 'Set-Cookie': sessionCookie(created.token, { maxAgeSeconds: created.maxAgeSeconds, secure: origin.startsWith('https:') }) };
    },
    log,
  });
  const account = createAccountApi({
    auth: sessionAuth,
    sessions,
    identityStore: store,
    allowedOrigins: origins,
    csrfToken: (principal, sessionId) => csrfTokenFor(csrfSecret, principal, sessionId),
    signOutCookies: (secure) => [expiredCookie(SESSION_COOKIE, { secure }), expiredCookie(cookieName, { secure })],
    log,
  });
  return { passkeys, account, sessionAuth };
}

const logToStderr = (message) => process.stderr.write(`${message}\n`);

export function createServeServer(config, { token = crypto.randomBytes(32).toString('hex'), env = process.env, log = logToStderr } = {}) {
  let api = null;
  let identity = null;
  // One CSRF secret for the intents and account APIs, so a session has one
  // CSRF token for both.
  const csrfSecret = crypto.createHmac('sha256', token).update('cockpit-intents-csrf').digest();
  // A live passkey session wins; otherwise the server-token cookie.
  const authFor = (req) => {
    const signedIn = identity?.sessionAuth.fromRequest(req);
    if (signedIn) return { kind: 'session', ...signedIn };
    return requestHasAuth(req, token) ? { kind: 'token' } : null;
  };
  const server = http.createServer((req, res) => {
    const port = boundPort(server, config);
    const allowedHosts = hostHeaderValues(config.host, port);
    if (!allowedHosts.has(req.headers.host ?? '')) return responseText(res, 400, 'Bad Host header\n');
    if (api && api.handle(req, res)) return undefined;
    if (identity && (identity.passkeys.handle(req, res) || identity.account.handle(req, res))) return undefined;

    if (config.auth) {
      const urlToken = requestToken(req);
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
  if (config.passkeys) identity = createIdentity(server, config, { token, csrfSecret, log });
  if (config.write) api = createWriteApi(server, config, { authFor, csrfSecret }, env);
  server.cockpitToken = token;
  return server;
}

export function servedUrl(config, token = undefined) {
  const host = config.host === '::1' ? '[::1]' : config.host;
  const url = new URL(`http://${host}:${config.port}/`);
  if (config.auth && token) url.searchParams.set('token', token);
  return url.href;
}

async function main() {
  assertNode20();
  const config = parseServeConfig({ argv: process.argv.slice(2), env: process.env, stderr: process.stderr });
  if (config.help) {
    process.stdout.write(usage());
    return;
  }
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
      process.stdout.write(`Add a passkey: ${origin}${loginPath}?token=${server.cockpitToken}\n`);
      process.stdout.write(`Devices and sign out: ${origin}${settingsPath}\n`);
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
