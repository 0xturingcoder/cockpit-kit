// Helpers for driving serve.mjs with passkeys over real HTTP. Credentials are
// synthetic, generated at runtime (webauthn-synthetic.mjs); users are invented.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { writeConfig } from '../../skill/lib/config.mjs';
import { openRecoveryStore } from '../../skill/lib/identity/recovery.mjs';
import { parseServeConfig } from '../../skill/lib/serve-config.mjs';
import { createServeServer } from '../../skill/scripts/serve.mjs';
import { authenticationResponse, registrationResponse } from './webauthn-synthetic.mjs';

export const makeServeRoot = () => {
  const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cockpit-sessions-serve-')));
  const root = path.join(base, 'root');
  fs.mkdirSync(path.join(root, '.cockpit'), { recursive: true });
  fs.writeFileSync(path.join(root, '.cockpit', 'sources.toml'), '');
  fs.writeFileSync(path.join(root, 'index.html'), '<h1>Home</h1>');
  const home = path.join(base, 'home');
  fs.mkdirSync(home);
  const env = { ...process.env, HOME: home };
  delete env.COCKPIT_HOME;
  delete env.XDG_CONFIG_HOME;
  delete env.XDG_STATE_HOME;
  writeConfig(env, { cockpit_root: root });
  return { base, root, env, identityStore: path.join(base, 'state', 'identity.json'), sessionStore: path.join(base, 'state', 'sessions.json') };
};

// The parsed config remembers the layout's env, so withServe keeps all state
// (including intents state with --write) inside the temp directory.
export const serveConfig = (layout, extra = []) => ({
  ...parseServeConfig({ argv: ['--passkeys', '--identity-store', layout.identityStore, '--port', '0', ...extra], env: layout.env }),
  testEnv: layout.env,
});

// `log` receives the server's log lines; `now` is the clock for invite
// expiry and the step-up window. With --passkeys the owner's recovery token
// is created first (as the first interactive start would) and passed as
// `recoveryToken`; `token` is the per-start server token, which --passkeys
// ignores.
export const withServe = async (config, fn, { log = () => {}, now } = {}) => {
  const token = crypto.randomBytes(32).toString('hex');
  const recoveryToken = config.passkeys ? openRecoveryStore({ file: config.recoveryStore, root: config.root, ...(now ? { now } : {}) }).ensure().token ?? null : null;
  const server = createServeServer(config, { token, log, env: config.testEnv ?? process.env, ...(now ? { now } : {}) });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    await fn({ port, token, recoveryToken, origin: `http://localhost:${port}` });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
};

export const call = ({ port, method = 'GET', pathname, body, origin, cookie, headers = {} }) => new Promise((resolve, reject) => {
  const req = http.request({
    hostname: '127.0.0.1',
    port,
    path: pathname,
    method,
    headers: {
      Host: `localhost:${port}`,
      ...(origin ? { Origin: origin } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
  }, (res) => {
    let text = '';
    res.setEncoding('utf8');
    res.on('data', (chunk) => { text += chunk; });
    res.on('end', () => {
      let json = null;
      try { json = JSON.parse(text); } catch { json = null; }
      resolve({ status: res.statusCode, headers: res.headers, text, json });
    });
  });
  req.on('error', reject);
  req.end(body === undefined ? undefined : JSON.stringify(body));
});

// Create the owner with the recovery token (no session yet) and a first passkey.
export const registerOwner = async ({ port, origin, recoveryToken }, credential, { rpId = 'localhost', label, displayName = 'Ada Example' } = {}) => {
  const options = await call({ port, method: 'POST', pathname: '/auth/passkey/register/options', body: { display_name: displayName, recovery_token: recoveryToken }, origin });
  assert.equal(options.status, 200, options.text);
  const response = registrationResponse({ credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId, origin });
  const verify = await call({
    port,
    method: 'POST',
    pathname: '/auth/passkey/register/verify',
    body: { challenge_id: options.json.challenge_id, credential: response, recovery_token: recoveryToken, ...(label ? { label } : {}) },
    origin,
  });
  assert.equal(verify.status, 201, verify.text);
  return verify.json;
};

// Session-authenticated POST with the session's CSRF token.
export const sessionPost = ({ port, origin }, pathname, { cookie, csrf, body = {}, headers = {} } = {}) => call({
  port, method: 'POST', pathname, body, origin, cookie, headers: { ...(csrf ? { 'X-Cockpit-CSRF': csrf } : {}), ...headers },
});

// The account view for a session cookie (includes its CSRF token).
export const accountOf = async ({ port }, cookie) => {
  const res = await call({ port, pathname: '/auth/account', cookie });
  assert.equal(res.status, 200, res.text);
  return res.json;
};

// Sign in with the recovery token; returns the response and the cookie.
export const recoverySignIn = async ({ port, origin, recoveryToken }, { token = recoveryToken } = {}) => {
  const res = await call({ port, method: 'POST', pathname: '/auth/passkey/recovery/sign-in', body: { token }, origin });
  return { res, cookie: res.headers['set-cookie']?.[0]?.split(';')[0] ?? null };
};

let stepUpCount = 1000;

// Complete a passkey step-up for a signed-in owner session.
export const stepUp = async (ctx, { cookie, csrf }, credential, userId, { rpId = 'localhost' } = {}) => {
  const options = await sessionPost(ctx, '/auth/passkey/step-up/options', { cookie, csrf });
  assert.equal(options.status, 200, options.text);
  stepUpCount += 1;
  const response = authenticationResponse({
    credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId, origin: ctx.origin, signCount: stepUpCount, userHandle: Buffer.from(userId, 'utf8'),
  });
  return sessionPost(ctx, '/auth/passkey/step-up/verify', { cookie, csrf, body: { challenge_id: options.json.challenge_id, credential: response } });
};

// Add a passkey to the owner from a session (which must have a fresh step-up).
// Returns { options, verify }; options.status is checked by the caller.
export const addPasskey = async (ctx, { cookie, csrf }, credential, { rpId = 'localhost', label } = {}) => {
  const options = await sessionPost(ctx, '/auth/passkey/register/options', { cookie, csrf });
  if (options.status !== 200) return { options, verify: null };
  const response = registrationResponse({ credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId, origin: ctx.origin });
  const verify = await sessionPost(ctx, '/auth/passkey/register/verify', {
    cookie, csrf, body: { challenge_id: options.json.challenge_id, credential: response, ...(label ? { label } : {}) },
  });
  return { options, verify };
};

let signCount = 1;

// Sign in with a passkey; returns the response and the `name=value` cookie.
export const signIn = async ({ port, origin }, credential, userId, { rpId = 'localhost', headers = {} } = {}) => {
  const options = await call({ port, method: 'POST', pathname: '/auth/passkey/login/options', body: {}, origin });
  assert.equal(options.status, 200, options.text);
  signCount += 1;
  const response = authenticationResponse({
    credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId, origin, signCount, userHandle: Buffer.from(userId, 'utf8'),
  });
  const res = await call({ port, method: 'POST', pathname: '/auth/passkey/login/verify', body: { challenge_id: options.json.challenge_id, credential: response }, origin, headers });
  assert.equal(res.status, 200, res.text);
  return { res, cookie: res.headers['set-cookie'][0].split(';')[0] };
};
