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

// `log` receives the server's log lines; `now` is the invite expiry clock.
export const withServe = async (config, fn, { log = () => {}, now } = {}) => {
  const token = crypto.randomBytes(32).toString('hex');
  const server = createServeServer(config, { token, log, env: config.testEnv ?? process.env, ...(now ? { now } : {}) });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    await fn({ port, token, origin: `http://localhost:${port}` });
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

export const registerOwner = async ({ port, origin, token }, credential, { rpId = 'localhost', label } = {}) => {
  const cookie = `cockpit_serve=${token}`;
  const options = await call({ port, method: 'POST', pathname: '/auth/passkey/register/options', body: { display_name: 'Ada Example' }, origin, cookie });
  assert.equal(options.status, 200, options.text);
  const response = registrationResponse({ credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId, origin });
  const verify = await call({
    port, method: 'POST', pathname: '/auth/passkey/register/verify', body: { challenge_id: options.json.challenge_id, credential: response, ...(label ? { label } : {}) }, origin, cookie,
  });
  assert.equal(verify.status, 201, verify.text);
  return verify.json;
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
