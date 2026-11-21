// Passkey HTTP routes, the login page, and serve integration. Credentials
// are synthetic, generated at runtime (test/support/webauthn-synthetic.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { createPasskeyApi } from '../skill/lib/identity/passkey-http.mjs';
import { IdentityStoreError, openIdentityStore } from '../skill/lib/identity/store.mjs';
import { parseServeConfig } from '../skill/lib/serve-config.mjs';
import { writeConfig } from '../skill/lib/config.mjs';
import { createServeServer } from '../skill/scripts/serve.mjs';
import { FLAGS, authenticationResponse, makeCredential, registrationResponse } from './support/webauthn-synthetic.mjs';

const repoRoot = path.resolve(import.meta.dirname, '..');
const ORIGIN = 'https://example.com';

const tempDir = (prefix) => fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));

// ---------------------------------------------------------------------------
// HTTP error mapping (fake ceremonies)

const fakeRequest = (pathname, { body = '{}', headers = {} } = {}) => new Promise((resolve, reject) => {
  const api = fakeRequest.api;
  const server = http.createServer((req, res) => {
    if (!api.handle(req, res)) { res.writeHead(404); res.end(); }
  });
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    const req = http.request({ hostname: '127.0.0.1', port, path: pathname, method: 'POST', headers: { Origin: ORIGIN, 'Content-Type': 'application/json', ...headers } }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => server.close(() => resolve({ status: res.statusCode, headers: res.headers, body: text ? JSON.parse(text) : null })));
    });
    req.on('error', reject);
    req.end(body);
  });
});

test('http: store_full, store_busy, and invalid_argument become clear client errors on registration', async () => {
  for (const [storeCode, status, code] of [['store_full', 507, 'store_full'], ['store_busy', 503, 'store_busy'], ['invalid_argument', 400, 'invalid_argument'], ['duplicate_id', 409, 'credential_exists']]) {
    fakeRequest.api = createPasskeyApi({
      ceremonies: { finishRegistration: () => { throw new IdentityStoreError('label must be at most 64 characters', storeCode); } },
      allowedOrigins: () => [ORIGIN],
      isOperator: () => true,
      onSignIn: () => ({}),
    });
    const res = await fakeRequest('/auth/passkey/register/verify', { body: JSON.stringify({ challenge_id: 'x', credential: {} }) });
    assert.equal(res.status, status, storeCode);
    assert.equal(res.body.error.code, code);
    if (storeCode === 'store_busy') assert.equal(res.headers['retry-after'], '2');
  }
});

test('http: store_busy during sign-in is a retryable 503; corrupt stores are 503 identity_unavailable', async () => {
  for (const [storeCode, status, code] of [['store_busy', 503, 'store_busy'], ['invalid_store', 503, 'identity_unavailable'], ['counter_regression', 401, 'sign_in_failed']]) {
    fakeRequest.api = createPasskeyApi({
      ceremonies: { finishAuthentication: () => { throw new IdentityStoreError('x', storeCode); } },
      allowedOrigins: () => [ORIGIN],
      isOperator: () => false,
      onSignIn: () => ({}),
    });
    const res = await fakeRequest('/auth/passkey/login/verify', { body: JSON.stringify({ challenge_id: 'x', credential: {} }) });
    assert.equal(res.status, status, storeCode);
    assert.equal(res.body.error.code, code);
  }
});

test('http: requests need an exact allowed Origin, same-origin fetch metadata, JSON, POST, and no query string', async () => {
  fakeRequest.api = createPasskeyApi({ ceremonies: { startAuthentication: () => ({ challengeId: 'id', publicKey: {} }) }, allowedOrigins: () => [ORIGIN], isOperator: () => false, onSignIn: () => ({}) });
  assert.equal((await fakeRequest('/auth/passkey/login/options')).status, 200);
  assert.equal((await fakeRequest('/auth/passkey/login/options', { headers: { Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await fakeRequest('/auth/passkey/login/options', { headers: { Origin: '' } })).status, 403);
  assert.equal((await fakeRequest('/auth/passkey/login/options', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await fakeRequest('/auth/passkey/login/options', { headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal((await fakeRequest('/auth/passkey/login/options', { body: '[]' })).status, 400);
  assert.equal((await fakeRequest('/auth/passkey/login/options?x=1')).status, 400);
  assert.equal((await fakeRequest('/auth/passkey/nope')).status, 404);
  const big = await fakeRequest('/auth/passkey/login/options', { body: JSON.stringify({ pad: 'x'.repeat(70 * 1024) }) });
  assert.equal(big.status, 413);
});

// ---------------------------------------------------------------------------
// serve integration

const makeServeRoot = () => {
  const base = tempDir('cockpit-passkeys-serve-');
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
  return { base, root, env, identityStore: path.join(base, 'state', 'identity.json') };
};

const serveConfig = (layout, extra = []) => parseServeConfig({ argv: ['--passkeys', '--identity-store', layout.identityStore, '--port', '0', ...extra], env: layout.env });

const withServe = async (config, fn) => {
  const token = crypto.randomBytes(32).toString('hex');
  const server = createServeServer(config, { token, log: () => {} });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    await fn({ port, token, origin: `http://localhost:${port}` });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
};

const call = ({ port, method = 'GET', pathname, body, origin, cookie, headers = {} }) => new Promise((resolve, reject) => {
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

const serveRegister = async ({ port, origin, token }, credential, body = { display_name: 'Ada Example' }) => {
  const cookie = `cockpit_serve=${token}`;
  const options = await call({ port, method: 'POST', pathname: '/auth/passkey/register/options', body, origin, cookie });
  assert.equal(options.status, 200, options.text);
  const response = registrationResponse({ credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin });
  const verify = await call({ port, method: 'POST', pathname: '/auth/passkey/register/verify', body: { challenge_id: options.json.challenge_id, credential: response }, origin, cookie });
  return { options: options.json, verify };
};

const serveSignInAttempt = async ({ port, origin }, credential, { userId, signCount = 1, mutate = (r) => r } = {}) => {
  const options = await call({ port, method: 'POST', pathname: '/auth/passkey/login/options', body: {}, origin });
  assert.equal(options.status, 200, options.text);
  const response = mutate(authenticationResponse({
    credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin, signCount, userHandle: Buffer.from(userId, 'utf8'),
  }));
  return call({ port, method: 'POST', pathname: '/auth/passkey/login/verify', body: { challenge_id: options.json.challenge_id, credential: response }, origin });
};

test('serve: passkey registration and sign-in work end to end for ES256 and RS256 and issue the session cookie', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const es = makeCredential({ alg: -7 });
    const { verify } = await serveRegister(ctx, es);
    assert.equal(verify.status, 201, verify.text);
    assert.equal(verify.json.created_owner, true);
    const userId = verify.json.user_id;

    const rs = makeCredential({ alg: -257 });
    const second = await serveRegister(ctx, rs, {});
    assert.equal(second.verify.status, 201, second.verify.text);
    assert.equal(second.verify.json.user_id, userId);

    for (const credential of [es, rs]) {
      const res = await serveSignInAttempt(ctx, credential, { userId, signCount: 2 });
      assert.equal(res.status, 200, res.text);
      assert.deepEqual(res.json, { signed_in: true, user_id: userId });
      const cookie = res.headers['set-cookie']?.[0] ?? '';
      assert.match(cookie, new RegExp(`^cockpit_serve=${ctx.token}; HttpOnly; SameSite=Strict; Path=/$`));
      const page = await call({ port: ctx.port, pathname: '/', cookie: cookie.split(';')[0] });
      assert.equal(page.status, 200);
      assert.equal(page.text, '<h1>Home</h1>');
    }
  });
});

test('serve: registration requires the operator session', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port, origin }) => {
    const res = await call({ port, method: 'POST', pathname: '/auth/passkey/register/options', body: { display_name: 'Ada Example' }, origin });
    assert.equal(res.status, 401);
    assert.equal(res.json.error.code, 'authentication_required');
    const verify = await call({ port, method: 'POST', pathname: '/auth/passkey/register/verify', body: { challenge_id: 'x', credential: {} }, origin, cookie: 'cockpit_serve=wrong' });
    assert.equal(verify.status, 401);
  });
});

test('serve: sign-in failures are generic and do not reveal whether a credential or user exists', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const credential = makeCredential();
    const { verify } = await serveRegister(ctx, credential);
    const userId = verify.json.user_id;
    const unknown = await serveSignInAttempt(ctx, makeCredential(), { userId });
    const badSignature = await serveSignInAttempt(ctx, credential, {
      userId,
      mutate: (r) => ({ ...r, response: { ...r.response, signature: Buffer.alloc(71, 1).toString('base64url') } }),
    });
    const wrongUser = await serveSignInAttempt(ctx, credential, { userId: 'usr_not_a_real_user' });
    const replay = await (async () => {
      const options = await call({ port: ctx.port, method: 'POST', pathname: '/auth/passkey/login/options', body: {}, origin: ctx.origin });
      const response = authenticationResponse({ credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin, signCount: 50, userHandle: Buffer.from(userId) });
      const body = { challenge_id: options.json.challenge_id, credential: response };
      const first = await call({ port: ctx.port, method: 'POST', pathname: '/auth/passkey/login/verify', body, origin: ctx.origin });
      assert.equal(first.status, 200);
      return call({ port: ctx.port, method: 'POST', pathname: '/auth/passkey/login/verify', body, origin: ctx.origin });
    })();
    for (const res of [unknown, badSignature, wrongUser, replay]) {
      assert.equal(res.status, 401);
      assert.deepEqual(res.json, { error: { code: 'sign_in_failed', message: 'Sign-in failed.' } });
      assert.equal(res.headers['set-cookie'], undefined);
    }
  });
});

test('serve: failed sign-in attempts are rate limited', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port, origin }) => {
    const fail = () => call({ port, method: 'POST', pathname: '/auth/passkey/login/verify', body: { challenge_id: 'x'.repeat(43), credential: { rawId: 'AAAA' } }, origin });
    for (let i = 0; i < 10; i += 1) {
      const res = await fail();
      assert.equal(res.status, 401, `attempt ${i + 1}`);
      assert.equal(res.json.error.code, 'sign_in_failed');
    }
    const limited = await fail();
    assert.equal(limited.status, 429);
    assert.equal(limited.json.error.code, 'rate_limited');
    assert.ok(Number(limited.headers['retry-after']) >= 1);
  });
});

test('serve: sign-in option requests are rate limited', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port, origin }) => {
    const statuses = [];
    for (let i = 0; i < 11; i += 1) statuses.push((await call({ port, method: 'POST', pathname: '/auth/passkey/login/options', body: {}, origin })).status);
    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(200));
    assert.equal(statuses[10], 429);
  });
});

test('serve: a member passkey verifies but does not get the owner session cookie', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    await serveRegister(ctx, makeCredential());
    const store = openIdentityStore({ file: layout.identityStore, root: layout.root });
    const member = store.createUser({ displayName: 'Test Member' });
    const credential = makeCredential();
    store.addCredential(member.id, { id: credential.rawId, publicKey: credential.cose });
    const res = await serveSignInAttempt(ctx, credential, { userId: member.id });
    assert.equal(res.status, 403);
    assert.equal(res.json.error.code, 'session_unavailable');
    assert.equal(res.headers['set-cookie'], undefined);
  });
});

test('serve: the passkey API only accepts the configured origin (not 127.0.0.1 or other hosts)', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port }) => {
    for (const origin of [undefined, `http://127.0.0.1:${port}`, 'https://evil.example', `http://localhost:${port + 1}`]) {
      const res = await call({ port, method: 'POST', pathname: '/auth/passkey/login/options', body: {}, origin });
      assert.equal(res.status, 403, String(origin));
    }
  });
});

test('serve: configured --rp-id and --origin are used instead of request headers', async () => {
  const layout = makeServeRoot();
  const config = serveConfig(layout, ['--rp-id', 'example.com', '--origin', 'https://cockpit.example.com']);
  assert.equal(config.rpId, 'example.com');
  await withServe(config, async ({ port, token }) => {
    const origin = 'https://cockpit.example.com';
    const cookie = `cockpit_serve=${token}`;
    const options = await call({ port, method: 'POST', pathname: '/auth/passkey/register/options', body: { display_name: 'Ada Example' }, origin, cookie });
    assert.equal(options.json.publicKey.rp.id, 'example.com');
    const credential = makeCredential();
    const response = registrationResponse({ credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'example.com', origin });
    const verify = await call({ port, method: 'POST', pathname: '/auth/passkey/register/verify', body: { challenge_id: options.json.challenge_id, credential: response }, origin, cookie });
    assert.equal(verify.status, 201, verify.text);
    const login = await call({ port, method: 'POST', pathname: '/auth/passkey/login/options', body: {}, origin });
    const good = authenticationResponse({ credential, challenge: Buffer.from(login.json.publicKey.challenge, 'base64url'), rpId: 'example.com', origin, signCount: 3, userHandle: Buffer.from(verify.json.user_id) });
    const ok = await call({ port, method: 'POST', pathname: '/auth/passkey/login/verify', body: { challenge_id: login.json.challenge_id, credential: good }, origin });
    assert.equal(ok.status, 200, ok.text);
    assert.match(ok.headers['set-cookie'][0], /; Secure$/);
  });
});

test('serve: the login page is served before auth with a strict CSP, no inline scripts, and no third-party hosts', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port, token }) => {
    const page = await call({ port, pathname: '/auth/login/' });
    assert.equal(page.status, 200);
    const csp = page.headers['content-security-policy'];
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'(;|$)/);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https?:/);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    const scripts = [...page.text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
    assert.ok(scripts.length >= 1);
    for (const [, attrs, inner] of scripts) {
      assert.match(attrs, /\bsrc="\/auth\/login\/[a-z-]+\.js"/);
      assert.equal(inner.trim(), '');
    }
    assert.doesNotMatch(page.text, /\son[a-z]+\s*=/i, 'no inline event handlers');
    assert.doesNotMatch(page.text, /\sstyle\s*=/i, 'no inline styles');
    assert.doesNotMatch(page.text, /(https?:)?\/\/[a-z0-9.-]+\.[a-z]/i, 'no third-party hosts');

    const js = await call({ port, pathname: '/auth/login/cockpit-login.js' });
    assert.equal(js.status, 200);
    assert.match(js.headers['content-type'], /text\/javascript/);
    assert.match(js.text, /navigator\.credentials\.get/);
    assert.match(js.text, /navigator\.credentials\.create/);
    assert.doesNotMatch(js.text, /https?:\/\//, 'login script talks only to this origin');
    assert.doesNotMatch(js.text, /\beval\(|new Function|innerHTML/);
    const css = await call({ port, pathname: '/auth/login/cockpit-login.css' });
    assert.equal(css.status, 200);
    assert.doesNotMatch(css.text, /@import|url\(/);

    const redirect = await call({ port, pathname: '/auth/login' });
    assert.equal(redirect.status, 301);
    assert.equal(redirect.headers.location, '/auth/login/');

    const tokenRedirect = await call({ port, pathname: `/auth/login/?token=${token}` });
    assert.equal(tokenRedirect.status, 302);
    assert.equal(tokenRedirect.headers.location, '/auth/login/');
    assert.match(tokenRedirect.headers['set-cookie'][0], /^cockpit_serve=/);

    const other = await call({ port, pathname: '/' });
    assert.equal(other.status, 401);
    assert.match(other.text, /\/auth\/login\//);
    const post = await call({ port, method: 'POST', pathname: '/auth/login/' });
    assert.equal(post.status, 405);
  });
});

test('serve: login page files on disk have no inline script and use only same-origin assets', () => {
  const dir = path.join(repoRoot, 'skill', 'templates', 'login');
  const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  for (const [, ref] of html.matchAll(/(?:src|href)="([^"]+)"/g)) assert.match(ref, /^\/auth\/login\//);
});

test('serve: without --passkeys, /auth/ paths are not special', async () => {
  const layout = makeServeRoot();
  const config = parseServeConfig({ argv: ['--identity-store', layout.identityStore, '--port', '0'], env: layout.env });
  assert.equal(config.passkeys, false);
  await withServe(config, async ({ port, origin }) => {
    assert.equal((await call({ port, pathname: '/auth/login/' })).status, 401);
    assert.equal((await call({ port, method: 'POST', pathname: '/auth/passkey/login/options', body: {}, origin })).status, 401);
  });
});

test('serve config: passkey options are validated at startup and come only from the command line', () => {
  const layout = makeServeRoot();
  const parse = (argv) => parseServeConfig({ argv, env: layout.env });
  const store = ['--identity-store', layout.identityStore];
  assert.equal(parse(['--passkeys', ...store]).rpId, 'localhost');
  assert.throws(() => parse(['--passkeys', '--no-auth', ...store]), /requires authentication/);
  assert.throws(() => parse(['--rp-id', 'example.com', ...store]), /--rp-id requires --passkeys/);
  assert.throws(() => parse(['--passkeys', '--rp-id', 'example.com', ...store]), /--rp-id/);
  assert.throws(() => parse(['--passkeys', '--rp-id', '127.0.0.1', '--origin', 'https://127.0.0.1', ...store]), /--rp-id/);
  assert.throws(() => parse(['--passkeys', '--rp-id', 'example.com', '--origin', 'https://evil.example', ...store]), /--rp-id/);
  assert.throws(() => parse(['--passkeys', '--origin', 'http://127.0.0.1:18765', ...store]), /--rp-id/);
  assert.equal(parse(['--passkeys', '--rp-id=example.com', '--origin', 'https://cockpit.example.com', ...store]).rpId, 'example.com');

  fs.writeFileSync(path.join(layout.root, '.cockpit', 'serve.toml'), `identity_store = "${layout.identityStore}"\n`);
  assert.throws(() => parse(['--passkeys']), /does not accept identity_store from \.cockpit\/serve\.toml/);
  assert.equal(parse(['--passkeys', ...store]).passkeys, true);
  assert.equal(parse([]).passkeys, false);

  const noHome = { ...layout.env, XDG_CONFIG_HOME: path.join(layout.base, 'home', '.config') };
  delete noHome.HOME;
  delete noHome.XDG_STATE_HOME;
  fs.rmSync(path.join(layout.root, '.cockpit', 'serve.toml'));
  assert.throws(() => parseServeConfig({ argv: ['--passkeys', '--root', layout.root], env: noHome }), /needs an identity store/);
});

test('serve: failed registration attempts map verifier errors to specific codes for the operator', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port, origin, token }) => {
    const cookie = `cockpit_serve=${token}`;
    const options = await call({ port, method: 'POST', pathname: '/auth/passkey/register/options', body: { display_name: 'Ada Example' }, origin, cookie });
    const response = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin, fmt: 'packed' });
    const res = await call({ port, method: 'POST', pathname: '/auth/passkey/register/verify', body: { challenge_id: options.json.challenge_id, credential: response }, origin, cookie });
    assert.equal(res.status, 400);
    assert.equal(res.json.error.code, 'unsupported_attestation');
    const again = await call({ port, method: 'POST', pathname: '/auth/passkey/register/verify', body: { challenge_id: options.json.challenge_id, credential: response }, origin, cookie });
    assert.equal(again.json.error.code, 'challenge_unknown');
    const flags = FLAGS.UP | FLAGS.AT;
    const o2 = await call({ port, method: 'POST', pathname: '/auth/passkey/register/options', body: { display_name: 'Ada Example' }, origin, cookie });
    const r2 = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(o2.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin, flags });
    const res2 = await call({ port, method: 'POST', pathname: '/auth/passkey/register/verify', body: { challenge_id: o2.json.challenge_id, credential: r2 }, origin, cookie });
    assert.equal(res2.json.error.code, 'user_not_verified');
  });
});
