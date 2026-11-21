// Per-device sessions in serve.mjs --passkeys: cookie attributes, concurrent
// sessions, revocation, expiry, authorization boundaries, the settings page,
// and passkey sessions on the intents API. Credentials are synthetic,
// generated at runtime; users are invented.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { openIdentityStore } from '../skill/lib/identity/store.mjs';
import { IntentStore } from '../skill/lib/intents/store.mjs';
import { deviceLabel } from '../skill/lib/identity/session-http.mjs';
import { parseServeConfig } from '../skill/lib/serve-config.mjs';
import { makeCredential } from './support/webauthn-synthetic.mjs';
import { call, makeServeRoot, registerOwner, serveConfig, signIn, withServe } from './support/serve-harness.mjs';

const account = (ctx, cookie) => call({ port: ctx.port, pathname: '/auth/account', cookie });

const post = (ctx, pathname, { cookie, csrf, body = {}, origin = ctx.origin, headers = {} } = {}) => call({
  port: ctx.port, method: 'POST', pathname, body, origin, cookie, headers: { ...(csrf ? { 'X-Cockpit-CSRF': csrf } : {}), ...headers },
});

// Owner with one passkey, plus a member with one passkey added through the store.
const setup = async (ctx, layout) => {
  const ownerKey = makeCredential();
  const owner = await registerOwner(ctx, ownerKey, { label: 'Work laptop' });
  const store = openIdentityStore({ file: layout.identityStore, root: layout.root });
  const member = store.createUser({ displayName: 'Test Member' });
  const memberKey = makeCredential();
  const memberCredential = store.addCredential(member.id, { id: memberKey.rawId, publicKey: memberKey.cose, label: 'Member phone' });
  return { store, ownerKey, ownerId: owner.user_id, ownerCredentialId: owner.credential_id, member, memberKey, memberCredentialId: memberCredential.id };
};

const writeSessionsFile = (file, doc) => {
  fs.writeFileSync(`${file}.edit`, JSON.stringify(doc), { mode: 0o600 });
  fs.renameSync(`${file}.edit`, file);
};

test('serve sessions: the cookie is HttpOnly, SameSite=Strict, Path=/, with Max-Age matching the configured lifetime', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout, ['--session-lifetime', '12h']), async (ctx) => {
    const key = makeCredential();
    const owner = await registerOwner(ctx, key);
    const { res } = await signIn(ctx, key, owner.user_id);
    const cookie = res.headers['set-cookie'][0];
    assert.match(cookie, /^cockpit_session=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Strict; Path=\/; Max-Age=43200$/);
    assert.doesNotMatch(cookie, /Secure/, 'not Secure over plain http://localhost');
    const stored = JSON.parse(fs.readFileSync(layout.sessionStore, 'utf8')).sessions[0];
    assert.equal(Date.parse(stored.expires_at) - Date.parse(stored.created_at), 43200 * 1000);
    assert.ok(!fs.readFileSync(layout.sessionStore, 'utf8').includes(cookie.split(';')[0].split('=')[1]), 'only the hash is stored');
  });
});

test('serve sessions: on an https origin the cookie is Secure', async () => {
  const layout = makeServeRoot();
  const origin = 'https://cockpit.example.com';
  await withServe(serveConfig(layout, ['--rp-id', 'example.com', '--origin', origin]), async (ctx) => {
    const https = { ...ctx, origin };
    const key = makeCredential();
    const owner = await registerOwner(https, key, { rpId: 'example.com' });
    const { res } = await signIn(https, key, owner.user_id, { rpId: 'example.com' });
    assert.match(res.headers['set-cookie'][0], /; HttpOnly; SameSite=Strict; Path=\/; Max-Age=7776000; Secure$/);
  });
});

test('serve sessions: each sign-in is its own session; a user lists them and revokes any, including the current one', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId } = await setup(ctx, layout);
    const laptop = await signIn(ctx, ownerKey, ownerId, { headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0' } });
    const phone = await signIn(ctx, ownerKey, ownerId);
    assert.notEqual(laptop.cookie, phone.cookie);
    for (const { cookie } of [laptop, phone]) assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 200);

    const view = await account(ctx, laptop.cookie);
    assert.equal(view.status, 200, view.text);
    assert.equal(view.json.user.id, ownerId);
    assert.equal(view.json.user.role, 'owner');
    assert.match(view.json.csrf_token, /^[0-9a-f]{64}$/);
    assert.equal(view.json.sessions.length, 2);
    assert.deepEqual(view.json.sessions.map((s) => s.label), ['Work laptop', 'Work laptop'], 'the passkey label names the device');
    const current = view.json.sessions.find((s) => s.current);
    assert.equal(current.id, view.json.session_id);
    for (const s of view.json.sessions) {
      assert.deepEqual(Object.keys(s).sort(), ['created_at', 'credential_id', 'current', 'expires_at', 'id', 'label', 'last_seen_at', 'user_id']);
    }
    assert.equal(view.headers['cache-control'], 'no-store');
    assert.match(view.headers['content-security-policy'], /default-src 'none'/);

    // Revoke the other session: it is refused on its very next request.
    const other = view.json.sessions.find((s) => !s.current);
    const revoked = await post(ctx, '/auth/account/sessions/revoke', { cookie: laptop.cookie, csrf: view.json.csrf_token, body: { session_id: other.id } });
    assert.equal(revoked.status, 200, revoked.text);
    assert.deepEqual(revoked.json, { revoked: true, current: false });
    assert.equal(revoked.headers['set-cookie'], undefined);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: phone.cookie })).status, 401);
    assert.equal((await account(ctx, phone.cookie)).status, 401);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: laptop.cookie })).status, 200);

    // Revoke the current session: the cookie is cleared and it stops working.
    const self = await post(ctx, '/auth/account/sessions/revoke', { cookie: laptop.cookie, csrf: view.json.csrf_token, body: { session_id: view.json.session_id } });
    assert.deepEqual(self.json, { revoked: true, current: true });
    assert.ok(self.headers['set-cookie'].some((c) => /^cockpit_session=; HttpOnly; SameSite=Strict; Path=\/; Max-Age=0$/.test(c)));
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: laptop.cookie })).status, 401);
  });
});

test('serve sessions: sign out revokes this session only and clears both cookies', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId } = await setup(ctx, layout);
    const a = await signIn(ctx, ownerKey, ownerId);
    const b = await signIn(ctx, ownerKey, ownerId);
    const { json } = await account(ctx, a.cookie);
    const out = await post(ctx, '/auth/account/sign-out', { cookie: a.cookie, csrf: json.csrf_token });
    assert.equal(out.status, 200, out.text);
    assert.deepEqual(out.json, { signed_out: true });
    const cleared = out.headers['set-cookie'];
    assert.ok(cleared.includes('cockpit_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'));
    assert.ok(cleared.includes('cockpit_serve=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'));
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: a.cookie })).status, 401);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: b.cookie })).status, 200);
    // Without CSRF, a signed-in sign-out is refused.
    assert.equal((await post(ctx, '/auth/account/sign-out', { cookie: b.cookie })).status, 403);
    // A browser with no session can still clear its cookies.
    assert.equal((await post(ctx, '/auth/account/sign-out', {})).status, 200);
  });
});

test('serve sessions: expired sessions are refused on the next request', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId } = await setup(ctx, layout);
    const { cookie } = await signIn(ctx, ownerKey, ownerId);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 200);
    const doc = JSON.parse(fs.readFileSync(layout.sessionStore, 'utf8'));
    doc.sessions[0].expires_at = new Date(Date.now() - 1000).toISOString();
    writeSessionsFile(layout.sessionStore, doc);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 401);
    assert.equal((await account(ctx, cookie)).status, 401);
  });
});

test('serve sessions: requests do not write the sessions file (last seen is throttled)', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId } = await setup(ctx, layout);
    const { cookie } = await signIn(ctx, ownerKey, ownerId);
    const before = fs.statSync(layout.sessionStore);
    for (let i = 0; i < 20; i += 1) assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 200);
    const after = fs.statSync(layout.sessionStore);
    assert.equal(after.ino, before.ino);
    assert.equal(after.mtimeMs, before.mtimeMs);
  });
});

test('serve sessions: members manage only their own sessions; the owner manages everyone', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId, member, memberKey, memberCredentialId, ownerCredentialId } = await setup(ctx, layout);
    const ownerSession = await signIn(ctx, ownerKey, ownerId);
    const memberSession = await signIn(ctx, memberKey, member.id);
    const memberSession2 = await signIn(ctx, memberKey, member.id);
    const ownerView = (await account(ctx, ownerSession.cookie)).json;
    const memberView = (await account(ctx, memberSession.cookie)).json;
    assert.equal(memberView.user.role, 'member');
    assert.equal(memberView.sessions.length, 2, 'members see only their own sessions');
    assert.ok(memberView.sessions.every((s) => s.user_id === member.id));

    // Member boundaries.
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account/users', cookie: memberSession.cookie })).status, 403);
    const steal = await post(ctx, '/auth/account/sessions/revoke', { cookie: memberSession.cookie, csrf: memberView.csrf_token, body: { session_id: ownerView.session_id } });
    assert.equal(steal.status, 404, 'another user\'s session looks missing');
    assert.equal(steal.json.error.code, 'session_not_found');
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: ownerSession.cookie })).status, 200);
    const removeOwnerKey = await post(ctx, '/auth/account/passkeys/remove', { cookie: memberSession.cookie, csrf: memberView.csrf_token, body: { credential_id: ownerCredentialId } });
    assert.equal(removeOwnerKey.status, 403);
    assert.equal(removeOwnerKey.json.error.code, 'forbidden');
    // A CSRF token from another session is refused.
    const crossCsrf = await post(ctx, '/auth/account/sessions/revoke', { cookie: memberSession.cookie, csrf: ownerView.csrf_token, body: { session_id: memberView.session_id } });
    assert.equal(crossCsrf.status, 403);
    assert.equal(crossCsrf.json.error.code, 'csrf_invalid');

    // Owner: list every user's sessions and passkeys.
    const users = await call({ port: ctx.port, pathname: '/auth/account/users', cookie: ownerSession.cookie });
    assert.equal(users.status, 200, users.text);
    const listed = Object.fromEntries(users.json.users.map((u) => [u.id, u]));
    assert.equal(listed[member.id].sessions.length, 2);
    assert.deepEqual(listed[member.id].passkeys.map((p) => p.id), [memberCredentialId]);
    assert.deepEqual(Object.keys(listed[member.id].passkeys[0]).sort(), ['created_at', 'id', 'label', 'transports'], 'no public keys or counters');
    assert.ok(!users.text.includes('token_hash'));

    // Owner revokes one member session, then removes the member's passkey,
    // which also ends the member's remaining session.
    const memberSessionId = listed[member.id].sessions.find((s) => s.id === memberView.session_id).id;
    const revoked = await post(ctx, '/auth/account/sessions/revoke', { cookie: ownerSession.cookie, csrf: ownerView.csrf_token, body: { session_id: memberSessionId } });
    assert.deepEqual(revoked.json, { revoked: true, current: false });
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: memberSession.cookie })).status, 401);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: memberSession2.cookie })).status, 200);
    const removed = await post(ctx, '/auth/account/passkeys/remove', { cookie: ownerSession.cookie, csrf: ownerView.csrf_token, body: { credential_id: memberCredentialId } });
    assert.equal(removed.status, 200, removed.text);
    assert.deepEqual(removed.json, { removed: true, sessions_revoked: 1, current: false });
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: memberSession2.cookie })).status, 401);

    // The owner's last passkey is refused.
    const last = await post(ctx, '/auth/account/passkeys/remove', { cookie: ownerSession.cookie, csrf: ownerView.csrf_token, body: { credential_id: ownerCredentialId } });
    assert.equal(last.status, 409);
    assert.equal(last.json.error.code, 'last_passkey');
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: ownerSession.cookie })).status, 200);
  });
});

test('serve sessions: removing the passkey a session signed in with ends that session', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId, ownerCredentialId, store } = await setup(ctx, layout);
    const spareKey = makeCredential();
    const spare = store.addCredential(ownerId, { id: spareKey.rawId, publicKey: spareKey.cose, label: 'Spare key' });
    const viaFirst = await signIn(ctx, ownerKey, ownerId);
    const viaSpare = await signIn(ctx, spareKey, ownerId);
    const { json } = await account(ctx, viaFirst.cookie);
    const removed = await post(ctx, '/auth/account/passkeys/remove', { cookie: viaFirst.cookie, csrf: json.csrf_token, body: { credential_id: ownerCredentialId } });
    assert.deepEqual(removed.json, { removed: true, sessions_revoked: 1, current: true });
    assert.ok(removed.headers['set-cookie'].some((c) => c.startsWith('cockpit_session=;')));
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: viaFirst.cookie })).status, 401);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: viaSpare.cookie })).status, 200);
    assert.equal(store.load().users[0].credentials[0].id, spare.id);
  });
});

test('serve sessions: a disabled user\'s sessions are refused', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { store, member, memberKey } = await setup(ctx, layout);
    const { cookie } = await signIn(ctx, memberKey, member.id);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 200);
    store.disableUser(member.id);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 401);
  });
});

test('serve sessions: account requests need an exact Origin, JSON, CSRF, and no query string', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId } = await setup(ctx, layout);
    const { cookie } = await signIn(ctx, ownerKey, ownerId);
    const { json } = await account(ctx, cookie);
    const body = { session_id: json.session_id };
    const revoke = (options) => post(ctx, '/auth/account/sessions/revoke', { cookie, csrf: json.csrf_token, body, ...options });
    assert.equal((await revoke({ origin: 'https://evil.example' })).status, 403);
    assert.equal((await revoke({ origin: `http://127.0.0.1:${ctx.port}` })).status, 403);
    assert.equal((await revoke({ headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
    assert.equal((await revoke({ headers: { 'Content-Type': 'text/plain' } })).status, 415);
    assert.equal((await revoke({ csrf: 'f'.repeat(64) })).json.error.code, 'csrf_invalid');
    assert.equal((await revoke({ cookie: undefined })).json.error.code, 'session_required');
    assert.equal((await revoke({ body: { session_id: 'nope' } })).status, 400);
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account?x=1', cookie })).status, 400);
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account', cookie, headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
    assert.equal((await call({ port: ctx.port, method: 'DELETE', pathname: '/auth/account', cookie })).status, 405);
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account/nope', cookie })).status, 404);
    // The server-token cookie is not a session.
    const tokenOnly = await account(ctx, `cockpit_serve=${ctx.token}`);
    assert.equal(tokenOnly.status, 401);
    assert.equal(tokenOnly.json.error.code, 'session_required');
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 200, 'nothing above revoked the session');
  });
});

test('serve sessions: the settings page is served with the login page security headers and no inline code', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port }) => {
    const page = await call({ port, pathname: '/auth/settings/' });
    const login = await call({ port, pathname: '/auth/login/' });
    assert.equal(page.status, 200);
    for (const header of ['content-security-policy', 'x-frame-options', 'referrer-policy', 'cache-control', 'x-content-type-options']) {
      assert.equal(page.headers[header], login.headers[header], header);
    }
    assert.doesNotMatch(page.text, /<script(?![^>]*\bsrc=)[^>]*>/);
    assert.doesNotMatch(page.text, /\son[a-z]+\s*=|\sstyle\s*=/i);
    for (const [, ref] of page.text.matchAll(/(?:src|href)="([^"]+)"/g)) assert.match(ref, /^\/auth\/(login|settings)\//);
    const js = await call({ port, pathname: '/auth/settings/cockpit-settings.js' });
    assert.equal(js.status, 200);
    assert.equal(js.headers['content-security-policy'], login.headers['content-security-policy']);
    assert.doesNotMatch(js.text, /https?:\/\/|\beval\(|new Function|innerHTML|outerHTML|insertAdjacentHTML/);
    assert.equal((await call({ port, pathname: '/auth/settings' })).headers.location, '/auth/settings/');
    assert.equal((await call({ port, method: 'POST', pathname: '/auth/settings/' })).status, 405);
  });
});

test('serve sessions: intents routes accept an owner passkey session with a session-bound CSRF token', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout, ['--write']), async (ctx) => {
    const { ownerKey, ownerId, member, memberKey } = await setup(ctx, layout);
    const ownerA = await signIn(ctx, ownerKey, ownerId);
    const ownerB = await signIn(ctx, ownerKey, ownerId);
    const caps = await call({ port: ctx.port, pathname: '/api/cockpit/v1/capabilities', cookie: ownerA.cookie });
    assert.equal(caps.status, 200, caps.text);
    const csrfA = caps.json.csrf_token;
    assert.equal(csrfA, (await account(ctx, ownerA.cookie)).json.csrf_token, 'one CSRF token per session for both APIs');
    const csrfB = (await call({ port: ctx.port, pathname: '/api/cockpit/v1/capabilities', cookie: ownerB.cookie })).json.csrf_token;
    const csrfToken = (await call({ port: ctx.port, pathname: '/api/cockpit/v1/capabilities', cookie: `cockpit_serve=${ctx.token}` })).json.csrf_token;
    assert.equal(new Set([csrfA, csrfB, csrfToken]).size, 3);

    const capture = (n) => ({ schema_version: 1, request_id: `00000000-0000-4000-8000-00000000000${n}`, mode: 'capture', operator_message: 'Remember this', target: null });
    const create = (cookie, csrf, n) => call({
      port: ctx.port, method: 'POST', pathname: '/api/cockpit/v1/intents', cookie, origin: ctx.origin, body: capture(n), headers: { 'X-Cockpit-CSRF': csrf },
    });
    const created = await create(ownerA.cookie, csrfA, 1);
    assert.equal(created.status, 201, created.text);
    const intent = (await call({ port: ctx.port, pathname: `/api/cockpit/v1/intents/${created.json.intent_id}`, cookie: ownerA.cookie })).json;
    assert.equal(intent.intent_id, created.json.intent_id);
    assert.equal((await create(ownerA.cookie, csrfB, 2)).json.error.code, 'csrf_invalid', 'another session\'s CSRF token is refused');
    assert.equal((await create(ownerA.cookie, csrfToken, 2)).json.error.code, 'csrf_invalid');
    assert.equal((await create(ownerB.cookie, csrfB, 2)).status, 201);
    // The server token keeps working on every intents route.
    assert.equal((await create(`cockpit_serve=${ctx.token}`, csrfToken, 3)).status, 201);
    const listed = await call({ port: ctx.port, pathname: '/api/cockpit/v1/intents', cookie: ownerA.cookie });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items.length, 3);

    // Member sessions are refused on every intents route.
    const memberSession = await signIn(ctx, memberKey, member.id);
    const memberCaps = await call({ port: ctx.port, pathname: '/api/cockpit/v1/capabilities', cookie: memberSession.cookie });
    assert.equal(memberCaps.status, 403);
    assert.equal(memberCaps.json.error.code, 'forbidden');
    assert.equal((await call({ port: ctx.port, pathname: '/api/cockpit/v1/intents', cookie: memberSession.cookie })).status, 403);

    // A revoked session is refused immediately.
    const view = (await account(ctx, ownerA.cookie)).json;
    await post(ctx, '/auth/account/sign-out', { cookie: ownerA.cookie, csrf: view.csrf_token });
    const after = await create(ownerA.cookie, csrfA, 4);
    assert.equal(after.status, 401);
    assert.equal(after.json.error.code, 'authentication_required');
  });
});

test('serve sessions: intents state records the owner user id as the principal', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout, ['--write']), async (ctx) => {
    const { ownerKey, ownerId } = await setup(ctx, layout);
    const { cookie } = await signIn(ctx, ownerKey, ownerId);
    const csrf = (await call({ port: ctx.port, pathname: '/api/cockpit/v1/capabilities', cookie })).json.csrf_token;
    const created = await call({
      port: ctx.port, method: 'POST', pathname: '/api/cockpit/v1/intents', cookie, origin: ctx.origin,
      body: { schema_version: 1, request_id: '00000000-0000-4000-8000-0000000000aa', mode: 'capture', operator_message: 'Note', target: null }, headers: { 'X-Cockpit-CSRF': csrf },
    });
    assert.equal(created.status, 201, created.text);
    const state = new IntentStore({ root: layout.root, env: layout.env }).read();
    assert.equal(state.intents[0].provenance.principal_id, ownerId);
  });
});

test('serve config: --session-lifetime is validated, needs --passkeys, and the sessions file sits next to the identity store', () => {
  const layout = makeServeRoot();
  const parse = (argv) => parseServeConfig({ argv: ['--identity-store', layout.identityStore, ...argv], env: layout.env });
  const day = 24 * 60 * 60 * 1000;
  assert.equal(parse(['--passkeys']).sessionLifetimeMs, 90 * day);
  assert.equal(parse(['--passkeys']).sessionStore, layout.sessionStore);
  assert.equal(parse(['--passkeys', '--session-lifetime', '30d']).sessionLifetimeMs, 30 * day);
  assert.equal(parse(['--passkeys', '--session-lifetime=8h']).sessionLifetimeMs, 8 * 60 * 60 * 1000);
  assert.equal(parse(['--passkeys', '--session-lifetime', '5m']).sessionLifetimeMs, 5 * 60 * 1000);
  for (const bad of ['4m', '401d', '90', '1.5d', '-1d', '0d', '90D', '1w', 'forever']) {
    assert.throws(() => parse(['--passkeys', `--session-lifetime=${bad}`]), /--session-lifetime must be/, bad);
  }
  assert.throws(() => parse(['--session-lifetime', '30d']), /--session-lifetime requires --passkeys/);
  assert.equal(parse([]).sessionStore, null);
  const clash = path.join(layout.base, 'state', 'sessions.json');
  assert.throws(() => parseServeConfig({ argv: ['--passkeys', '--identity-store', clash], env: layout.env }), /must not be named sessions\.json/);
});

test('device labels come from the passkey label, else a coarse browser and system name', () => {
  assert.equal(deviceLabel({ credentialLabel: 'Work laptop', userAgent: 'Firefox/150.0' }), 'Work laptop');
  assert.equal(deviceLabel({ userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0' }), 'Firefox on Linux');
  assert.equal(deviceLabel({ userAgent: 'Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0 Mobile Safari/537.36' }), 'Chrome on Android');
  assert.equal(deviceLabel({ userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1' }), 'Safari on iOS');
  assert.equal(deviceLabel({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0 Safari/537.36 Edg/150.0' }), 'Edge on Windows');
  assert.equal(deviceLabel({ userAgent: '<script>‮' }), 'Unknown device');
  assert.equal(deviceLabel({}), 'Unknown device');
});
