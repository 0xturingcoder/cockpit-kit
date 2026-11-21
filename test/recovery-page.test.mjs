// The login page's recovery and first-owner forms
// (skill/templates/login/cockpit-login.js) and the settings page's step-up,
// "Add a passkey", recovery banner, and recovery activity
// (skill/templates/settings/cockpit-settings.js), run in node:vm against
// stubbed browser APIs: where the recovery token goes, the order of requests,
// the step-up retry, and that storage, cookies, and the console are left
// alone. Tokens are generated at runtime; no browser or dependency is needed.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const repoRoot = path.resolve(import.meta.dirname, '..');
const loginScript = path.join(repoRoot, 'skill', 'templates', 'login', 'cockpit-login.js');
const settingsScript = path.join(repoRoot, 'skill', 'templates', 'settings', 'cockpit-settings.js');
const ORIGIN = 'https://cockpit.example';

// Elements are created on first lookup and remember their listeners.
const makeDocument = (initial = {}) => {
  const elements = new Map();
  const element = (id) => {
    if (elements.has(id)) return elements.get(id);
    const listeners = {};
    const node = {
      id, hidden: false, value: '', textContent: '', disabled: false, className: '', type: '', children: [],
      classList: { toggle: () => {}, add: () => {}, remove: () => {} },
      addEventListener: (type, fn) => { (listeners[type] ??= []).push(fn); },
      dispatch: (type, event = {}) => (listeners[type] ?? []).map((fn) => fn(event)),
      append: (...children) => { node.children.push(...children); },
      replaceChildren: (...children) => { node.children = children; },
      reset: () => {},
      select: () => {},
      elements: new Proxy({}, { get: (_, name) => element(`field:${String(name)}`) }),
      ...initial[id],
    };
    elements.set(id, node);
    return node;
  };
  return { element, getElementById: element, createElement: (tag) => ({ ...element(`new:${crypto.randomUUID()}`), tag }) };
};

// A sandbox whose storage, cookies, and console record any access at all.
const makeSandbox = ({ document, fetch, credentials, events, passkeys = true }) => {
  const touched = [];
  const tripwire = (name) => new Proxy({}, {
    get: (_, key) => { touched.push(`${name}.${String(key)}`); return () => {}; },
    set: (_, key) => { touched.push(`${name}.${String(key)}=`); return true; },
  });
  Object.defineProperty(document, 'cookie', {
    get: () => { touched.push('document.cookie'); return ''; },
    set: () => { touched.push('document.cookie='); },
  });
  const listeners = {};
  const location = {
    pathname: '/auth/login/', search: '', hash: '', origin: ORIGIN,
    assign: (url) => { events.push({ kind: 'navigate', url: String(url) }); },
    replace: (url) => { events.push({ kind: 'navigate', url: String(url) }); },
  };
  const history = {
    replaceState: (s, t, url) => { events.push({ kind: 'navigate', url: String(url) }); },
    pushState: (s, t, url) => { events.push({ kind: 'navigate', url: String(url) }); },
  };
  const sandbox = {
    document, fetch, location, history, atob, btoa, URL, TextEncoder, Promise, JSON, Object, Array, Uint8Array, Error, String, Date,
    navigator: passkeys ? { credentials, clipboard: { writeText: async () => {} } } : {},
    localStorage: tripwire('localStorage'),
    sessionStorage: tripwire('sessionStorage'),
    console: tripwire('console'),
    addEventListener: (type, fn) => { (listeners[type] ??= []).push(fn); },
    dispatch: (type, event = {}) => (listeners[type] ?? []).forEach((fn) => fn(event)),
  };
  if (passkeys) sandbox.PublicKeyCredential = function PublicKeyCredential() {};
  sandbox.window = sandbox;
  return { sandbox, touched };
};

const settle = async () => {
  for (let i = 0; i < 30; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

const jsonResponse = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

const assertion = () => ({
  id: 'credEXAMPLE', rawId: new Uint8Array([1, 2, 3]).buffer, type: 'public-key', authenticatorAttachment: 'platform',
  response: { clientDataJSON: new Uint8Array([4]).buffer, authenticatorData: new Uint8Array([5]).buffer, signature: new Uint8Array([6]).buffer, userHandle: null },
  getClientExtensionResults: () => ({}),
});

const attestation = () => ({
  id: 'newEXAMPLE', rawId: new Uint8Array([7, 8]).buffer, type: 'public-key', authenticatorAttachment: 'cross-platform',
  response: { clientDataJSON: new Uint8Array([4]).buffer, attestationObject: new Uint8Array([9]).buffer, getTransports: () => ['usb'] },
  getClientExtensionResults: () => ({}),
});

const creationOptions = () => ({
  challenge_id: 'c'.repeat(43),
  publicKey: {
    rp: { id: 'cockpit.example', name: 'Cockpit' },
    user: { id: Buffer.from('usr_ownerEXAMPLEonly0001').toString('base64url'), name: 'Test Owner', displayName: 'Test Owner' },
    challenge: crypto.randomBytes(32).toString('base64url'),
    pubKeyCredParams: [],
    excludeCredentials: [{ type: 'public-key', id: 'AQID' }],
  },
});

const requestOptions = () => ({
  challenge_id: 's'.repeat(43),
  publicKey: { challenge: crypto.randomBytes(32).toString('base64url'), rpId: 'cockpit.example', userVerification: 'required', allowCredentials: [{ type: 'public-key', id: 'AQID' }] },
});

// ---------------------------------------------------------------------------
// Login page

const runLogin = async ({ routes, fields = {}, passkeys = true }) => {
  const events = [];
  const fetch = async (url, init = {}) => {
    events.push({ kind: 'fetch', url: String(url), init });
    const route = routes[String(url)];
    return route ? route(JSON.parse(init.body ?? '{}')) : jsonResponse(404, null);
  };
  const credentials = {
    create: async () => { events.push({ kind: 'create' }); return attestation(); },
    get: async () => { events.push({ kind: 'get' }); return assertion(); },
  };
  const initial = Object.fromEntries(Object.entries(fields).map(([name, value]) => [`field:${name}`, { value }]));
  const document = makeDocument(initial);
  const { sandbox, touched } = makeSandbox({ document, fetch, credentials, events, passkeys });
  vm.runInNewContext(fs.readFileSync(loginScript, 'utf8'), sandbox, { filename: loginScript });
  return { events, touched, document };
};

const assertTokenOnlyInBodies = (events, token, document) => {
  for (const event of events) {
    if (event.url !== undefined) {
      assert.ok(!event.url.includes(token), `${event.kind} ${event.url} carries the token`);
      assert.ok(!event.url.includes('?'), `${event.kind} ${event.url} has a query string`);
    }
    if (event.kind === 'fetch') {
      assert.equal(event.init.method, 'POST');
      assert.equal(event.init.credentials, 'same-origin');
      assert.equal(event.init.referrerPolicy, 'no-referrer');
      assert.ok(!JSON.stringify({ ...event.init, body: undefined }).includes(token), `${event.url}: the token is only in the body`);
    }
  }
  assert.ok(!document.element('status').textContent.includes(token));
};

test('login page: recovery sends the token only in the sign-in POST body, clears the field, and opens Devices', async () => {
  const token = crypto.randomBytes(32).toString('base64url');
  const { events, touched, document } = await runLogin({
    routes: { '/auth/passkey/recovery/sign-in': () => jsonResponse(200, { signed_in: true, user_id: 'usr_ownerEXAMPLEonly0001', recovery: true }) },
    fields: { token },
  });
  document.element('recover-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  const fetches = events.filter((e) => e.kind === 'fetch');
  assert.deepEqual(fetches.map((e) => e.url), ['/auth/passkey/recovery/sign-in']);
  assert.deepEqual(JSON.parse(fetches[0].init.body), { token });
  assertTokenOnlyInBodies(events, token, document);
  assert.equal(document.element('field:token').value, '', 'the field is cleared');
  assert.deepEqual(events.filter((e) => e.kind === 'navigate').map((e) => e.url), ['/auth/settings/']);
  assert.deepEqual(touched, [], 'storage, cookies, and the console are untouched');
});

test('login page: a refused recovery shows the error, clears the field, and stays put; no owner points to setup', async () => {
  const token = crypto.randomBytes(32).toString('base64url');
  for (const [status, code, pattern] of [[401, 'recovery_failed', /not valid/], [429, 'rate_limited', /Too many/], [409, 'no_owner', /Create the owner below/]]) {
    const { events, touched, document } = await runLogin({
      routes: { '/auth/passkey/recovery/sign-in': () => jsonResponse(status, { error: { code, message: code === 'rate_limited' ? 'Too many attempts; retry shortly.' : 'The recovery token is not valid.' } }) },
      fields: { token },
    });
    document.element('recover-form').dispatch('submit', { preventDefault: () => {} });
    await settle();
    assert.match(document.element('status').textContent, pattern, code);
    assert.equal(document.element('field:token').value, '');
    assert.equal(events.filter((e) => e.kind === 'navigate').length, 0);
    assertTokenOnlyInBodies(events, token, document);
    assert.deepEqual(touched, []);
  }
});

test('login page: recovery works in a browser without passkey support, and an empty field sends nothing', async () => {
  const token = crypto.randomBytes(32).toString('base64url');
  const run = await runLogin({ routes: { '/auth/passkey/recovery/sign-in': () => jsonResponse(200, { signed_in: true }) }, fields: { token }, passkeys: false });
  run.document.element('recover-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  assert.deepEqual(run.events.filter((e) => e.kind === 'navigate').map((e) => e.url), ['/auth/settings/']);
  assert.equal(run.document.element('setup').disabled, true, 'setup needs passkeys');

  const empty = await runLogin({ routes: {}, fields: { token: '   ' } });
  empty.document.element('recover-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  assert.equal(empty.events.filter((e) => e.kind === 'fetch').length, 0);
  assert.match(empty.document.element('status').textContent, /Enter the recovery token/);
});

test('login page: first-owner setup sends the recovery token only in the options and verify bodies', async () => {
  const token = crypto.randomBytes(32).toString('base64url');
  const { events, touched, document } = await runLogin({
    routes: {
      '/auth/passkey/register/options': () => jsonResponse(200, creationOptions()),
      '/auth/passkey/register/verify': () => jsonResponse(201, { registered: true, created_owner: true }),
    },
    fields: { recovery_token: token, display_name: 'Test Owner', label: 'Laptop' },
  });
  document.element('setup-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  const fetches = events.filter((e) => e.kind === 'fetch');
  assert.deepEqual(fetches.map((e) => e.url), ['/auth/passkey/register/options', '/auth/passkey/register/verify']);
  assert.deepEqual(events.map((e) => e.kind), ['fetch', 'create', 'fetch']);
  assert.deepEqual(JSON.parse(fetches[0].init.body), { display_name: 'Test Owner', recovery_token: token });
  const verify = JSON.parse(fetches[1].init.body);
  assert.equal(verify.recovery_token, token);
  assert.equal(verify.label, 'Laptop');
  assert.equal(verify.challenge_id, 'c'.repeat(43));
  assertTokenOnlyInBodies(events, token, document);
  assert.equal(document.element('field:recovery_token').value, '');
  assert.match(document.element('status').textContent, /Owner created/);
  assert.deepEqual(touched, []);
});

test('login page: setup when the owner exists says to sign in and add passkeys from Devices', async () => {
  const token = crypto.randomBytes(32).toString('base64url');
  const { events, document } = await runLogin({
    routes: { '/auth/passkey/register/options': () => jsonResponse(409, { error: { code: 'owner_exists', message: 'The owner already exists.' } }) },
    fields: { recovery_token: token, display_name: 'Test Owner' },
  });
  document.element('setup-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  assert.match(document.element('status').textContent, /already exists\. Sign in, then add passkeys from Devices/);
  assert.equal(events.filter((e) => e.kind === 'create').length, 0);
});

// ---------------------------------------------------------------------------
// Settings page

const ACCOUNT = (kind = 'passkey') => ({
  csrf_token: 'csrf-EXAMPLE',
  user: { id: 'usr_ownerEXAMPLEonly0001', display_name: 'Test Owner', role: 'owner' },
  session_id: 'ses_AAAAAAAAAAAAAAAAAAAAAA',
  sessions: [{ id: 'ses_AAAAAAAAAAAAAAAAAAAAAA', kind, label: kind === 'recovery' ? 'Recovery (server token)' : 'Laptop', current: true, created_at: '2026-01-02T03:04:05.000Z', last_seen_at: '2026-01-02T03:04:05.000Z', expires_at: '2026-01-02T15:04:05.000Z' }],
});

// `stale` routes answer 403 step_up_required until a step-up verify succeeds.
const runSettings = async ({ kind = 'passkey', stale = [], audit = [], fields = {}, getError = null } = {}) => {
  const events = [];
  let steppedUp = false;
  const url = `${ORIGIN}/auth/invite/#${crypto.randomBytes(32).toString('base64url')}`;
  const posts = {
    '/auth/account/invites': () => jsonResponse(201, { url, invite: { id: `inv_${'A'.repeat(22)}`, display_name: 'Test Member' } }),
    '/auth/passkey/step-up/options': () => jsonResponse(200, requestOptions()),
    '/auth/passkey/step-up/verify': () => { steppedUp = true; return jsonResponse(200, { stepped_up: true, step_up_at: '2026-01-02T03:05:00.000Z' }); },
    '/auth/passkey/register/options': () => jsonResponse(200, creationOptions()),
    '/auth/passkey/register/verify': () => jsonResponse(201, { registered: true }),
  };
  const fetch = async (requestUrl, init = {}) => {
    const route = String(requestUrl);
    events.push({ kind: 'fetch', url: route, init });
    if (init.method === 'POST') {
      if (stale.includes(route) && !steppedUp) return jsonResponse(403, { error: { code: 'step_up_required', message: 'Confirm with your passkey first.' } });
      return posts[route] ? posts[route]() : jsonResponse(404, null);
    }
    if (route === '/auth/account') return jsonResponse(200, ACCOUNT(kind));
    if (route === '/auth/account/users') return jsonResponse(200, { users: [] });
    if (route === '/auth/account/invites') return jsonResponse(200, { invites: [] });
    if (route === '/auth/account/audit') return jsonResponse(200, { events: audit });
    return jsonResponse(404, null);
  };
  const credentials = {
    get: async (options) => {
      events.push({ kind: 'get', options });
      if (getError) throw Object.assign(new Error('cancelled'), { name: getError });
      return assertion();
    },
    create: async () => { events.push({ kind: 'create' }); return attestation(); },
  };
  const initial = { 'invite-result': { hidden: true }, ...Object.fromEntries(Object.entries(fields).map(([name, value]) => [`field:${name}`, { value }])) };
  const document = makeDocument(initial);
  const { sandbox, touched } = makeSandbox({ document, fetch, credentials, events });
  vm.runInNewContext(fs.readFileSync(settingsScript, 'utf8'), sandbox, { filename: settingsScript });
  await settle();
  return { events, touched, document, url };
};

const postsOf = (events) => events.filter((e) => e.kind === 'fetch' && e.init.method === 'POST');

test('settings page: creating an invite that needs a step-up asks for a passkey, then retries once', async () => {
  const { events, touched, document, url } = await runSettings({ stale: ['/auth/account/invites'], fields: { display_name: 'Test Member' } });
  document.element('invite-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  assert.deepEqual(postsOf(events).map((e) => e.url), [
    '/auth/account/invites', '/auth/passkey/step-up/options', '/auth/passkey/step-up/verify', '/auth/account/invites',
  ]);
  for (const post of postsOf(events)) assert.equal(post.init.headers['X-Cockpit-CSRF'], 'csrf-EXAMPLE', post.url);
  const get = events.find((e) => e.kind === 'get');
  assert.equal(get.options.publicKey.userVerification, 'required');
  assert.ok(get.options.publicKey.allowCredentials[0].id instanceof ArrayBuffer, 'credential ids are decoded');
  assert.equal(JSON.parse(postsOf(events)[2].init.body).challenge_id, 's'.repeat(43));
  assert.equal(document.element('invite-url').value, url);
  assert.deepEqual(touched, []);
});

test('settings page: a cancelled step-up shows the error and does not retry', async () => {
  const { events, document } = await runSettings({ stale: ['/auth/account/invites'], fields: { display_name: 'Test Member' }, getError: 'NotAllowedError' });
  document.element('invite-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  assert.deepEqual(postsOf(events).map((e) => e.url), ['/auth/account/invites', '/auth/passkey/step-up/options']);
  assert.match(document.element('status').textContent, /cancelled or timed out/);
  assert.equal(document.element('invite-result').hidden, true);
});

test('settings page: the owner adds a passkey: step-up when needed, then create and verify with CSRF', async () => {
  const { events, touched, document } = await runSettings({ stale: ['/auth/passkey/register/options'], fields: { label: 'Security key' } });
  assert.equal(document.element('passkey-section').hidden, false);
  document.element('passkey-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  assert.deepEqual(postsOf(events).map((e) => e.url), [
    '/auth/passkey/register/options', '/auth/passkey/step-up/options', '/auth/passkey/step-up/verify', '/auth/passkey/register/options', '/auth/passkey/register/verify',
  ]);
  const order = events.filter((e) => e.kind !== 'fetch' || e.init.method === 'POST').map((e) => (e.kind === 'fetch' ? e.url.split('/').slice(-2).join('/') : e.kind));
  assert.deepEqual(order, ['register/options', 'step-up/options', 'get', 'step-up/verify', 'register/options', 'create', 'register/verify']);
  for (const post of postsOf(events)) assert.equal(post.init.headers['X-Cockpit-CSRF'], 'csrf-EXAMPLE', post.url);
  const verify = JSON.parse(postsOf(events).at(-1).init.body);
  assert.equal(verify.label, 'Security key');
  assert.deepEqual(verify.credential.response.transports, ['usb']);
  assert.match(document.element('status').textContent, /Passkey added/);
  assert.deepEqual(touched, []);
});

test('settings page: a recovery session shows the banner; recovery activity is listed as text', async () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const audit = [
    { at: '2026-01-02T03:04:05.000Z', event: 'token_sign_in', result: 'ok' },
    { at: '2026-01-02T03:00:00.000Z', event: 'token_sign_in', result: 'invalid' },
    { at: '2026-01-01T00:00:00.000Z', event: hostile, result: 'rate_limited' },
  ];
  const recovery = await runSettings({ kind: 'recovery', audit });
  assert.equal(recovery.document.element('recovery-banner').hidden, false);
  assert.equal(recovery.document.element('audit-section').hidden, false);
  const items = recovery.document.element('audit').children.map((child) => child.textContent);
  assert.equal(items.length, 3);
  assert.match(items[0], /Recovery token sign-in · succeeded$/);
  assert.match(items[1], /Recovery token sign-in · wrong token$/);
  assert.ok(items[2].includes(hostile), 'unknown values are shown as plain text');
  const sessionLabels = recovery.document.element('sessions').children[0].children.map((child) => child.textContent);
  assert.ok(sessionLabels.includes(' (recovery token)'));

  const passkey = await runSettings({ kind: 'passkey' });
  assert.equal(passkey.document.element('recovery-banner').hidden, true);
  assert.equal(passkey.document.element('audit').children[0].textContent, 'No recovery activity.');
  assert.ok(passkey.events.every((e) => e.kind !== 'fetch' || e.init.method !== 'POST'), 'loading posts nothing');
});
