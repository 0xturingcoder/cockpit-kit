// The invite page script (skill/templates/invite/cockpit-invite.js) and the
// settings page invite link (skill/templates/settings/cockpit-settings.js),
// run in node:vm against stubbed browser APIs: where the invite token goes,
// in what order, and what the scripts leave alone. Tokens are generated at
// runtime; no browser or dependency is needed.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const repoRoot = path.resolve(import.meta.dirname, '..');
const inviteScript = path.join(repoRoot, 'skill', 'templates', 'invite', 'cockpit-invite.js');
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
const makeSandbox = ({ document, fetch, location, history, credentials, events }) => {
  const touched = [];
  const tripwire = (name) => new Proxy({}, {
    get: (_, key) => { touched.push(`${name}.${String(key)}`); return () => {}; },
    set: (_, key) => { touched.push(`${name}.${String(key)}=`); return true; },
  });
  const listeners = {};
  Object.defineProperty(document, 'cookie', {
    get: () => { touched.push('document.cookie'); return ''; },
    set: () => { touched.push('document.cookie='); },
  });
  const sandbox = {
    document, fetch, location, history, atob, btoa, URL, TextEncoder, Promise, JSON, Object, Array, Uint8Array, Error, String, Date,
    navigator: { credentials, clipboard: { writeText: async () => {} } },
    PublicKeyCredential: function PublicKeyCredential() {},
    localStorage: tripwire('localStorage'),
    sessionStorage: tripwire('sessionStorage'),
    console: tripwire('console'),
    addEventListener: (type, fn) => { (listeners[type] ??= []).push(fn); },
    dispatch: (type, event = {}) => (listeners[type] ?? []).forEach((fn) => fn(event)),
    events,
  };
  sandbox.window = sandbox;
  return { sandbox, touched };
};

const settle = async () => {
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

const jsonResponse = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

// Run the invite page with `token` in the fragment and submit the form.
const runInvitePage = async (token, { optionsStatus = 200 } = {}) => {
  const events = [];
  const location = {
    hash: token ? `#${token}` : '', pathname: '/auth/invite/', search: '', origin: ORIGIN,
    get href() { return `${ORIGIN}${this.pathname}${this.search}${this.hash}`; },
    assign: (url) => { events.push({ kind: 'navigate', url: String(url) }); },
    replace: (url) => { events.push({ kind: 'navigate', url: String(url) }); },
  };
  const history = {
    replaceState: (state, title, url) => {
      events.push({ kind: 'replaceState', url: String(url) });
      const next = new URL(String(url), location.href);
      location.pathname = next.pathname;
      location.search = next.search;
      location.hash = next.hash;
    },
    pushState: (state, title, url) => { events.push({ kind: 'navigate', url: String(url) }); },
  };
  const fetch = async (url, init = {}) => {
    events.push({ kind: 'fetch', url: String(url), init });
    if (String(url).endsWith('/invite/options')) {
      if (optionsStatus !== 200) return jsonResponse(optionsStatus, { error: { code: 'invite_invalid', message: 'This invite link is not valid.' } });
      return jsonResponse(200, {
        challenge_id: 'c'.repeat(43),
        publicKey: {
          rp: { id: 'cockpit.example', name: 'Cockpit' },
          user: { id: Buffer.from('usr_memberEXAMPLE0001').toString('base64url'), name: 'Test Member', displayName: 'Test Member' },
          challenge: crypto.randomBytes(32).toString('base64url'),
          pubKeyCredParams: [],
          excludeCredentials: [],
        },
      });
    }
    return jsonResponse(201, { enrolled: true, signed_in: true, user_id: 'usr_memberEXAMPLE0001' });
  };
  const credentials = {
    create: async () => ({
      id: 'credEXAMPLE', rawId: new Uint8Array([1, 2, 3]).buffer, type: 'public-key', authenticatorAttachment: 'platform',
      response: { clientDataJSON: new Uint8Array([4]).buffer, attestationObject: new Uint8Array([5]).buffer, getTransports: () => ['internal'] },
      getClientExtensionResults: () => ({}),
    }),
  };
  const document = makeDocument();
  const { sandbox, touched } = makeSandbox({ document, fetch, location, history, credentials, events });
  vm.runInNewContext(fs.readFileSync(inviteScript, 'utf8'), sandbox, { filename: inviteScript });
  events.push({ kind: 'loaded' });
  document.element('enroll-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  return { events, touched, document, location };
};

test('invite page: the fragment is stripped before any request, and the token goes only in POST bodies', async () => {
  const token = crypto.randomBytes(32).toString('base64url');
  const { events, touched, document, location } = await runInvitePage(token);

  const kinds = events.map((event) => event.kind);
  assert.equal(kinds[0], 'replaceState', 'the fragment is stripped first');
  assert.ok(kinds.indexOf('replaceState') < kinds.indexOf('fetch'), 'replaceState runs before the first fetch');
  assert.equal(location.hash, '');
  assert.equal(events[0].url, '/auth/invite/');

  const fetches = events.filter((event) => event.kind === 'fetch');
  assert.deepEqual(fetches.map((event) => event.url), ['/auth/passkey/invite/options', '/auth/passkey/invite/verify']);
  for (const { url, init } of fetches) {
    assert.equal(init.method, 'POST', url);
    assert.equal(init.referrerPolicy, 'no-referrer', url);
    assert.equal(init.credentials, 'same-origin', url);
    assert.equal(JSON.parse(init.body).token, token, `${url}: the token is in the body`);
    assert.ok(!JSON.stringify({ ...init, body: undefined }).includes(token), `${url}: the token is only in the body`);
  }
  for (const event of events.filter((e) => e.url !== undefined)) {
    assert.ok(!event.url.includes(token), `${event.kind} ${event.url} must not carry the token`);
    assert.ok(!event.url.includes('?'), `${event.kind} ${event.url} has no query string`);
  }
  assert.deepEqual(events.filter((e) => e.kind === 'navigate').map((e) => e.url), ['/'], 'signed in: opens Cockpit');
  assert.deepEqual(touched, [], 'storage, cookies, and the console are untouched');
  assert.ok(!JSON.stringify(document.element('status').textContent).includes(token));
});

test('invite page: an invalid invite shows the generic message and still keeps the token out of URLs', async () => {
  const token = crypto.randomBytes(32).toString('base64url');
  const { events, touched, document } = await runInvitePage(token, { optionsStatus: 400 });
  assert.equal(events[0].kind, 'replaceState');
  const fetches = events.filter((event) => event.kind === 'fetch');
  assert.equal(fetches.length, 1);
  assert.ok(!fetches[0].url.includes(token));
  assert.equal(events.filter((e) => e.kind === 'navigate').length, 0);
  assert.match(document.element('status').textContent, /not valid/);
  assert.equal(document.element('sign-in-link').hidden, false);
  assert.deepEqual(touched, []);
});

test('invite page: without a token nothing is fetched', async () => {
  const { events, touched } = await runInvitePage('');
  assert.deepEqual(events.map((event) => event.kind), ['loaded']);
  assert.deepEqual(touched, []);
});

test('settings page: a shown invite link is cleared when the page is hidden', async () => {
  const url = `${ORIGIN}/auth/invite/#${crypto.randomBytes(32).toString('base64url')}`;
  const posts = [];
  const fetch = async (requestUrl, init = {}) => {
    const route = String(requestUrl);
    if (init.method === 'POST') {
      posts.push(route);
      return jsonResponse(201, { url, invite: { id: `inv_${'A'.repeat(22)}`, display_name: 'Test Member' } });
    }
    if (route === '/auth/account') {
      return jsonResponse(200, { csrf_token: 'csrf', user: { display_name: 'Test Owner', role: 'owner' }, sessions: [] });
    }
    if (route === '/auth/account/users') return jsonResponse(200, { users: [] });
    if (route === '/auth/account/invites') return jsonResponse(200, { invites: [] });
    return jsonResponse(404, null);
  };
  const document = makeDocument({ 'invite-result': { hidden: true }, 'field:display_name': { value: 'Test Member' } });
  const { sandbox, touched } = makeSandbox({ document, fetch, location: { pathname: '/auth/settings/' }, history: {}, credentials: {}, events: [] });
  vm.runInNewContext(fs.readFileSync(settingsScript, 'utf8'), sandbox, { filename: settingsScript });
  await settle();
  document.element('invite-form').dispatch('submit', { preventDefault: () => {} });
  await settle();
  assert.deepEqual(posts, ['/auth/account/invites']);
  assert.equal(document.element('invite-url').value, url, 'the link is shown once');
  assert.equal(document.element('invite-result').hidden, false);

  sandbox.dispatch('pagehide', { persisted: true });
  assert.equal(document.element('invite-url').value, '', 'pagehide clears the link');
  assert.equal(document.element('invite-result').hidden, true);
  assert.deepEqual(touched, []);
});
