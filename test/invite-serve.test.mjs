// One-time invite links in serve.mjs --passkeys, end to end: owner-only
// creation, enrollment with synthetic credentials generated at runtime,
// single use, expiry (injected clock), revocation, wrong user, replay,
// concurrent enrollments, one generic error, the invite page headers, the
// token staying out of logs and responses, separate rate-limit buckets and
// challenge capacity, and --invite-lifetime parsing. Users are invented.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { DEFAULT_MAX_CHALLENGES, createChallengeStore } from '../skill/lib/identity/challenges.mjs';
import { openInviteStore } from '../skill/lib/identity/invites.mjs';
import { createPasskeyApi } from '../skill/lib/identity/passkey-http.mjs';
import { createPasskeyCeremonies } from '../skill/lib/identity/passkeys.mjs';
import { hashToken } from '../skill/lib/identity/sessions.mjs';
import { MAX_FILE_BYTES, findUser, openIdentityStore } from '../skill/lib/identity/store.mjs';
import { parseServeConfig } from '../skill/lib/serve-config.mjs';
import { makeCredential, registrationResponse } from './support/webauthn-synthetic.mjs';
import { openRecoveryStore } from '../skill/lib/identity/recovery.mjs';
import { call, makeServeRoot, registerOwner, serveConfig, signIn, stepUp, withServe } from './support/serve-harness.mjs';

const HOUR = 60 * 60 * 1000;
const OWNER_ID = 'usr_ownerEXAMPLEonly0001';

const post = (ctx, pathname, { cookie, csrf, body = {}, origin = ctx.origin, headers = {} } = {}) => call({
  port: ctx.port, method: 'POST', pathname, body, origin, cookie, headers: { ...(csrf ? { 'X-Cockpit-CSRF': csrf } : {}), ...headers },
});

// The owner (created with the recovery token) signed in with a passkey.
const ownerSession = async (ctx) => {
  const key = makeCredential();
  const owner = await registerOwner(ctx, key);
  const { cookie } = await signIn(ctx, key, owner.user_id);
  const account = await call({ port: ctx.port, pathname: '/auth/account', cookie });
  return { cookie, csrf: account.json.csrf_token, userId: owner.user_id, key };
};

// Create an invite; like the settings page, step up and retry when the
// session's step-up is no longer fresh (for example after the test clock moved).
const createInvite = async (ctx, owner, displayName = 'Test Member') => {
  const send = () => post(ctx, '/auth/account/invites', { cookie: owner.cookie, csrf: owner.csrf, body: { display_name: displayName } });
  let res = await send();
  if (res.status === 403 && res.json?.error?.code === 'step_up_required') {
    assert.equal((await stepUp(ctx, owner, owner.key, owner.userId)).status, 200);
    res = await send();
  }
  assert.equal(res.status, 201, res.text);
  const token = res.json.url.split('#')[1];
  return { res, token, invite: res.json.invite };
};

const inviteOptions = (ctx, body) => post(ctx, '/auth/passkey/invite/options', { body });

// Run the browser side of an enrollment: options, then a synthetic
// registration response, then verify (with `verifyToken`, default the same).
const enroll = async (ctx, token, { credential = makeCredential(), verifyToken = token, label, extra = {} } = {}) => {
  const options = await inviteOptions(ctx, { token, ...extra });
  assert.equal(options.status, 200, options.text);
  const response = registrationResponse({ credential, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin });
  const body = { token: verifyToken, challenge_id: options.json.challenge_id, credential: response, ...(label ? { label } : {}), ...extra };
  const verify = await post(ctx, '/auth/passkey/invite/verify', { body });
  return { options, verify, body, credential };
};

const INVALID = { error: { code: 'invite_invalid', message: 'This invite link is not valid. Ask the owner for a new one.' } };

const assertInvalid = (res, what) => {
  assert.equal(res.status, 400, `${what}: ${res.text}`);
  assert.deepEqual(res.json, INVALID, what);
  assert.equal(res.headers['set-cookie'], undefined, what);
};

const identity = (layout) => openIdentityStore({ file: layout.identityStore, root: layout.root });
const inviteStore = (layout) => openInviteStore({ file: path.join(layout.base, 'state', 'invites.json'), root: layout.root });
const members = (layout) => identity(layout).load().users.filter((user) => user.role === 'member');

test('invites: the owner creates an invite; the link carries a random token in the fragment that is stored only hashed', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { res, token, invite } = await createInvite(ctx, owner);
    assert.match(res.json.url, new RegExp(`^${ctx.origin}/auth/invite/#[A-Za-z0-9_-]{43}$`));
    assert.equal(Buffer.from(token, 'base64url').length, 32);
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
    assert.deepEqual(Object.keys(invite).sort(), ['created_at', 'created_by', 'display_name', 'expires_at', 'id', 'role', 'user_id']);
    assert.equal(invite.created_by, owner.userId);
    assert.equal(invite.role, 'member');
    assert.equal(Date.parse(invite.expires_at) - Date.parse(invite.created_at), 24 * HOUR, 'default lifetime is 24 hours');

    const inviteFile = path.join(layout.base, 'state', 'invites.json');
    const stored = fs.readFileSync(inviteFile, 'utf8');
    assert.ok(!stored.includes(token), 'the token is not stored');
    assert.ok(stored.includes(hashToken(token)), 'its hash is');
    if (process.platform !== 'win32') assert.equal(fs.statSync(inviteFile).mode & 0o777, 0o600);
    assert.equal(findUser(identity(layout).load(), invite.user_id), null, 'no user exists until enrollment');

    const list = await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie });
    assert.equal(list.status, 200, list.text);
    assert.deepEqual(list.json, { invites: [invite] });
    assert.ok(!list.text.includes(token) && !list.text.includes(hashToken(token)) && !list.text.includes('token_hash'));
  });
});

test('invites: the invite link uses the configured https origin', async () => {
  const layout = makeServeRoot();
  const origin = 'https://cockpit.example.com';
  await withServe(serveConfig(layout, ['--rp-id', 'example.com', '--origin', origin]), async (ctx) => {
    const https = { ...ctx, origin };
    const key = makeCredential();
    const owner = await registerOwner(https, key, { rpId: 'example.com' });
    const { cookie } = await signIn(https, key, owner.user_id, { rpId: 'example.com' });
    const csrf = (await call({ port: ctx.port, pathname: '/auth/account', cookie })).json.csrf_token;
    const res = await post(https, '/auth/account/invites', { cookie, csrf, body: { display_name: 'Test Member' } });
    assert.equal(res.status, 201, res.text);
    assert.match(res.json.url, /^https:\/\/cockpit\.example\.com\/auth\/invite\/#[A-Za-z0-9_-]{43}$/);
  });
});

test('invites: enrolling creates the bound member with one passkey and signs them in', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token, invite } = await createInvite(ctx, owner, 'Test Member');
    // Fields a client might add to pick a user, name, or role are ignored.
    const extra = { user_id: OWNER_ID, display_name: 'Ada Example', role: 'owner' };
    const { options, verify, credential } = await enroll(ctx, token, { label: 'Member phone', extra });
    assert.equal(options.json.publicKey.user.id, Buffer.from(invite.user_id, 'utf8').toString('base64url'));
    assert.equal(options.json.publicKey.user.name, 'Test Member');
    assert.deepEqual(options.json.publicKey.excludeCredentials, []);
    assert.equal(options.headers['cache-control'], 'no-store');

    assert.equal(verify.status, 201, verify.text);
    assert.deepEqual(verify.json, { enrolled: true, signed_in: true, user_id: invite.user_id });
    const cookie = verify.headers['set-cookie'][0];
    assert.match(cookie, /^cockpit_session=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Strict; Path=\/; Max-Age=7776000$/);
    const session = cookie.split(';')[0];
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: session })).status, 200);
    const account = await call({ port: ctx.port, pathname: '/auth/account', cookie: session });
    assert.deepEqual(account.json.user, { id: invite.user_id, display_name: 'Test Member', role: 'member' });
    assert.equal(account.json.sessions[0].label, 'Member phone');

    const [member] = members(layout);
    assert.equal(member.id, invite.user_id);
    assert.equal(member.display_name, 'Test Member');
    assert.equal(member.credentials.length, 1);
    assert.equal(member.credentials[0].id, credential.rawId.toString('base64url'));
    assert.equal(identity(layout).load().users.filter((user) => user.role === 'owner').length, 1);
    assert.deepEqual((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites, [], 'the invite is spent');

    // The new member signs in with the passkey later, like any member.
    await signIn(ctx, credential, invite.user_id);
  });
});

test('invites: single use and replay: a spent invite refuses new options, a replayed verify, and a second passkey', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token } = await createInvite(ctx, owner);
    const first = await enroll(ctx, token);
    assert.equal(first.verify.status, 201, first.verify.text);
    assertInvalid(await post(ctx, '/auth/passkey/invite/verify', { body: first.body }), 'replayed verify body');
    assertInvalid(await inviteOptions(ctx, { token }), 'options with a spent token');
    assert.equal(members(layout).length, 1);
    assert.equal(members(layout)[0].credentials.length, 1, 'the replay added no passkey');
  });
});

test('invites: a token replayed with a fresh challenge obtained before the invite was spent is refused', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token } = await createInvite(ctx, owner);
    // An attacker holding the token gets options first, then the invitee enrolls.
    const early = await inviteOptions(ctx, { token });
    assert.equal(early.status, 200);
    assert.equal((await enroll(ctx, token)).verify.status, 201);
    const response = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(early.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin });
    assertInvalid(await post(ctx, '/auth/passkey/invite/verify', { body: { token, challenge_id: early.json.challenge_id, credential: response } }), 'token replay');
    assert.equal(members(layout).length, 1);
  });
});

test('invites: expiry follows the clock: refused at 24 hours by default, and at --invite-lifetime when set', async () => {
  const layout = makeServeRoot();
  const clock = { at: Date.now() };
  const now = () => clock.at;
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token } = await createInvite(ctx, owner);
    clock.at += 24 * HOUR - 1000;
    const options = await inviteOptions(ctx, { token });
    assert.equal(options.status, 200, 'still valid just before 24 hours');
    clock.at += 1000;
    assertInvalid(await inviteOptions(ctx, { token }), 'expired at 24 hours');
    // Options obtained before expiry cannot be finished after it.
    const response = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin });
    assertInvalid(await post(ctx, '/auth/passkey/invite/verify', { body: { token, challenge_id: options.json.challenge_id, credential: response } }), 'verify after expiry');
    assert.equal(members(layout).length, 0);
    assert.deepEqual((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites, [], 'expired invites are not listed');
  }, { now });

  const short = makeServeRoot();
  await withServe(serveConfig(short, ['--invite-lifetime', '30m']), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token, invite } = await createInvite(ctx, owner);
    assert.equal(Date.parse(invite.expires_at) - Date.parse(invite.created_at), 30 * 60 * 1000);
    clock.at += 30 * 60 * 1000;
    assertInvalid(await inviteOptions(ctx, { token }), 'expired at 30 minutes');
  }, { now });
});

test('invites: the owner revokes pending invites; a revoked invite is refused, even mid-enrollment', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const revoke = (inviteId) => post(ctx, '/auth/account/invites/revoke', { cookie: owner.cookie, csrf: owner.csrf, body: { invite_id: inviteId } });
    const a = await createInvite(ctx, owner, 'Test Member');
    const b = await createInvite(ctx, owner, 'Other Member');
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites.length, 2);

    const done = await revoke(a.invite.id);
    assert.equal(done.status, 200, done.text);
    assert.deepEqual(done.json, { revoked: true });
    assertInvalid(await inviteOptions(ctx, { token: a.token }), 'revoked before options');
    assert.deepEqual((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites.map((i) => i.id), [b.invite.id]);
    assert.equal((await revoke(a.invite.id)).json.error.code, 'invite_not_found');
    assert.equal((await revoke('inv_AAAAAAAAAAAAAAAAAAAAAA')).status, 404);
    assert.equal((await revoke('not-an-id')).status, 400);

    // Revoked between options and verify: refused, and no user is created.
    const options = await inviteOptions(ctx, { token: b.token });
    assert.equal(options.status, 200);
    await revoke(b.invite.id);
    const response = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin });
    assertInvalid(await post(ctx, '/auth/passkey/invite/verify', { body: { token: b.token, challenge_id: options.json.challenge_id, credential: response } }), 'revoked mid-enrollment');
    assert.equal(members(layout).length, 0);
  });
});

test('invites: wrong user: a challenge from one invite cannot be finished with another invite\'s token', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const a = await createInvite(ctx, owner, 'Test Member');
    const b = await createInvite(ctx, owner, 'Other Member');
    // Options for A (bound to A's user), finished with B's token.
    const crossed = await enroll(ctx, a.token, { verifyToken: b.token });
    assertInvalid(crossed.verify, 'A challenge with B token');
    assert.equal(members(layout).length, 0, 'no user was created for either invite');
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites.length, 2, 'neither invite was spent');
    // Each token still enrolls exactly its own user.
    assert.equal((await enroll(ctx, b.token)).verify.json.user_id, b.invite.user_id);
    assert.equal((await enroll(ctx, a.token)).verify.json.user_id, a.invite.user_id);
    assert.deepEqual(members(layout).map((m) => [m.id, m.display_name]).sort(), [[a.invite.user_id, 'Test Member'], [b.invite.user_id, 'Other Member']].sort());
  });
});

test('invites: concurrent enrollments with one invite: exactly one wins', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token, invite } = await createInvite(ctx, owner);
    const bodies = [];
    for (let i = 0; i < 6; i += 1) {
      const options = await inviteOptions(ctx, { token });
      assert.equal(options.status, 200, options.text);
      const response = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin });
      bodies.push({ token, challenge_id: options.json.challenge_id, credential: response });
    }
    const results = await Promise.all(bodies.map((body) => post(ctx, '/auth/passkey/invite/verify', { body })));
    const winners = results.filter((res) => res.status === 201);
    assert.equal(winners.length, 1, results.map((res) => res.status).join(','));
    for (const res of results.filter((r) => r.status !== 201)) assertInvalid(res, 'losing enrollment');
    const all = members(layout);
    assert.equal(all.length, 1);
    assert.equal(all[0].id, invite.user_id);
    assert.equal(all[0].credentials.length, 1);
  });
});

// Each case set runs on its own server, so the invite rate limits (10
// failures at once) do not kick in.
test('invites: spent, expired, revoked, unknown, malformed, and mismatched tokens and bad ceremonies all get the same error', async () => {
  const responses = {};
  const clock = { at: Date.now() };
  await withServe(serveConfig(makeServeRoot()), async (ctx) => {
    const owner = await ownerSession(ctx);
    const spent = await createInvite(ctx, owner, 'Spent Member');
    assert.equal((await enroll(ctx, spent.token)).verify.status, 201);
    const revoked = await createInvite(ctx, owner, 'Revoked Member');
    await post(ctx, '/auth/account/invites/revoke', { cookie: owner.cookie, csrf: owner.csrf, body: { invite_id: revoked.invite.id } });
    const expiring = await createInvite(ctx, owner, 'Expired Member');
    clock.at += 24 * HOUR;
    const live = await createInvite(ctx, owner, 'Live Member');
    Object.assign(responses, {
      spent: await inviteOptions(ctx, { token: spent.token }),
      expired: await inviteOptions(ctx, { token: expiring.token }),
      revoked: await inviteOptions(ctx, { token: revoked.token }),
      unknown: await inviteOptions(ctx, { token: Buffer.alloc(32, 7).toString('base64url') }),
      'too short': await inviteOptions(ctx, { token: live.token.slice(1) }),
      'not a string': await inviteOptions(ctx, { token: 42 }),
      missing: await inviteOptions(ctx, {}),
      'invite id': await inviteOptions(ctx, { token: live.invite.id }),
      'token hash': await inviteOptions(ctx, { token: hashToken(live.token) }),
    });
  }, { now: () => clock.at });

  // Verify-side failures with a live invite: another invite's token, an
  // unknown token, an unknown challenge, a challenge from another ceremony,
  // and a response that fails verification.
  await withServe(serveConfig(makeServeRoot()), async (ctx) => {
    const owner = await ownerSession(ctx);
    const live = await createInvite(ctx, owner, 'Live Member');
    const other = await createInvite(ctx, owner, 'Other Member');
    responses['wrong user'] = (await enroll(ctx, live.token, { verifyToken: other.token })).verify;
    const fresh = await inviteOptions(ctx, { token: live.token });
    const good = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(fresh.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin });
    responses['unknown token on verify'] = await post(ctx, '/auth/passkey/invite/verify', { body: { token: Buffer.alloc(32, 7).toString('base64url'), challenge_id: fresh.json.challenge_id, credential: good } });
    responses['unknown challenge'] = await post(ctx, '/auth/passkey/invite/verify', { body: { token: live.token, challenge_id: 'x'.repeat(43), credential: good } });
    const login = await post(ctx, '/auth/passkey/login/options', { body: {} });
    responses['sign-in challenge'] = await post(ctx, '/auth/passkey/invite/verify', { body: { token: live.token, challenge_id: login.json.challenge_id, credential: good } });
    const again = await inviteOptions(ctx, { token: live.token });
    const wrongOrigin = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(again.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: 'http://localhost:1' });
    responses['bad response'] = await post(ctx, '/auth/passkey/invite/verify', { body: { token: live.token, challenge_id: again.json.challenge_id, credential: wrongOrigin } });
    // None of those attempts spent the live invite.
    assert.equal((await enroll(ctx, live.token)).verify.status, 201);
  });

  assert.equal(Object.keys(responses).length, 14);
  for (const [what, res] of Object.entries(responses)) {
    assertInvalid(res, what);
    assert.equal(res.text, responses.spent.text, `${what}: byte-identical body`);
  }
});

test('invites: only an owner passkey session can create, list, or revoke invites', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { invite, token } = await createInvite(ctx, owner);
    const enrolled = await enroll(ctx, token);
    const memberCookie = enrolled.verify.headers['set-cookie'][0].split(';')[0];
    const memberCsrf = (await call({ port: ctx.port, pathname: '/auth/account', cookie: memberCookie })).json.csrf_token;
    const pending = await createInvite(ctx, owner, 'Other Member');
    const tokenCookie = `cockpit_serve=${ctx.token}`;
    const attempts = (cookie, csrf) => [
      call({ port: ctx.port, pathname: '/auth/account/invites', cookie }),
      post(ctx, '/auth/account/invites', { cookie, csrf, body: { display_name: 'Sneaky Member' } }),
      post(ctx, '/auth/account/invites/revoke', { cookie, csrf, body: { invite_id: pending.invite.id } }),
    ];
    for (const res of await Promise.all(attempts(memberCookie, memberCsrf))) {
      assert.equal(res.status, 403, res.text);
      assert.equal(res.json.error.code, 'forbidden');
    }
    for (const res of await Promise.all(attempts(tokenCookie, undefined))) {
      assert.equal(res.status, 401, res.text);
      assert.equal(res.json.error.code, 'session_required');
    }
    for (const res of await Promise.all(attempts(undefined, undefined))) assert.equal(res.status, 401);
    // The owner's request checks still apply.
    const create = (options) => post(ctx, '/auth/account/invites', { cookie: owner.cookie, csrf: owner.csrf, body: { display_name: 'Test Member' }, ...options });
    assert.equal((await create({ csrf: 'f'.repeat(64) })).json.error.code, 'csrf_invalid');
    assert.equal((await create({ origin: 'https://evil.example' })).status, 403);
    assert.equal((await create({ headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
    assert.equal((await create({ headers: { 'Content-Type': 'text/plain' } })).status, 415);
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie, headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
    for (const name of ['', ' Padded', 'x'.repeat(129), 'Zero​width', 42]) {
      const bad = await create({ body: { display_name: name } });
      assert.equal(bad.status, 400, String(name));
      assert.equal(bad.json.error.code, 'invalid_request');
    }
    const list = (await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites;
    assert.deepEqual(list.map((i) => i.id), [pending.invite.id], 'nothing above created or revoked an invite');
    assert.notEqual(invite.id, pending.invite.id);
  });
});

test('invites: at most 32 are pending', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    for (let i = 0; i < 32; i += 1) await createInvite(ctx, owner, `Member ${i}`);
    const full = await post(ctx, '/auth/account/invites', { cookie: owner.cookie, csrf: owner.csrf, body: { display_name: 'One Too Many' } });
    assert.equal(full.status, 409, full.text);
    assert.equal(full.json.error.code, 'too_many_invites');
  });
});

test('invites: a busy identity store returns 503 and keeps the invite for a retry', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token, invite } = await createInvite(ctx, owner);
    const lockFile = `${layout.identityStore}.lock`;
    fs.writeFileSync(lockFile, 'another-writer', { mode: 0o600 });
    try {
      const busy = await enroll(ctx, token);
      assert.equal(busy.verify.status, 503, busy.verify.text);
      assert.equal(busy.verify.json.error.code, 'store_busy');
    } finally {
      fs.rmSync(lockFile, { force: true });
    }
    assert.equal(members(layout).length, 0);
    assert.deepEqual((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites, [invite], 'the invite was put back');
    assert.equal((await enroll(ctx, token)).verify.status, 201);
  });
});

test('invites: the owner can revoke an invite an enrollment has claimed, and the claim cannot bring it back', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token, invite } = await createInvite(ctx, owner);
    const store = inviteStore(layout);
    assert.deepEqual(store.spend(token, invite.id), invite);
    assert.deepEqual((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites, [], 'a claimed invite is not listed');
    assertInvalid(await inviteOptions(ctx, { token }), 'a claimed invite looks unknown');
    const done = await post(ctx, '/auth/account/invites/revoke', { cookie: owner.cookie, csrf: owner.csrf, body: { invite_id: invite.id } });
    assert.equal(done.status, 200, done.text);
    assert.deepEqual(done.json, { revoked: true });
    assert.equal(store.restore(token, invite.id), false);
    assertInvalid(await inviteOptions(ctx, { token }), 'revoked');
  });
});

// The server blocks on the identity lock for a second; another process
// revokes the invite during that wait, while the enrollment holds its claim.
test('invites: a revoke from another process during a failed enrollment wins, and the revoked link stays invalid', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token, invite } = await createInvite(ctx, owner);
    const store = inviteStore(layout);
    // A second challenge for the same invite, to try the link again after the revoke.
    const spare = await inviteOptions(ctx, { token });
    assert.equal(spare.status, 200, spare.text);

    const url = new URL('../skill/lib/identity/invites.mjs', import.meta.url).href;
    const script = `
      import fs from 'node:fs';
      import { openInviteStore } from ${JSON.stringify(url)};
      const [file, root, inviteId] = process.argv.slice(1);
      const pause = new Int32Array(new SharedArrayBuffer(4));
      process.stdout.write('ready;');
      const deadline = Date.now() + 20000;
      const claimed = () => {
        try {
          return JSON.parse(fs.readFileSync(file, 'utf8')).invites.some((i) => i.id === inviteId && i.claimed_at);
        } catch {
          return false;
        }
      };
      while (!claimed()) {
        if (Date.now() > deadline) process.exit(2);
        Atomics.wait(pause, 0, 0, 5);
      }
      process.stdout.write(JSON.stringify(openInviteStore({ file, root }).revoke(inviteId)));`;
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, store.file, layout.root, invite.id], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const exited = new Promise((resolve) => child.on('exit', resolve));
    await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('exit', (code) => reject(new Error(`revoker exited ${code} before it was ready: ${stderr}`)));
      child.stdout.on('data', (chunk) => {
        stdout += chunk;
        if (stdout.startsWith('ready;')) resolve();
      });
    });

    const lockFile = `${layout.identityStore}.lock`;
    fs.writeFileSync(lockFile, 'another-writer', { mode: 0o600 });
    let busy;
    try {
      busy = await enroll(ctx, token);
    } finally {
      fs.rmSync(lockFile, { force: true });
    }
    const code = await exited;
    assert.equal(code, 0, `revoker exited ${code}: ${stderr}`);
    assert.equal(busy.verify.status, 503, busy.verify.text);
    assert.equal(busy.verify.json.error.code, 'store_busy');
    assert.deepEqual(JSON.parse(stdout.slice('ready;'.length)), invite, 'the revoke found the claimed invite');

    assert.deepEqual(store.load().invites, [], 'the restore did not bring it back');
    assertInvalid(await inviteOptions(ctx, { token }), 'revoked link, new options');
    const response = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(spare.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin });
    assertInvalid(await post(ctx, '/auth/passkey/invite/verify', { body: { token, challenge_id: spare.json.challenge_id, credential: response } }), 'revoked link, earlier challenge');
    assert.equal(members(layout).length, 0);
  });
});

test('invites: a full identity store returns 507, creates no user, and keeps the invite for a retry', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token, invite } = await createInvite(ctx, owner);
    // Fill the identity store to just under its cap with invented members.
    const doc = JSON.parse(fs.readFileSync(layout.identityStore, 'utf8'));
    const bytes = () => Buffer.byteLength(`${JSON.stringify(doc, null, 2)}\n`);
    const credential = (idBytes, keyBytes) => ({
      id: crypto.randomBytes(idBytes).toString('base64url'),
      public_key: Buffer.concat([Buffer.from([0xa5]), crypto.randomBytes(keyBytes - 1)]).toString('base64url'),
      counter: 0, transports: ['usb'], created_at: doc.users[0].created_at, label: 'Test key',
    });
    const fill = (idBytes, keyBytes) => {
      for (let index = 0; ; index += 1) {
        let user = doc.users.at(-1);
        if (user.role === 'owner' || user.credentials.length === 32) {
          user = { id: `usr_filler${String(doc.users.length).padStart(4, '0')}`, display_name: 'Filler Member', role: 'member', disabled: false, created_at: doc.users[0].created_at, credentials: [] };
          doc.users.push(user);
        }
        user.credentials.push(credential(idBytes, keyBytes));
        if ((idBytes > 100 ? index * 4400 > MAX_FILE_BYTES - 64 * 1024 : true) && bytes() > MAX_FILE_BYTES) {
          user.credentials.pop();
          if (user.credentials.length === 0) doc.users.pop();
          return;
        }
      }
    };
    fill(1023, 2048);
    fill(16, 64);
    fs.writeFileSync(layout.identityStore, JSON.stringify(doc, null, 2));
    const before = members(layout).length;

    const full = await enroll(ctx, token);
    assert.equal(full.verify.status, 507, full.verify.text);
    assert.equal(full.verify.json.error.code, 'store_full');
    assert.equal(full.verify.headers['set-cookie'], undefined);
    assert.equal(members(layout).length, before, 'no user was created');
    assert.equal(findUser(identity(layout).load(), invite.user_id), null);
    assert.deepEqual((await call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie })).json.invites, [invite], 'the invite was put back');

    // Make room, then the same link enrolls.
    doc.users = doc.users.filter((user) => user.role === 'owner');
    fs.writeFileSync(layout.identityStore, JSON.stringify(doc, null, 2));
    const retry = await enroll(ctx, token);
    assert.equal(retry.verify.status, 201, retry.verify.text);
    assert.equal(retry.verify.json.user_id, invite.user_id);
  });
});

test('invites: if no session can be created, the enrollment still stands and the member signs in later', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const { token, invite } = await createInvite(ctx, owner);
    const lockFile = `${layout.sessionStore}.lock`;
    fs.writeFileSync(lockFile, 'another-writer', { mode: 0o600 });
    let enrolled;
    try {
      enrolled = await enroll(ctx, token);
    } finally {
      fs.rmSync(lockFile, { force: true });
    }
    assert.equal(enrolled.verify.status, 201, enrolled.verify.text);
    assert.deepEqual(enrolled.verify.json, { enrolled: true, signed_in: false, user_id: invite.user_id });
    assert.equal(enrolled.verify.headers['set-cookie'], undefined);
    assert.equal(members(layout).length, 1);
    assertInvalid(await inviteOptions(ctx, { token }), 'the invite is spent');
    await signIn(ctx, enrolled.credential, invite.user_id);
  });
});

test('invites: the invite page is served before auth with the login page headers and no inline code', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port }) => {
    const page = await call({ port, pathname: '/auth/invite/' });
    const login = await call({ port, pathname: '/auth/login/' });
    assert.equal(page.status, 200);
    assert.equal(page.headers['content-type'], 'text/html; charset=utf-8');
    for (const header of ['content-security-policy', 'x-frame-options', 'referrer-policy', 'cache-control', 'x-content-type-options']) {
      assert.equal(page.headers[header], login.headers[header], header);
    }
    assert.equal(page.headers['referrer-policy'], 'no-referrer');
    assert.equal(page.headers['x-frame-options'], 'DENY');
    assert.match(page.headers['content-security-policy'], /default-src 'none'; script-src 'self';/);
    assert.match(page.text, /<meta name="referrer" content="no-referrer">/);
    assert.doesNotMatch(page.text, /<script(?![^>]*\bsrc=)[^>]*>/);
    assert.doesNotMatch(page.text, /\son[a-z]+\s*=|\sstyle\s*=/i);
    for (const [, ref] of page.text.matchAll(/(?:src|href)="([^"]+)"/g)) assert.match(ref, /^\/auth\/(login|invite)\//);

    const js = await call({ port, pathname: '/auth/invite/cockpit-invite.js' });
    assert.equal(js.status, 200);
    assert.equal(js.headers['content-security-policy'], login.headers['content-security-policy']);
    assert.doesNotMatch(js.text, /https?:\/\/|\beval\(|new Function|innerHTML|outerHTML|insertAdjacentHTML|console\.|localStorage|sessionStorage|document\.cookie/);
    // The fragment is stripped before any request, and the token goes only in POST bodies.
    const strip = js.text.indexOf('history.replaceState(');
    assert.ok(strip > 0 && strip < js.text.indexOf('fetch('), 'replaceState runs before any fetch');
    assert.doesNotMatch(js.text, /[?&]token=|searchParams/);
    assert.match(js.text, /method: 'POST'/);

    assert.equal((await call({ port, pathname: '/auth/invite' })).headers.location, '/auth/invite/');
    assert.equal((await call({ port, method: 'POST', pathname: '/auth/invite/' })).status, 405);
    assert.equal((await call({ port, pathname: '/' })).status, 401, 'other pages still need auth');
  });
});

test('invites: the settings page invite section builds with textContent only and loads nothing else', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async ({ port }) => {
    const page = await call({ port, pathname: '/auth/settings/' });
    assert.match(page.text, /id="invites-section" hidden/);
    const js = await call({ port, pathname: '/auth/settings/cockpit-settings.js' });
    assert.match(js.text, /'\/invites\/revoke'/);
    assert.doesNotMatch(js.text, /innerHTML|outerHTML|insertAdjacentHTML|console\.|localStorage|sessionStorage/);
  });
});

test('invites: the token never appears in log lines or in any response except the create response', async () => {
  const layout = makeServeRoot();
  const lines = [];
  const clock = { at: Date.now() };
  await withServe(serveConfig(layout), async (ctx) => {
    const owner = await ownerSession(ctx);
    const created = await createInvite(ctx, owner);
    const { token } = created;
    const other = await createInvite(ctx, owner, 'Other Member');
    const seen = [];
    const record = async (promise) => {
      const res = await promise;
      seen.push(res);
      return res;
    };
    await record(call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie }));
    await record(inviteOptions(ctx, { token: `${token}x` }));
    seen.push((await enroll(ctx, token, { verifyToken: other.token })).verify);
    seen.push((await enroll(ctx, other.token, { verifyToken: token })).verify);
    const bad = await record(inviteOptions(ctx, { token }));
    const response = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(bad.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: 'http://localhost:1' });
    await record(post(ctx, '/auth/passkey/invite/verify', { body: { token, challenge_id: bad.json.challenge_id, credential: response } }));
    const done = await enroll(ctx, token);
    seen.push(done.options, done.verify);
    await record(post(ctx, '/auth/passkey/invite/verify', { body: done.body }));
    await record(inviteOptions(ctx, { token }));
    clock.at += 25 * HOUR;
    await record(inviteOptions(ctx, { token: other.token }));
    await record(call({ port: ctx.port, pathname: '/auth/account/invites', cookie: owner.cookie }));
    await record(call({ port: ctx.port, pathname: '/auth/invite/' }));

    assert.ok(seen.length >= 10);
    for (const res of seen) {
      const all = `${res.text}${JSON.stringify(res.headers)}`;
      for (const secret of [token, other.token, hashToken(token), hashToken(other.token)]) assert.ok(!all.includes(secret), `response ${res.status} leaks a token`);
    }
    assert.ok(lines.length > 0, 'the failures above were logged');
    for (const line of lines) {
      for (const secret of [token, other.token, hashToken(token), hashToken(other.token)]) assert.ok(!line.includes(secret), `log line leaks a token: ${line}`);
      assert.match(line, /^[a-z ]+[a-z_]+( \([a-z_]+\))?$/, `log lines are codes only: ${line}`);
    }
  }, { log: (line) => lines.push(line), now: () => clock.at });
});

// The real CLI: everything the server writes to stderr and stdout during a
// full invite flow, including failed attempts, is free of the token.
test('invites: serve.mjs never writes an invite token or its hash to stderr or stdout', async () => {
  const layout = makeServeRoot();
  const script = path.resolve(import.meta.dirname, '..', 'skill', 'scripts', 'serve.mjs');
  // A non-interactive start does not create the recovery token; create it as an operator would.
  const { token: recoveryToken } = openRecoveryStore({ file: path.join(layout.base, 'state', 'recovery.json'), root: layout.root }).ensure();
  const child = spawn(process.execPath, [script, '--passkeys', '--identity-store', layout.identityStore, '--port', '0'], {
    env: layout.env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const exited = new Promise((resolve) => child.on('exit', resolve));
  try {
    const url = await new Promise((resolve, reject) => {
      child.stdout.on('data', (chunk) => {
        stdout += chunk;
        const match = stdout.match(/Serving: (http:\/\/\S+)/);
        if (match && stdout.includes('Devices, invites, and sign out:')) resolve(new URL(match[1]));
      });
      child.on('exit', () => reject(new Error(`serve.mjs exited: ${stderr}`)));
    });
    const port = Number(url.port);
    const ctx = { port, recoveryToken, origin: `http://localhost:${port}` };
    const owner = await ownerSession(ctx);
    const a = await createInvite(ctx, owner);
    const b = await createInvite(ctx, owner, 'Other Member');
    assertInvalid((await enroll(ctx, a.token, { verifyToken: b.token })).verify, 'mismatched');
    assertInvalid(await inviteOptions(ctx, { token: `${a.token}x` }), 'malformed');
    const options = await inviteOptions(ctx, { token: a.token });
    const wrongOrigin = registrationResponse({ credential: makeCredential(), challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: 'http://localhost:1' });
    assertInvalid(await post(ctx, '/auth/passkey/invite/verify', { body: { token: a.token, challenge_id: options.json.challenge_id, credential: wrongOrigin } }), 'bad response');
    const done = await enroll(ctx, a.token);
    assert.equal(done.verify.status, 201, done.verify.text);
    assertInvalid(await post(ctx, '/auth/passkey/invite/verify', { body: done.body }), 'replay');

    child.kill('SIGTERM');
    await exited;
    assert.match(stderr, /invite_invalid/, 'the refusals were logged');
    for (const secret of [a.token, b.token, hashToken(a.token), hashToken(b.token), recoveryToken, hashToken(recoveryToken)]) {
      assert.ok(!stderr.includes(secret), 'stderr leaks a token');
      assert.ok(!stdout.includes(secret), 'stdout leaks a token');
    }
  } finally {
    child.kill('SIGKILL');
  }
});

// ---------------------------------------------------------------------------
// Rate limits and challenge capacity (fake rate-limit clock, real ceremonies)

const apiRequest = (api, pathname, { body = {}, cookie } = {}) => new Promise((resolve, reject) => {
  const server = http.createServer((req, res) => {
    if (!api.handle(req, res)) { res.writeHead(404); res.end(); }
  });
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    const req = http.request({
      hostname: '127.0.0.1', port, path: pathname, method: 'POST', headers: { Origin: 'https://example.com', 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
    }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => server.close(() => resolve({ status: res.statusCode, json: text ? JSON.parse(text) : null })));
    });
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
});

const apiSetup = () => {
  const layout = makeServeRoot();
  const store = openIdentityStore({ file: layout.identityStore, root: layout.root });
  store.createUser({ id: OWNER_ID, displayName: 'Ada Example', role: 'owner' });
  const invites = openInviteStore({ file: path.join(layout.base, 'state', 'invites.json'), root: layout.root });
  const ceremonies = createPasskeyCeremonies({ store, rpId: 'example.com', origins: ['https://example.com'], invites, challenges: createChallengeStore() });
  const clock = { at: 0 };
  const api = createPasskeyApi({
    ceremonies,
    allowedOrigins: () => ['https://example.com'],
    authorizeRegistration: (req) => (req.headers.cookie === 'operator' ? { userId: OWNER_ID, sessionId: 'ses_EXAMPLEonlyAAAAAAAAAAA' } : null),
    onSignIn: () => ({}),
    now: () => clock.at,
  });
  return { api, invites, clock };
};

test('invites: invite traffic has its own rate-limit buckets: draining them leaves sign-in and registration alone, and the reverse', async () => {
  const { api, invites } = apiSetup();
  const { token } = invites.create({ displayName: 'Test Member', createdBy: OWNER_ID });
  // Failed invite lookups empty the invite failures bucket...
  const statuses = [];
  for (let i = 0; i < 11; i += 1) statuses.push((await apiRequest(api, '/auth/passkey/invite/options', { body: { token: 'A'.repeat(43) } })).status);
  assert.deepEqual(statuses, [...Array(10).fill(400), 429]);
  assert.equal((await apiRequest(api, '/auth/passkey/invite/options', { body: { token } })).status, 429, 'even a valid token waits');
  // ...but sign-in and registration options still work.
  assert.equal((await apiRequest(api, '/auth/passkey/login/options')).status, 200);
  assert.equal((await apiRequest(api, '/auth/passkey/register/options', { cookie: 'operator' })).status, 200);

  // Draining the sign-in buckets does not limit invites.
  const other = apiSetup();
  const fresh = other.invites.create({ displayName: 'Test Member', createdBy: OWNER_ID });
  for (let i = 0; i < 11; i += 1) await apiRequest(other.api, '/auth/passkey/login/options');
  assert.equal((await apiRequest(other.api, '/auth/passkey/login/options')).status, 429);
  const badSignIn = { challenge_id: 'x'.repeat(43), credential: { rawId: 'AAAA' } };
  for (let i = 0; i < 11; i += 1) await apiRequest(other.api, '/auth/passkey/login/verify', { body: badSignIn });
  assert.equal((await apiRequest(other.api, '/auth/passkey/login/verify', { body: badSignIn })).status, 429);
  assert.equal((await apiRequest(other.api, '/auth/passkey/invite/options', { body: { token: fresh.token } })).status, 200);
  // Invite options have their own options bucket too.
  const optionStatuses = [];
  for (let i = 0; i < 11; i += 1) optionStatuses.push((await apiRequest(other.api, '/auth/passkey/invite/options', { body: { token: fresh.token } })).status);
  assert.equal(optionStatuses.at(-1), 429);
  assert.equal((await apiRequest(other.api, '/auth/passkey/register/options', { cookie: 'operator' })).status, 200);
});

test('invites: bad tokens on invite options spend the failures bucket that also limits invite verify', async () => {
  const { api } = apiSetup();
  const statuses = [];
  for (let i = 0; i < 10; i += 1) statuses.push((await apiRequest(api, '/auth/passkey/invite/options', { body: { token: 'A'.repeat(43) } })).status);
  assert.deepEqual(statuses, Array(10).fill(400));
  const junk = { token: 'B'.repeat(43), challenge_id: 'x'.repeat(43), credential: { rawId: 'AAAA' } };
  const verify = await apiRequest(api, '/auth/passkey/invite/verify', { body: junk });
  assert.equal(verify.status, 429, JSON.stringify(verify.json));

  // A fresh server answers the same junk verify with the generic error.
  const fresh = apiSetup();
  assert.equal((await apiRequest(fresh.api, '/auth/passkey/invite/verify', { body: junk })).status, 400);
});

test('invites: invitation challenges have their own cap: filling it leaves sign-in and registration alone, and the reverse', async () => {
  const { api, invites, clock } = apiSetup();
  const { token } = invites.create({ displayName: 'Test Member', createdBy: OWNER_ID });
  let issued = 0;
  for (;;) {
    clock.at += 2000;
    const res = await apiRequest(api, '/auth/passkey/invite/options', { body: { token } });
    if (res.status === 503) {
      assert.equal(res.json.error.code, 'too_many_challenges');
      break;
    }
    assert.equal(res.status, 200);
    issued += 1;
  }
  assert.equal(issued, DEFAULT_MAX_CHALLENGES);
  clock.at += 60000;
  assert.equal((await apiRequest(api, '/auth/passkey/login/options')).status, 200);
  assert.equal((await apiRequest(api, '/auth/passkey/register/options', { cookie: 'operator' })).status, 200);

  const other = apiSetup();
  const fresh = other.invites.create({ displayName: 'Test Member', createdBy: OWNER_ID });
  for (;;) {
    other.clock.at += 2000;
    if ((await apiRequest(other.api, '/auth/passkey/login/options')).status === 503) break;
  }
  other.clock.at += 60000;
  assert.equal((await apiRequest(other.api, '/auth/passkey/invite/options', { body: { token: fresh.token } })).status, 200);
});

// ---------------------------------------------------------------------------
// Config

test('serve config: --invite-lifetime is validated, needs --passkeys, and the invites file sits next to the identity store', () => {
  const layout = makeServeRoot();
  const parse = (argv) => parseServeConfig({ argv: ['--identity-store', layout.identityStore, ...argv], env: layout.env });
  assert.equal(parse(['--passkeys']).inviteLifetimeMs, 24 * HOUR);
  assert.equal(parse(['--passkeys']).inviteStore, path.join(layout.base, 'state', 'invites.json'));
  assert.equal(parse(['--passkeys', '--invite-lifetime', '3d']).inviteLifetimeMs, 72 * HOUR);
  assert.equal(parse(['--passkeys', '--invite-lifetime=2h']).inviteLifetimeMs, 2 * HOUR);
  assert.equal(parse(['--passkeys', '--invite-lifetime', '5m']).inviteLifetimeMs, 5 * 60 * 1000);
  assert.equal(parse(['--passkeys', '--invite-lifetime', '7d']).inviteLifetimeMs, 7 * 24 * HOUR);
  for (const bad of ['4m', '8d', '169h', '24', '1.5h', '0h', '-1h', '24H', '1w', 'never']) {
    assert.throws(() => parse(['--passkeys', `--invite-lifetime=${bad}`]), /--invite-lifetime must be .* from 5m to 7d/, bad);
  }
  assert.throws(() => parse(['--invite-lifetime', '24h']), /--invite-lifetime requires --passkeys/);
  assert.equal(parse([]).inviteStore, null);
  assert.equal(parse([]).inviteLifetimeMs, null);
  const clash = path.join(layout.base, 'state', 'invites.json');
  assert.throws(() => parseServeConfig({ argv: ['--passkeys', '--identity-store', clash], env: layout.env }), /must not be named invites\.json/);
});
