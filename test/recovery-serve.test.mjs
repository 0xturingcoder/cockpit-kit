// The owner's recovery token and passkey step-up in serve.mjs --passkeys, end
// to end: token sign-in creating an owner-only recovery session, the step-up
// gate on registration and invites (no step-up, stale, fresh), step-up
// binding, member precedence, the account API from a recovery session, rate
// limits, the audit log, rotation, --recovery-enroll, the CLI, and the token
// staying out of responses, logs, and files. Credentials are synthetic,
// generated at runtime; users are invented.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { openRecoveryStore } from '../skill/lib/identity/recovery.mjs';
import { hashToken, openSessionStore } from '../skill/lib/identity/sessions.mjs';
import { DEFAULT_STEP_UP_WINDOW_MS, requireFreshStepUp } from '../skill/lib/identity/session-http.mjs';
import { openIdentityStore } from '../skill/lib/identity/store.mjs';
import { parseServeConfig } from '../skill/lib/serve-config.mjs';
import { rotateRecoveryToken } from '../skill/scripts/serve.mjs';
import { makeCredential } from './support/webauthn-synthetic.mjs';
import {
  accountOf, addPasskey, call, makeServeRoot, recoverySignIn, registerOwner, serveConfig, sessionPost, signIn, stepUp, withServe,
} from './support/serve-harness.mjs';

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const serveScript = path.resolve(import.meta.dirname, '..', 'skill', 'scripts', 'serve.mjs');

const statePath = (layout, name) => path.join(layout.base, 'state', name);
const readAudit = (layout) => JSON.parse(fs.readFileSync(statePath(layout, 'audit.json'), 'utf8'));
const clockFrom = (at = Date.now()) => {
  const clock = { at };
  clock.now = () => clock.at;
  return clock;
};

// Owner with one passkey and a passkey session, plus a member with a passkey session.
const setup = async (ctx, layout) => {
  const ownerKey = makeCredential();
  const owner = await registerOwner(ctx, ownerKey, { label: 'Work laptop' });
  const ownerSession = await signIn(ctx, ownerKey, owner.user_id);
  const store = openIdentityStore({ file: layout.identityStore, root: layout.root });
  const member = store.createUser({ displayName: 'Test Member' });
  const memberKey = makeCredential();
  store.addCredential(member.id, { id: memberKey.rawId, publicKey: memberKey.cose, label: 'Member phone' });
  const memberSession = await signIn(ctx, memberKey, member.id);
  return {
    store,
    ownerKey,
    ownerId: owner.user_id,
    ownerCredentialId: owner.credential_id,
    owner: { cookie: ownerSession.cookie, csrf: (await accountOf(ctx, ownerSession.cookie)).csrf_token },
    member,
    memberKey,
    memberSession: { cookie: memberSession.cookie, csrf: (await accountOf(ctx, memberSession.cookie)).csrf_token },
  };
};

const recovery = async (ctx) => {
  const { res, cookie } = await recoverySignIn(ctx);
  assert.equal(res.status, 200, res.text);
  return { res, cookie, csrf: (await accountOf(ctx, cookie)).csrf_token };
};

const createInvite = (ctx, session, displayName = 'New Member') => sessionPost(ctx, '/auth/account/invites', { ...session, body: { display_name: displayName } });

const assertStepUpRequired = (res, what) => {
  assert.equal(res.status, 403, `${what}: ${res.text}`);
  assert.deepEqual(res.json, { error: { code: 'step_up_required', message: 'Confirm with your passkey first.' } }, what);
};

// ---------------------------------------------------------------------------
// The gate itself (#13 uses it for delegation approve and revoke)

test('requireFreshStepUp: recovery with no step-up, stale, and fresh; passkey stale and fresh; future times refused', () => {
  const now = Date.parse('2026-05-06T07:08:09.000Z');
  const windowMs = DEFAULT_STEP_UP_WINDOW_MS;
  const at = (ms) => new Date(ms).toISOString();
  const session = (kind, stepUpAt) => ({ session: { kind, step_up_at: stepUpAt } });
  const refused = (signedIn) => assert.throws(() => requireFreshStepUp(signedIn, { now, windowMs }), { status: 403, code: 'step_up_required' });
  refused(session('recovery', null));
  refused(session('recovery', at(now - windowMs - 1)));
  requireFreshStepUp(session('recovery', at(now - windowMs)), { now, windowMs });
  requireFreshStepUp(session('recovery', at(now)), { now, windowMs });
  refused(session('passkey', at(now - windowMs - 1)));
  requireFreshStepUp(session('passkey', at(now - 1000)), { now, windowMs });
  refused(session('passkey', at(now + 1000)));
  refused(session('passkey', 'not a time'));
  refused(undefined);
  assert.equal(windowMs, 5 * MINUTE);
});

// ---------------------------------------------------------------------------
// Token sign-in

test('recovery: token sign-in maps only to the owner and creates a recovery session (12 hours at most) that lists and can be revoked', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerId, owner } = await setup(ctx, layout);
    const { res, cookie, csrf } = await recovery(ctx);
    assert.deepEqual(res.json, { signed_in: true, user_id: ownerId, recovery: true });
    assert.match(res.headers['set-cookie'][0], /^cockpit_session=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Strict; Path=\/; Max-Age=43200$/);
    assert.ok(!res.text.includes(ctx.recoveryToken) && !JSON.stringify(res.headers).includes(ctx.recoveryToken));

    const view = await accountOf(ctx, cookie);
    assert.equal(view.user.id, ownerId);
    assert.equal(view.user.role, 'owner');
    const current = view.sessions.find((s) => s.current);
    assert.equal(current.kind, 'recovery');
    assert.equal(current.credential_id, null);
    assert.equal(current.step_up_at, null);
    assert.equal(current.label, 'Recovery (server token)');
    assert.equal(Date.parse(current.expires_at) - Date.parse(current.created_at), 12 * HOUR);
    // Pages work with the recovery session.
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 200);

    // The owner's passkey session sees it and can revoke it; that browser is then signed out.
    const listed = (await accountOf(ctx, owner.cookie)).sessions.find((s) => s.kind === 'recovery');
    assert.equal(listed.id, current.id);
    const revoked = await sessionPost(ctx, '/auth/account/sessions/revoke', { ...owner, body: { session_id: current.id } });
    assert.equal(revoked.status, 200, revoked.text);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie })).status, 401, 'revoking the recovery session signs that browser out');
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account', cookie })).status, 401);
    void csrf;
  });
});

test('recovery: a shorter --session-lifetime also caps recovery sessions', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout, ['--session-lifetime', '2h']), async (ctx) => {
    await registerOwner(ctx, makeCredential());
    const { res } = await recovery(ctx);
    assert.match(res.headers['set-cookie'][0], /Max-Age=7200$/);
  });
});

test('recovery: a wrong, malformed, or missing token gets one error, and no owner yet gets 409 no_owner', async () => {
  await withServe(serveConfig(makeServeRoot()), async (ctx) => {
    const noOwner = await recoverySignIn(ctx);
    assert.equal(noOwner.res.status, 409);
    assert.equal(noOwner.res.json.error.code, 'no_owner');
    assert.equal(noOwner.cookie, null);
  });
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    // Creating the owner takes two attempts from the shared bucket of five.
    await registerOwner(ctx, makeCredential());
    const wrong = [];
    for (const token of [ctx.token, hashToken(ctx.recoveryToken)]) wrong.push((await recoverySignIn(ctx, { token })).res);
    wrong.push(await call({ port: ctx.port, method: 'POST', pathname: '/auth/passkey/recovery/sign-in', body: {}, origin: ctx.origin }));
    for (const res of wrong) {
      assert.equal(res.status, 401, res.text);
      assert.deepEqual(res.json, { error: { code: 'recovery_failed', message: 'The recovery token is not valid.' } });
      assert.equal(res.headers['set-cookie'], undefined);
    }
    // Origin and query checks come first.
    const crossSite = await call({ port: ctx.port, method: 'POST', pathname: '/auth/passkey/recovery/sign-in', body: { token: ctx.recoveryToken }, origin: 'https://evil.example' });
    assert.equal(crossSite.status, 403);
    const query = await call({ port: ctx.port, method: 'POST', pathname: `/auth/passkey/recovery/sign-in?token=${ctx.recoveryToken}`, body: {}, origin: ctx.origin });
    assert.equal(query.status, 400);
  });
});

test('recovery: attempts are rate limited (5 at once) with Retry-After, and each one is audited with time, event, and result only', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    await registerOwner(ctx, makeCredential());
    const statuses = [];
    for (let i = 0; i < 3; i += 1) statuses.push((await recoverySignIn(ctx, { token: 'A'.repeat(43) })).res.status);
    statuses.push((await recoverySignIn(ctx)).res.status);
    // registerOwner took two attempts from the shared bucket (options and verify).
    const limited = await recoverySignIn(ctx);
    assert.deepEqual(statuses, [401, 401, 401, 429]);
    assert.equal(limited.res.status, 429);
    assert.equal(limited.res.json.error.code, 'rate_limited');
    assert.ok(Number(limited.res.headers['retry-after']) >= 1);
    assert.equal(limited.cookie, null, 'even the right token waits');

    const audit = readAudit(layout);
    assert.deepEqual(audit.events.map((e) => [e.event, e.result]), [
      ['first_owner', 'ok'], ['token_sign_in', 'invalid'], ['token_sign_in', 'invalid'], ['token_sign_in', 'invalid'], ['token_sign_in', 'rate_limited'],
    ], 'rate_limited is written at most once a minute');
    for (const entry of audit.events) assert.deepEqual(Object.keys(entry), ['at', 'event', 'result']);
    const text = fs.readFileSync(statePath(layout, 'audit.json'), 'utf8');
    for (const secret of [ctx.recoveryToken, hashToken(ctx.recoveryToken), '127.0.0.1', 'localhost']) assert.ok(!text.includes(secret), secret);
  });
});

test('recovery: 40 minutes of bad attempts against the bucket cannot push a successful sign-in out of the audit log', async () => {
  const layout = makeServeRoot();
  const clock = clockFrom(Date.parse('2026-03-04T05:06:00.000Z'));
  const start = clock.at;
  await withServe(serveConfig(layout), async (ctx) => {
    await registerOwner(ctx, makeCredential());
    const rec = await recovery(ctx);
    const MINUTES = 40;
    for (let minute = 1; minute <= MINUTES; minute += 1) {
      clock.at = start + minute * MINUTE;
      const statuses = [];
      for (let i = 0; i < 7; i += 1) statuses.push((await recoverySignIn(ctx, { token: 'A'.repeat(43) })).res.status);
      assert.deepEqual(statuses, [401, 401, 401, 401, 401, 429, 429], `minute ${minute}`);
      assert.ok(readAudit(layout).events.length <= 200, `minute ${minute}: the log stays bounded`);
    }
    const res = await call({ port: ctx.port, pathname: '/auth/account/audit', cookie: rec.cookie });
    assert.equal(res.status, 200, res.text);
    const { events } = res.json;
    assert.equal(events.length, 200);
    assert.deepEqual(events.slice(-2).map((e) => `${e.event}:${e.result}`), ['token_sign_in:ok', 'first_owner:ok'], 'the successful entries survive');
    const failures = events.filter((e) => e.result === 'invalid' || e.result === 'rate_limited');
    // 6 failures written a minute for 40 minutes is 240; the newest 198 are kept,
    // so the oldest 7 minutes are gone.
    assert.equal(failures.length, 198);
    assert.deepEqual(failures[0], { at: new Date(start + MINUTES * MINUTE).toISOString(), event: 'token_sign_in', result: 'rate_limited' });
    assert.deepEqual(failures.at(-1), { at: new Date(start + 8 * MINUTE).toISOString(), event: 'token_sign_in', result: 'invalid' });
  }, { now: clock.now });
});

test('recovery: the owner sees the audit log in the account API, newest first; members cannot', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { owner, memberSession } = await setup(ctx, layout);
    await recoverySignIn(ctx, { token: 'B'.repeat(43) });
    const rec = await recovery(ctx);
    for (const cookie of [owner.cookie, rec.cookie]) {
      const res = await call({ port: ctx.port, pathname: '/auth/account/audit', cookie });
      assert.equal(res.status, 200, res.text);
      assert.deepEqual(res.json.events.map((e) => `${e.event}:${e.result}`), ['token_sign_in:ok', 'token_sign_in:invalid', 'first_owner:ok']);
      assert.ok(!res.text.includes(ctx.recoveryToken));
      assert.equal(res.headers['cache-control'], 'no-store');
    }
    const member = await call({ port: ctx.port, pathname: '/auth/account/audit', cookie: memberSession.cookie });
    assert.equal(member.status, 403);
    assert.equal((await call({ port: ctx.port, pathname: '/auth/account/audit' })).status, 401);
  });
});

test('recovery: a successful sign-in that cannot be audited is refused with 503 and creates no session', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    await registerOwner(ctx, makeCredential());
    const lockFile = `${statePath(layout, 'audit.json')}.lock`;
    fs.writeFileSync(lockFile, 'another-writer', { mode: 0o600 });
    try {
      const { res, cookie } = await recoverySignIn(ctx);
      assert.equal(res.status, 503, res.text);
      assert.equal(res.json.error.code, 'audit_unavailable');
      assert.equal(cookie, null);
    } finally {
      fs.rmSync(lockFile, { force: true });
    }
    const sessions = openSessionStore({ file: layout.sessionStore, root: layout.root });
    assert.deepEqual(sessions.list().filter((s) => s.kind === 'recovery'), []);
  });
});

// ---------------------------------------------------------------------------
// Step-up gate

test('recovery: a recovery session cannot add a passkey or create an invite without a step-up, with a stale one, and can with a fresh one', async () => {
  const layout = makeServeRoot();
  const clock = clockFrom();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId, store } = await setup(ctx, layout);
    const rec = await recovery(ctx);

    // No step-up.
    assertStepUpRequired((await addPasskey(ctx, rec, makeCredential())).options, 'register options, no step-up');
    assertStepUpRequired(await sessionPost(ctx, '/auth/passkey/register/verify', { ...rec, body: { challenge_id: 'x'.repeat(43), credential: {} } }), 'register verify, no step-up');
    assertStepUpRequired(await createInvite(ctx, rec), 'invite, no step-up');

    // Fresh step-up: both work.
    const done = await stepUp(ctx, rec, ownerKey, ownerId);
    assert.equal(done.status, 200, done.text);
    assert.equal(done.json.stepped_up, true);
    assert.equal(done.json.step_up_at, new Date(clock.at).toISOString());
    const added = await addPasskey(ctx, rec, makeCredential(), { label: 'Spare key' });
    assert.equal(added.options.status, 200, added.options.text);
    assert.equal(added.verify.status, 201, added.verify.text);
    assert.equal(added.verify.json.user_id, ownerId);
    assert.equal(store.load().users.find((u) => u.id === ownerId).credentials.length, 2);
    assert.equal((await createInvite(ctx, rec)).status, 201);

    // Stale step-up: the clock moves past the 5-minute window.
    clock.at += 5 * MINUTE + 1000;
    assertStepUpRequired((await addPasskey(ctx, rec, makeCredential())).options, 'register options, stale');
    assertStepUpRequired(await createInvite(ctx, rec), 'invite, stale');
    assert.equal(store.load().users.find((u) => u.id === ownerId).credentials.length, 2, 'nothing was added');

    // Options issued while fresh cannot be finished once the step-up is stale.
    assert.equal((await stepUp(ctx, rec, ownerKey, ownerId)).status, 200);
    const early = await sessionPost(ctx, '/auth/passkey/register/options', rec);
    assert.equal(early.status, 200);
    clock.at += 5 * MINUTE + 1000;
    assertStepUpRequired(await sessionPost(ctx, '/auth/passkey/register/verify', { ...rec, body: { challenge_id: early.json.challenge_id, credential: {} } }), 'verify after it went stale');
  }, { now: clock.now });
});

test('recovery: a passkey session counts as stepped up when it signs in; once stale it must step up again', async () => {
  const layout = makeServeRoot();
  const clock = clockFrom();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId, owner } = await setup(ctx, layout);
    assert.equal((await addPasskey(ctx, owner, makeCredential())).verify.status, 201, 'fresh from sign-in');
    clock.at += 5 * MINUTE + 1000;
    assertStepUpRequired((await addPasskey(ctx, owner, makeCredential())).options, 'stale passkey session');
    assertStepUpRequired(await createInvite(ctx, owner), 'stale passkey session invite');
    assert.equal((await stepUp(ctx, owner, ownerKey, ownerId)).status, 200);
    assert.equal((await createInvite(ctx, owner)).status, 201);
  }, { now: clock.now });
});

test('recovery: --step-up-window changes the window', async () => {
  const layout = makeServeRoot();
  const clock = clockFrom();
  await withServe(serveConfig(layout, ['--step-up-window', '1m']), async (ctx) => {
    const { owner } = await setup(ctx, layout);
    clock.at += 59 * 1000;
    assert.equal((await createInvite(ctx, owner)).status, 201);
    clock.at += 2000;
    assertStepUpRequired(await createInvite(ctx, owner), 'past 1m');
  }, { now: clock.now });
});

test('recovery: a step-up started by one session cannot be finished by another; members and CSRF-less requests cannot step up', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { ownerKey, ownerId, memberSession, memberKey, member } = await setup(ctx, layout);
    const a = await recovery(ctx);
    const b = await recovery(ctx);
    const options = await sessionPost(ctx, '/auth/passkey/step-up/options', a);
    assert.equal(options.status, 200, options.text);
    const { authenticationResponse } = await import('./support/webauthn-synthetic.mjs');
    const response = authenticationResponse({
      credential: ownerKey, challenge: Buffer.from(options.json.publicKey.challenge, 'base64url'), rpId: 'localhost', origin: ctx.origin, signCount: 500, userHandle: Buffer.from(ownerId),
    });
    const crossed = await sessionPost(ctx, '/auth/passkey/step-up/verify', { ...b, body: { challenge_id: options.json.challenge_id, credential: response } });
    assert.equal(crossed.status, 401, crossed.text);
    assert.deepEqual(crossed.json, { error: { code: 'step_up_failed', message: 'The passkey check failed; try again.' } });
    assertStepUpRequired(await createInvite(ctx, b), 'b did not step up');
    assertStepUpRequired(await createInvite(ctx, a), 'a did not finish');

    const memberTry = await sessionPost(ctx, '/auth/passkey/step-up/options', memberSession);
    assert.equal(memberTry.status, 403);
    assert.equal(memberTry.json.error.code, 'forbidden');
    void memberKey;
    void member;
    const noCsrf = await sessionPost(ctx, '/auth/passkey/step-up/options', { cookie: a.cookie });
    assert.equal(noCsrf.status, 403);
    assert.equal(noCsrf.json.error.code, 'csrf_invalid');
    const noSession = await sessionPost(ctx, '/auth/passkey/step-up/options', {});
    assert.equal(noSession.status, 401);
    // A step-up with a member's passkey for the owner session fails.
    const memberKeyAttempt = await stepUp(ctx, a, memberKey, member.id);
    assert.equal(memberKeyAttempt.status, 401);
  });
});

test('recovery: a member session wins over a recovery token in the body and over a leftover server-token cookie', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { memberSession, store, ownerId } = await setup(ctx, layout);
    const before = store.load().users.find((u) => u.id === ownerId).credentials.length;
    const withToken = await sessionPost(ctx, '/auth/passkey/register/options', { ...memberSession, body: { recovery_token: ctx.recoveryToken, display_name: 'Ada Example' } });
    assert.equal(withToken.status, 403, withToken.text);
    assert.equal(withToken.json.error.code, 'forbidden');
    const withCookie = await sessionPost(ctx, '/auth/passkey/register/options', { cookie: `${memberSession.cookie}; cockpit_serve=${ctx.token}`, csrf: memberSession.csrf });
    assert.equal(withCookie.status, 403);
    assert.equal(withCookie.json.error.code, 'forbidden');
    const verify = await sessionPost(ctx, '/auth/passkey/register/verify', { ...memberSession, body: { recovery_token: ctx.recoveryToken, challenge_id: 'x'.repeat(43), credential: {} } });
    assert.equal(verify.status, 403);
    assert.equal((await createInvite(ctx, memberSession)).status, 403);
    assert.equal(store.load().users.find((u) => u.id === ownerId).credentials.length, before);
  });
});

test('recovery: once the owner exists the recovery token cannot add a passkey without a session', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    await registerOwner(ctx, makeCredential());
    const res = await call({ port: ctx.port, method: 'POST', pathname: '/auth/passkey/register/options', body: { recovery_token: ctx.recoveryToken }, origin: ctx.origin });
    assert.equal(res.status, 409, res.text);
    assert.equal(res.json.error.code, 'owner_exists');
    assert.deepEqual(readAudit(layout).events.map((e) => `${e.event}:${e.result}`), ['first_owner:ok', 'first_owner:owner_exists']);
  });
});

// ---------------------------------------------------------------------------
// Recovery session and the account API

test('recovery: a recovery session lists and revokes sessions and removes passkeys without a step-up, but not the owner\'s last passkey', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { owner, ownerCredentialId, store, ownerId, member, memberSession } = await setup(ctx, layout);
    const rec = await recovery(ctx);
    const users = await call({ port: ctx.port, pathname: '/auth/account/users', cookie: rec.cookie });
    assert.equal(users.status, 200, users.text);
    const ownerView = users.json.users.find((u) => u.id === ownerId);
    assert.deepEqual(ownerView.sessions.map((s) => s.kind).sort(), ['passkey', 'recovery']);

    // Cut off a lost device: revoke the owner's passkey session, then remove a member passkey.
    const lost = ownerView.sessions.find((s) => s.kind === 'passkey');
    assert.equal((await sessionPost(ctx, '/auth/account/sessions/revoke', { ...rec, body: { session_id: lost.id } })).status, 200);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: owner.cookie })).status, 401);
    const memberPasskey = users.json.users.find((u) => u.id === member.id).passkeys[0].id;
    const removed = await sessionPost(ctx, '/auth/account/passkeys/remove', { ...rec, body: { credential_id: memberPasskey } });
    assert.equal(removed.status, 200, removed.text);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: memberSession.cookie })).status, 401);

    // The owner's last passkey stays refused.
    const last = await sessionPost(ctx, '/auth/account/passkeys/remove', { ...rec, body: { credential_id: ownerCredentialId } });
    assert.equal(last.status, 409);
    assert.equal(last.json.error.code, 'last_passkey');
    assert.equal(store.load().users.find((u) => u.id === ownerId).credentials.length, 1);

    // Sign-out ends the recovery session.
    assert.equal((await sessionPost(ctx, '/auth/account/sign-out', rec)).status, 200);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: rec.cookie })).status, 401);
  });
});

test('recovery: a recovery session belonging to anyone but the owner is refused', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { member } = await setup(ctx, layout);
    const sessions = openSessionStore({ file: layout.sessionStore, root: layout.root });
    const forged = sessions.create({ userId: member.id, kind: 'recovery' });
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: `cockpit_session=${forged.token}` })).status, 401);
  });
});

// ---------------------------------------------------------------------------
// Rotation

test('recovery: --rotate-token ends recovery sessions and the old token, keeps passkey sessions, and is audited', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    const { owner } = await setup(ctx, layout);
    const rec = await recovery(ctx);
    const config = serveConfig(layout);
    const { token, revoked, warnings } = rotateRecoveryToken(config);
    assert.equal(revoked, 1);
    assert.deepEqual(warnings, []);
    assert.notEqual(token, ctx.recoveryToken);
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: rec.cookie })).status, 401, 'recovery sessions end');
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: owner.cookie })).status, 200, 'passkey sessions stay');
    assert.equal((await recoverySignIn(ctx)).res.status, 401, 'the old token fails');
    const fresh = await recoverySignIn(ctx, { token });
    assert.equal(fresh.res.status, 200, 'the running server picks up the new token');
    const events = readAudit(layout).events.map((e) => `${e.event}:${e.result}`);
    assert.deepEqual(events.slice(-3), ['token_rotated:ok', 'token_sign_in:invalid', 'token_sign_in:ok']);
    for (const name of ['recovery.json', 'audit.json', 'sessions.json']) {
      const text = fs.readFileSync(statePath(layout, name), 'utf8');
      assert.ok(!text.includes(token) && !text.includes(ctx.recoveryToken), `${name} holds no token`);
    }
  });
});

test('recovery: a recovery session that rotation could not revoke is still refused because it predates the new token', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    await setup(ctx, layout);
    const rec = await recovery(ctx);
    await new Promise((resolve) => { setTimeout(resolve, 5); });
    const lockFile = `${layout.sessionStore}.lock`;
    fs.writeFileSync(lockFile, 'another-writer', { mode: 0o600 });
    let result;
    try {
      result = rotateRecoveryToken({ ...serveConfig(layout) });
    } finally {
      fs.rmSync(lockFile, { force: true });
    }
    assert.equal(result.revoked, 0);
    assert.match(result.warnings[0], /could not revoke recovery sessions \(store_busy\)/);
    assert.ok(openSessionStore({ file: layout.sessionStore, root: layout.root }).list().some((s) => s.kind === 'recovery'), 'still stored');
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: rec.cookie })).status, 401, 'but refused');
  });
});

test('recovery: without a recovery token file every recovery session is refused', async () => {
  const layout = makeServeRoot();
  await withServe(serveConfig(layout), async (ctx) => {
    await setup(ctx, layout);
    const rec = await recovery(ctx);
    fs.rmSync(statePath(layout, 'recovery.json'));
    assert.equal((await call({ port: ctx.port, pathname: '/', cookie: rec.cookie })).status, 401);
    assert.equal((await recoverySignIn(ctx)).res.status, 401);
  });
});

// ---------------------------------------------------------------------------
// --recovery-enroll

test('recovery: --recovery-enroll lets a recovery session add one owner passkey without a step-up, then closes; it is audited', async () => {
  const layout = makeServeRoot();
  const clock = clockFrom();
  await withServe(serveConfig(layout, ['--recovery-enroll']), async (ctx) => {
    const { store, ownerId, owner } = await setup(ctx, layout);
    clock.at += 6 * MINUTE;
    // Passkey sessions are not covered: a stale one still needs a step-up.
    assertStepUpRequired((await addPasskey(ctx, owner, makeCredential())).options, 'passkey session');
    const rec = await recovery(ctx);
    const first = await addPasskey(ctx, rec, makeCredential(), { label: 'Replacement key' });
    assert.equal(first.verify?.status, 201, first.options.text);
    assert.equal(store.load().users.find((u) => u.id === ownerId).credentials.length, 2);
    assertStepUpRequired((await addPasskey(ctx, rec, makeCredential())).options, 'closed after one use');
    assertStepUpRequired(await createInvite(ctx, rec), 'invites still need a step-up');
    assert.ok(readAudit(layout).events.some((e) => e.event === 'recovery_enroll' && e.result === 'ok'));
  }, { now: clock.now });

  const later = makeServeRoot();
  const clock2 = clockFrom();
  await withServe(serveConfig(later, ['--recovery-enroll']), async (ctx) => {
    await setup(ctx, later);
    const rec = await recovery(ctx);
    clock2.at += 15 * MINUTE;
    assertStepUpRequired((await addPasskey(ctx, rec, makeCredential())).options, 'closed after 15 minutes');
  }, { now: clock2.now });

  const off = makeServeRoot();
  await withServe(serveConfig(off), async (ctx) => {
    await setup(ctx, off);
    const rec = await recovery(ctx);
    assertStepUpRequired((await addPasskey(ctx, rec, makeCredential())).options, 'off without the flag');
  });
});

// ---------------------------------------------------------------------------
// Secrets stay out of responses and logs

test('recovery: the token never appears in a response, a log line, or a stored file', async () => {
  const layout = makeServeRoot();
  const lines = [];
  const seen = [];
  let recoveryToken;
  await withServe(serveConfig(layout), async (ctx) => {
    ({ recoveryToken } = ctx);
    const record = async (promise) => {
      const res = await promise;
      seen.push(res);
      return res;
    };
    const { owner } = await setup(ctx, layout);
    await record(recoverySignIn(ctx, { token: `${recoveryToken}x` }).then((r) => r.res));
    await record(recoverySignIn(ctx, { token: recoveryToken.split('').reverse().join('') }).then((r) => r.res));
    const rec = await recoverySignIn(ctx);
    seen.push(rec.res);
    await record(call({ port: ctx.port, pathname: '/auth/account', cookie: rec.cookie }));
    await record(call({ port: ctx.port, pathname: '/auth/account/users', cookie: rec.cookie }));
    await record(call({ port: ctx.port, pathname: '/auth/account/audit', cookie: owner.cookie }));
    await record(call({ port: ctx.port, method: 'POST', pathname: '/auth/passkey/register/options', body: { recovery_token: recoveryToken }, origin: ctx.origin }));
    await record(call({ port: ctx.port, pathname: '/auth/login/' }));
    await record(call({ port: ctx.port, pathname: '/auth/settings/' }));
  }, { log: (line) => lines.push(line) });
  const secrets = [recoveryToken, hashToken(recoveryToken)];
  assert.ok(seen.length >= 9);
  for (const res of seen) {
    const all = `${res.text}${JSON.stringify(res.headers)}`;
    for (const secret of secrets) assert.ok(!all.includes(secret), `response ${res.status} leaks the token`);
  }
  assert.ok(lines.length > 0, 'refusals were logged');
  for (const line of lines) {
    for (const secret of secrets) assert.ok(!line.includes(secret), `log line leaks the token: ${line}`);
    assert.match(line, /^[a-z -]+[a-z_]+( \([a-z_]+\))?$/, `log lines are codes only: ${line}`);
  }
  for (const name of ['recovery.json', 'audit.json', 'sessions.json', 'identity.json']) {
    assert.ok(!fs.readFileSync(statePath(layout, name), 'utf8').includes(recoveryToken), `${name} holds no token`);
  }
  for (const name of ['audit.json', 'sessions.json', 'identity.json']) {
    assert.ok(!fs.readFileSync(statePath(layout, name), 'utf8').includes(hashToken(recoveryToken)), `${name} holds no token hash`);
  }
});

// ---------------------------------------------------------------------------
// The CLI

const runServe = (layout, args, { untilLine } = {}) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [serveScript, '--passkeys', '--identity-store', layout.identityStore, '--port', '0', ...args], {
    env: layout.env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    if (untilLine && untilLine.test(stdout)) child.kill('SIGTERM');
  });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('error', reject);
  child.on('exit', (code) => resolve({ code, stdout, stderr }));
});

test('recovery CLI: a non-interactive start does not create or print a token; --rotate-token prints one once on stdout and later starts never do', async () => {
  const layout = makeServeRoot();
  const first = await runServe(layout, [], { untilLine: /No recovery token yet/ });
  assert.match(first.stdout, /No recovery token yet\. Run serve\.mjs with --passkeys --rotate-token in a terminal/);
  assert.doesNotMatch(first.stdout, /token=|Add a passkey/);
  assert.match(first.stdout, /Serving: http:\/\/127\.0\.0\.1:\d+\/\n/, 'the Serving line has no token');
  assert.equal(fs.existsSync(statePath(layout, 'recovery.json')), false);

  const rotated = await runServe(layout, ['--rotate-token']);
  assert.equal(rotated.code, 0, rotated.stderr);
  const match = rotated.stdout.match(/New recovery token: ([A-Za-z0-9_-]{43})\n/);
  assert.ok(match, rotated.stdout);
  const token = match[1];
  assert.match(rotated.stdout, /Store it offline/);
  assert.ok(!rotated.stderr.includes(token));
  assert.equal(openRecoveryStore({ file: statePath(layout, 'recovery.json'), root: layout.root }).check(token), true);
  assert.ok(!fs.readFileSync(statePath(layout, 'recovery.json'), 'utf8').includes(token));
  assert.deepEqual(readAudit(layout).events.map((e) => `${e.event}:${e.result}`), ['token_rotated:ok']);

  const again = await runServe(layout, ['--recovery-enroll'], { untilLine: /Devices, invites, and sign out/ });
  assert.ok(!again.stdout.includes(token) && !again.stderr.includes(token), 'later starts never print it');
  assert.doesNotMatch(again.stdout, /No recovery token yet|Recovery token/);
  assert.match(again.stderr, /--recovery-enroll is on/);
});

test('serve config: --step-up-window, --rotate-token, and --recovery-enroll are validated and need --passkeys', () => {
  const layout = makeServeRoot();
  const parse = (argv) => parseServeConfig({ argv: ['--identity-store', layout.identityStore, ...argv], env: layout.env });
  assert.equal(parse(['--passkeys']).stepUpWindowMs, 5 * MINUTE);
  assert.equal(parse(['--passkeys', '--step-up-window', '15m']).stepUpWindowMs, 15 * MINUTE);
  assert.equal(parse(['--passkeys', '--step-up-window=1m']).stepUpWindowMs, MINUTE);
  assert.equal(parse(['--passkeys', '--step-up-window', '60m']).stepUpWindowMs, HOUR);
  assert.equal(parse(['--passkeys', '--step-up-window', '1h']).stepUpWindowMs, HOUR);
  for (const bad of ['0m', '61m', '2h', '1d', '30', '30s', '5M', 'soon']) {
    assert.throws(() => parse(['--passkeys', `--step-up-window=${bad}`]), /--step-up-window must be .* from 1m to 60m/, bad);
  }
  assert.throws(() => parse(['--step-up-window', '5m']), /--step-up-window requires --passkeys/);
  assert.throws(() => parse(['--rotate-token']), /--rotate-token requires --passkeys/);
  assert.throws(() => parse(['--recovery-enroll']), /--recovery-enroll requires --passkeys/);
  assert.throws(() => parse(['--passkeys', '--rotate-token', '--recovery-enroll']), /cannot be combined/);
  assert.equal(parse(['--passkeys', '--rotate-token']).rotateToken, true);
  assert.equal(parse(['--passkeys', '--recovery-enroll']).recoveryEnroll, true);
  assert.equal(parse([]).stepUpWindowMs, null);
  fs.writeFileSync(path.join(layout.root, '.cockpit', 'serve.toml'), 'step_up_window = "30m"\n');
  assert.equal(parse(['--passkeys']).stepUpWindowMs, 5 * MINUTE, 'command line only: serve.toml does not set it');
});
