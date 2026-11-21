# Per-device sessions

Phase 1 of passkeys and identity, after [passkey sign-in](passkeys.md). With `serve.mjs --passkeys`, every passkey sign-in creates its own server-side session. A signed-in user can list their sessions and revoke any of them, including the one they are using, and the owner can list and revoke every user's sessions and passkeys. Without `--passkeys` nothing here is active.

## Summary

| | |
| --- | --- |
| Session token | 32 random bytes (`crypto.randomBytes`), base64url, sent only in the cookie. |
| Stored | SHA-256 of the token, never the token itself, plus a public session id, user id, the passkey used, device label, created, last seen, and expiry. |
| Lifetime | 90 days by default, fixed at sign-in (not extended by use). `--session-lifetime` changes it for new sessions. |
| Cookie | `cockpit_session=<token>; HttpOnly; SameSite=Strict; Path=/; Max-Age=<lifetime in seconds>`, plus `Secure` when the sign-in came from an `https` origin. |
| Revocation | Deletes the session. The next request with that cookie is refused. |
| Expiry | Checked on every request against the stored `expires_at`. |
| File | `sessions.json` in the identity store's directory, with the same file safety. |

## Configuration

| Flag | Meaning |
| --- | --- |
| `--session-lifetime <duration>` | Lifetime of new passkey sessions: a whole number of minutes, hours, or days, such as `90d`, `12h`, or `30m`, from `5m` to `400d` (browsers cap cookie lifetimes at 400 days). Default `90d`. Requires `--passkeys`. Command line only, like the other passkey settings. Existing sessions keep the expiry they were created with. |

The sessions file is always `sessions.json` next to the identity store (by default `${XDG_STATE_HOME:-~/.local/state}/cockpit-kit/<repo-hash>/sessions.json`). It is not configurable on its own, so it shares the identity store's checks: outside the served root, and a directory that is not a symlink and not writable by group or others. An identity store named `sessions.json` is refused at startup.

## What a session grants

Sessions authenticate the user by id. `serve.mjs` checks the cookie on every request: the token's hash must match a stored session that has not expired, the session's user must still exist in the identity store and not be disabled, and the passkey the session signed in with must still be on that user. If any check fails, the request is treated as unauthenticated. A corrupt or unreadable sessions file fails closed the same way (the reason is logged to stderr as a code).

| Surface | Owner session | Member session | Server-token cookie |
| --- | --- | --- | --- |
| Knowledge-repo pages (`GET`/`HEAD`) | yes | yes | yes |
| `/auth/account` (own sessions, sign out) | yes | yes | no (`401 session_required`); sign-out still clears cookies |
| `/auth/account/users`, `/auth/account/passkeys/remove` | yes | no (`403 forbidden`) | no |
| Passkey registration (`/auth/passkey/register/*`) | no | no | yes, even alongside a session cookie (unchanged; see [Not in this change](#not-in-this-change)) |
| Intents API with `serve --write` (see below) | yes | no (`403 forbidden`) | yes |

If a request carries both a live session cookie and the server-token cookie, the session is used on the account API and the intents API, so a member session plus the server-token cookie gets `403 forbidden` on the intents routes. Passkey registration is the exception: it looks only at the server-token cookie, so a browser holding a member session and the server-token cookie can still add a passkey for the owner. Aligning registration with the session-first rule is tracked in #11.

### Intents routes

With `serve.mjs --write --passkeys`, every route under `/api/cockpit/v1` accepts either an owner passkey session or the server-token cookie:

| Route | Owner passkey session | Server token |
| --- | --- | --- |
| `GET /capabilities` | yes; returns this session's CSRF token | yes |
| `GET /intents`, `GET /intents/<id>` | yes | yes |
| `POST /intents`, `POST /intents/<id>/replies`, `POST /intents/<id>/archive` | yes, with `X-Cockpit-CSRF` set to this session's token, plus the existing Origin, JSON, and size checks | yes, with the token's CSRF value |

- `authenticate` in `skill/lib/intents/http.mjs` returns `{ principal: <user id>, session: <session id> }` for a passkey session, so intents created through a session record the owner's user id as `principal_id`. The server token keeps the principal `operator`.
- The CSRF token is `HMAC-SHA-256(secret, "csrf:<user id>:session:<session id>")`, so a token taken from one session does not work in any other, and it stops working when the session is revoked. Requests with the server token keep `HMAC(secret, "csrf:operator")`. The secret is derived from the per-start server token, so CSRF tokens change when the server restarts; the widget already fetches a new one after `403 csrf_invalid`.
- Member sessions get `403 forbidden` on every intents route until verified comment authors and the allowlist land (#12).
- The standalone `intents-service.mjs` is unchanged: it still authenticates only through the reverse proxy's shared secret and accepts no passkey session or cookie.

## Account API

Under `/auth/account`, served only with `--passkeys`. Responses are JSON with `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Content-Security-Policy: default-src 'none'; ...`. Errors use `{ "error": { "code", "message" } }` with fixed messages.

Every request: no query string (`400 invalid_request`). `GET` requests with `Sec-Fetch-Site: cross-site` or `same-site` are refused. `POST` requests need an `Origin` that exactly matches a configured passkey origin, `Sec-Fetch-Site: same-origin` when present, `Content-Type: application/json`, a JSON object body of at most 64 KiB, and `X-Cockpit-CSRF` set to the session's CSRF token (the same value `GET /auth/account` and `GET /api/cockpit/v1/capabilities` return).

| Route | Who | Behavior |
| --- | --- | --- |
| `GET /auth/account` | any session | `{ user: { id, display_name, role }, session_id, csrf_token, sessions: [...] }`: the caller's own live sessions. |
| `POST /auth/account/sign-out` `{}` | anyone | Revokes the current session (CSRF required when there is one) and clears both `cockpit_session` and `cockpit_serve` with `Max-Age=0`. Without a session it only clears the cookies. |
| `POST /auth/account/sessions/revoke` `{ session_id }` | any session | Revokes one session. Members can revoke only their own; another user's session returns `404 session_not_found`, exactly like a missing one. Returns `{ revoked: true, current }`, and clears the cookies when `current` is true. |
| `GET /auth/account/users` | owner | `{ users: [{ id, display_name, role, disabled, created_at, passkeys: [{ id, label, created_at, transports }], sessions: [...] }] }`. No public keys, counters, or token hashes. |
| `POST /auth/account/passkeys/remove` `{ credential_id }` | owner | Revokes every session that signed in with the passkey, then removes the passkey (any user's). Returns `{ removed: true, sessions_revoked, current }`. A malformed id, an unknown passkey, and the owner's last passkey (`409 last_passkey`) are refused before anything changes, so a refused request ends no sessions. If the removal then fails (for example `503 store_busy`), the passkey is still there and the request can be retried. |

Each session in a response is `{ id, user_id, credential_id, label, created_at, last_seen_at, expires_at, current }`.

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Query string, body not a JSON object, or a malformed `session_id` or `credential_id`. |
| 401 | `session_required` | No live session (including a request with only the server-token cookie). |
| 403 | `origin_denied` / `csrf_invalid` / `forbidden` | Wrong Origin or fetch metadata; missing or wrong CSRF token; a member calling an owner route. |
| 404 | `session_not_found` / `passkey_not_found` / `not_found` | Unknown session (or another user's, for members); unknown passkey; unknown route. |
| 405 | `method_not_allowed` | Wrong method. |
| 409 | `last_passkey` | Removing the owner's only passkey. |
| 413 / 415 | `body_too_large` / `unsupported_media_type` | Body over 64 KiB; not `application/json` or compressed. |
| 503 | `store_busy` | The sessions or identity store lock stayed busy for 1 second. Retry (`Retry-After: 2`). |
| 503 | `identity_unavailable` | A store file is corrupt or unreadable. |
| 507 | `store_full` | The sessions store is full. |

Passkey sign-in (`POST /auth/passkey/login/verify`) can also return `503 store_busy` or `503 identity_unavailable` when the session cannot be saved.

## Settings page

`/auth/settings/` is part of the kit (`skill/templates/settings/`), served before auth like the login page, with the same headers: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`. The page holds no data; its script reads `/auth/account` and lists the signed-in devices with a revoke button each and a **Sign out on this device** button. For the owner it also lists every user with their sessions and passkeys. It builds the page with `textContent` only and loads nothing from other hosts. The login page links to it, and `serve.mjs --passkeys` prints its URL at startup.

## Storage and I/O

`skill/lib/identity/sessions.mjs` stores sessions in a private JSON file:

```json
{
  "schema_version": 1,
  "sessions": [
    {
      "id": "ses_EXAMPLEonlyAAAAAAAAAAA",
      "token_hash": "x3Xnt1ft5jDNCqERO9ECZhqziCnKUqZCKreChi8mhkY",
      "user_id": "usr_3q2-7wEXAMPLEonlyAAAAA",
      "credential_id": "q83vEjRWeJA",
      "label": "Work laptop",
      "created_at": "2026-01-02T03:04:05.000Z",
      "last_seen_at": "2026-01-02T03:14:05.000Z",
      "expires_at": "2026-04-02T03:04:05.000Z"
    }
  ]
}
```

- **File safety:** the same code as the identity store (`skill/lib/identity/private-file.mjs`): mode `0600` in a directory that is not a symlink and not writable by group or others, atomic temp-file-and-rename writes, a lock file for each change with a re-read under the lock, a 1 MiB cap, and loading that fails closed on any unknown field, bad value, duplicate id or hash, or unsupported `schema_version`. See [identity-store.md, File safety](identity-store.md#file-safety).
- **Device label:** the label of the passkey used to sign in, or if it has none, a coarse "Browser on System" name such as `Firefox on Linux`, picked from a fixed list. User-Agent text is never stored.
- **Reads do not write:** the parsed file is cached and re-read only when it changes (every write renames a new file into place, which changes its inode), so a revocation by this server or another process is seen on the next request.
- **Throttled last seen:** `last_seen_at` is written at most once every 10 minutes per session. That write never waits for the lock: if the store is busy it is skipped, and the request still succeeds.
- **Pruning and limits:** expired sessions are dropped on the next write. Each user keeps at most 32 sessions; a new sign-in beyond that drops the user's least recently seen session. At most 2,000 sessions in total.
- **Blocking:** the API is synchronous like the identity store. Sign-in and revocation wait at most 1 second for the lock and then return `503 store_busy`. Moving store writes off the event loop is tracked in #20.

### API

```js
import { openSessionStore } from '../lib/identity/sessions.mjs';

const sessions = openSessionStore({ file, root, lifetimeMs, lockWaitMs: 1000 });
const { token, session, maxAgeSeconds } = sessions.create({ userId, credentialId, label });
sessions.validate(token);            // public session, or null (unknown, revoked, or expired)
sessions.list({ userId });           // live sessions
sessions.get(sessionId);
sessions.revoke(sessionId);          // removed session, or null
sessions.revokeUser(userId);         // removed sessions
sessions.revokeCredential(credentialId);
```

`openSessionStore({ file, root, now?, lifetimeMs?, lastSeenIntervalMs?, lockWaitMs?, lockStaleMs? })` checks that `file` is absolute and outside `root`. Public sessions never include `token_hash`. Errors are `SessionStoreError` with a `code`: `invalid_store`, `unsupported_schema`, `duplicate_id`, `invalid_argument`, `unsafe_path`, `unsafe_file`, `unsafe_permissions`, `unreadable`, `store_busy`, or `store_full`.

`skill/lib/identity/session-http.mjs` holds the cookie helpers, `createSessionAuth()` (cookie to `{ session, user }`), and `createAccountApi()` (the routes above).

## Users, passkeys, and recovery

- **Owner's last passkey:** `removeCredential` in the identity store refuses it (`last_credential`), and the account API returns `409 last_passkey`. Add another passkey first. A member's last passkey can be removed.
- **Removing a passkey** ends every session that signed in with it. The account API revokes those sessions before it removes the passkey, and a session whose passkey is no longer on its user is refused on the next request in any case, so a passkey removed some other way (such as `removeCredential` in the identity store) also ends its sessions. Sessions created without a passkey are unaffected.
- **Disabled users:** their sessions are refused on the next request. The owner cannot be disabled (unchanged).

## Not in this change

- **The server token is not a session yet.** The tokenized URL still sets the `cockpit_serve` cookie, which is not listed or revocable and lasts for the browser session until the server restarts with a new token. It still authorizes passkey registration, and it is accepted on the intents API with the principal `operator`. Revoking sessions does not sign out a browser that also holds this cookie; **Sign out** on that browser clears it. A browser holding only this cookie cannot use the account API (`401 session_required`), so during recovery it cannot list or revoke sessions; that is tracked in #11, along with registration accepting this cookie alongside a member session (see [What a session grants](#what-a-session-grants)). Making token sign-in an owner-only recovery session that cannot add passkeys without a fresh passkey step-up, its rate limits and audit log, and token rotation are #11.
- **User administration:** there is no `enableUser`, user removal, or ownership transfer, and the disabled-user rules in the identity store are unchanged. These are left for #11 (recovery) and #10 (invites).
- **Members on the intents API:** refused until verified comment authors and the allowlist (#12).
- **Per-client rate limits** (#21) and **async store writes** (#20).

## Tests

- `test/sessions.test.mjs`: the store, including hashing, expiry, revocation seen across processes, concurrent sessions, two processes creating sessions at once, throttled and non-blocking last-seen writes, the per-user limit, and fail-closed loading.
- `test/session-serve.test.mjs`: `serve.mjs` end to end: cookie attributes (`Max-Age`, `Secure` on https), concurrent sessions, revoking another or the current session, sign-out, expiry, no writes per request, member and owner authorization boundaries, passkey removal ending sessions (including when a store write fails, a refused removal, and a passkey removed directly in the store), disabled users, request checks, the settings page headers, the intents routes with session-bound CSRF, a member session winning over the server-token cookie on the intents routes, and `--session-lifetime` parsing.
