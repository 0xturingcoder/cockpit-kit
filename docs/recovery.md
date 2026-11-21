# Owner recovery and passkey step-up

Phase 1 of passkeys and identity, after [passkey sign-in](passkeys.md), [per-device sessions](sessions.md), and [invites](invites.md). With `serve.mjs --passkeys`, the owner has a long-lived **recovery token**. It signs the owner in when no passkey is at hand, with a **recovery session** that can look around and cut off a lost device but cannot add a passkey, create an invite, or (with #13) change delegations until the owner confirms with a passkey (a **step-up**). Without `--passkeys` nothing here is active: the per-start server token, the `?token=` URL, and the `cockpit_serve` cookie work exactly as before.

## Summary

| | |
| --- | --- |
| Recovery token | 32 random bytes (`crypto.randomBytes`), base64url (43 characters). Owner only. |
| Stored | `recovery.json` next to the identity store holds only `{ schema_version, token_hash, created_at }`, where `token_hash` is the SHA-256 of the token. The token itself is never written to disk. |
| Shown | Once: on the first interactive `--passkeys` start, or by `--rotate-token`. Never in a response, log line, or file. |
| Sign-in | `POST /auth/passkey/recovery/sign-in` `{ token }`, from the login page. Signs in the owner only, with a recovery session (no passkey, no step-up) that lasts at most 12 hours (or `--session-lifetime`, if shorter). |
| Step-up | A fresh, user-verified assertion from one of the owner's passkeys, by a signed-in owner session. Fresh for `--step-up-window` (default 5 minutes). A passkey sign-in counts as a step-up when it happens. |
| Needs a fresh step-up | Adding a passkey, creating an invite, and (#13) approving or revoking delegations. From every session kind. |
| Rate limit | Every recovery-token attempt takes a token from one shared bucket: 5 at once, refilling at 5 per minute. Then `429 rate_limited` with `Retry-After`. |
| Audit log | `audit.json` next to the identity store: at most 200 `{ at, event, result }` entries; failed attempts are dropped before anything else, so a flood of them cannot push out a successful or security-relevant entry ([retention](#retention)). No token, hash, IP address, or User-Agent. Shown to the owner on `/auth/settings/` and at `GET /auth/account/audit`. |
| Rotation | `serve.mjs --passkeys --rotate-token`: new token, every recovery session ended, old token refused, printed once. |

## Keeping the token offline

The recovery token is as strong as an owner passkey for signing in, so treat it like a password you hope never to use:

- Store it **offline**: in a password manager entry, or on paper kept somewhere safe.
- **Never** put it in the knowledge repo, a dotfile, shell history, a chat, an issue, a ticket, or an agent's context. Do not pass it on a command line (`--token=...` does not exist for this reason); paste it into the login page's password field.
- Rotate it (below) whenever it may have been seen by someone else, after using it on an untrusted device, and when someone with access to it leaves.

The server prints the token only when it creates one, so it does not sit in your terminal scrollback after a restart, and `serve.mjs` refuses to create one on a non-interactive start (see [First start](#first-start)), so it never lands in a service journal.

## First start

On the first `serve.mjs --passkeys` start with no `recovery.json`:

- **In a terminal** (stdout is a TTY), the server creates the token and prints it once, with a reminder to store it offline:

  ```text
  Recovery token (create the owner, or recover, at http://localhost:18765/auth/login/): <43 characters>
  Store it offline (a password manager or paper), never in the repo, shell history, or chat. It is not shown again.
  ```

- **Not in a terminal** (for example under a service manager, whose journal keeps stdout), no token is created and the server prints `No recovery token yet. Run serve.mjs with --passkeys --rotate-token in a terminal to create one; it is needed to create the owner.` Run that once in a terminal, as the service user.

Later starts never print the token. Then create the owner: open `/auth/login/`, and under **Create the owner** enter your name, an optional device label, and the recovery token, and choose **Create the owner**. The recovery token authorizes this only while the identity store has no owner; afterwards it returns `409 owner_exists`.

## Recovering

When you have no passkey at hand (a new device, or your passkey device is away):

1. Open `/auth/login/` and paste the token into **Recover with the server token**. You are signed in with a recovery session and taken to `/auth/settings/`, which shows that you are signed in with the recovery token.
2. From there, without any step-up, you can:
   - see every user's sessions and passkeys, and **revoke sessions** (for example a lost phone's);
   - **remove passkeys**, except the owner's last one (`409 last_passkey`);
   - read the recovery activity;
   - read pages, and use the intents API with `--write` as the owner (principal: the owner's user id).
3. Adding a passkey or creating an invite asks you to confirm with one of your passkeys first. If you have one on another device, a cross-device prompt works. If you have lost **every** owner passkey, see [Lost every passkey](#lost-every-passkey).
4. Sign out when you are done (**Sign out on this device**), or let the session expire. Recovery sessions show up in the session list as "Recovery (server token)" and can be revoked like any other.

## Step-up

`POST /auth/passkey/step-up/options` and `POST /auth/passkey/step-up/verify` need a live **owner** session (passkey or recovery) and that session's CSRF token (`X-Cockpit-CSRF`), plus the usual exact `Origin`, fetch metadata, JSON, and 64 KiB checks. Members get `403 forbidden`.

1. Options: `{}` returns `{ challenge_id, publicKey }` with `challenge`, `rpId`, `timeout`, `userVerification: "required"`, and `allowCredentials` listing the owner's passkeys. The challenge is a separate `step-up` ceremony (its own cap of 64 pending challenges) bound to this session and user.
2. The settings page calls `navigator.credentials.get()`.
3. Verify: `{ challenge_id, credential }`. The server consumes the challenge, refuses it if another session or user started it, verifies the assertion against one of the owner's passkeys (including the user handle and user verification), stores the new signature counter, and records `step_up_at` on the session. Returns `{ stepped_up: true, step_up_at }`.

Every failure returns one `401 step_up_failed`. Step-up has its own options and failures buckets (as sign-in has), so sign-in traffic cannot rate-limit it.

### The gate

`requireFreshStepUp(signedIn, { now, windowMs })` in `skill/lib/identity/session-http.mjs` throws `403 step_up_required` unless the session's `step_up_at` is no more than `windowMs` old (a time in the future does not count). It applies to every session kind; a passkey session counts as stepped up when it signs in, so the owner is asked only once the session is older than the window. When a page gets `step_up_required` it asks for a passkey and retries once.

Gated actions (add to this list as gated routes land):

| Action | Route | Since |
| --- | --- | --- |
| Add an owner passkey | `POST /auth/passkey/register/options` and `/verify` (checked again at verify) | #11 |
| Create an invite | `POST /auth/account/invites` | #11 |
| Approve or revoke a delegation | the delegation routes; #13 calls `requireFreshStepUp` on them and adds its own route tests | #13 |

Revoking sessions, removing passkeys, revoking invites, signing out, and reading the audit log are **not** gated, so a recovery session can always cut off a lost device.

### Configuration

| Flag | Meaning |
| --- | --- |
| `--step-up-window <duration>` | How long a step-up stays fresh: a whole number of minutes or hours from `1m` to `60m` (for example `5m`, `15m`, `1h`). Default `5m`. Requires `--passkeys`. Command line only, like the other passkey settings. |

## Rotation

```bash
node skill/scripts/serve.mjs --root /path/to/knowledge-repo --passkeys --rotate-token
```

Run it in a terminal, as the user the server runs as. It does not serve; it:

1. writes a new token hash to `recovery.json` under its lock (this also replaces a damaged file);
2. revokes every recovery session (`revokeKind('recovery')` on the sessions store);
3. records `token_rotated` in the audit log;
4. prints the new token once, with the offline reminder, and exits.

A running server picks up the new hash on its next request (it re-reads `recovery.json` when the file changes), so there is no need to restart. As a second safeguard, a recovery session created before the current token's `created_at` is refused on every request, so old recovery sessions stay dead even if step 2 failed (the command then prints a warning). If `recovery.json` is deleted, every recovery session is refused and no token signs in until you rotate again. Passkey sessions are not affected.

## Lost every passkey

The owner's last passkey cannot be removed, but a lost or broken device can still leave you with none that work. A step-up is then impossible, so recovery happens on the host, where shell access is already stronger than the token:

1. Stop the server and start it once with `--recovery-enroll` (in addition to your usual flags). It prints a warning to stderr.
2. Sign in with the recovery token on the login page.
3. On `/auth/settings/`, choose **Add a passkey**. While the window is open, a **recovery** session may add **one** owner passkey without a step-up. The window closes after the first success or after 15 minutes, whichever comes first, and the use is recorded as `recovery_enroll` in the audit log. Passkey sessions are not affected by the flag.
4. Remove the lost passkeys from **All users**, then restart the server without `--recovery-enroll`. Consider rotating the token.

## Audit log

`audit.json` sits next to the identity store and uses the same file safety (mode `0600`, atomic rename, lock file, 1 MiB cap, fail closed):

```json
{
  "schema_version": 1,
  "events": [
    { "at": "2026-01-02T03:04:05.000Z", "event": "token_sign_in", "result": "ok" }
  ]
}
```

| `event` | When |
| --- | --- |
| `token_sign_in` | Any recovery-token sign-in attempt. |
| `first_owner` | Creating the owner with the recovery token (each refused attempt, and the success). |
| `token_rotated` | `--rotate-token`. |
| `recovery_enroll` | A passkey added through `--recovery-enroll`. |

| `result` | Meaning |
| --- | --- |
| `ok` | Succeeded. |
| `invalid` | Wrong, malformed, or missing token. |
| `rate_limited` | The shared bucket was empty. Written at most once per minute per event. |
| `no_owner` | A correct token, but there is no owner to sign in yet. |
| `owner_exists` | A correct token used to create the owner when one already exists. |

Entries hold nothing but those three fields: no token, hash, IP address, User-Agent, or session id. A **successful** token sign-in is refused with `503 audit_unavailable` (and no session) if its entry cannot be written; a refused attempt that cannot be logged is still refused, and the write failure goes to stderr as a code. The owner reads the log under **Recovery activity** on `/auth/settings/`, or at `GET /auth/account/audit` (`{ events: [...] }`, newest first; members get `403 forbidden`).

### Retention

The log holds at most 200 entries. Each is either a **failed attempt** (a `token_sign_in` or `first_owner` entry whose result is `invalid` or `rate_limited`) or **notable** (everything else: every `ok`, `no_owner`, and `owner_exists` result, and every `token_rotated` and `recovery_enroll` entry). When a write would make 201 entries:

1. the oldest failed attempt is dropped, so failed attempts keep only the newest ones that fit;
2. only if there are no failed attempts left (notable entries alone fill the log) is the oldest notable entry dropped, to make room for a newer notable one;
3. a new failed attempt that finds the log full of notable entries is not written.

So no number of failed attempts, which anyone who can reach the login page can make, can push a successful sign-in or any other notable entry out of the log; only 200 newer notable entries can. A damaged log is not trimmed or rewritten: reads and writes fail closed.

## Routes and errors

| Route | Who | Result |
| --- | --- | --- |
| `POST /auth/passkey/recovery/sign-in` `{ token }` | anyone with the token | `200 { signed_in: true, user_id, recovery: true }` and a session cookie. |
| `POST /auth/passkey/register/options` `{ display_name, recovery_token }` | no session, no owner yet | First-owner setup (also send `recovery_token` to `/register/verify`). |
| `POST /auth/passkey/step-up/options`, `/verify` | owner session + CSRF | See [Step-up](#step-up). |
| `GET /auth/account/audit` | owner session | `{ events }`. |

| Status | Code | When |
| --- | --- | --- |
| 401 | `recovery_failed` | Wrong, malformed, or missing recovery token (one fixed message). |
| 401 | `step_up_failed` | Any step-up verification failure, including a challenge started by another session. |
| 401 | `authentication_required` | Registration with no session and no recovery token. |
| 403 | `step_up_required` | A gated action without a fresh step-up. |
| 403 | `forbidden` | A member session on registration or step-up, even with a recovery token in the body or a leftover `cockpit_serve` cookie: a live session always wins. |
| 409 | `no_owner` | Recovery sign-in before the owner exists. |
| 409 | `owner_exists` | First-owner setup when the owner exists. |
| 429 | `rate_limited` | The recovery bucket is empty (`Retry-After`). |
| 503 | `audit_unavailable` | A successful recovery sign-in could not be audited. |
| 503 | `identity_unavailable` | `recovery.json` or `audit.json` is damaged or unsafe. |

## Storage and API

`skill/lib/identity/recovery.mjs`:

```js
import { openRecoveryStore, openAuditLog } from '../lib/identity/recovery.mjs';

const recovery = openRecoveryStore({ file, root });  // recovery.json, outside root
recovery.ensure();       // { created: true, token, createdAt } once, then { created: false }
recovery.rotate();       // { token, createdAt }
recovery.check(token);   // true or false; strict format check, constant-time hash compare
recovery.createdAt();    // ms or null
const audit = openAuditLog({ file, root });          // audit.json
audit.record('token_sign_in', 'ok');                 // false when a rate_limited entry is coalesced, or a failed attempt finds no room
audit.list();                                        // newest first
```

Both throw `RecoveryStoreError` with a `code` (`invalid_store`, `unsupported_schema`, `invalid_argument`, `unsafe_path`, `unsafe_file`, `unsafe_permissions`, `unreadable`, `store_busy`, `store_full`). An identity store named `recovery.json` or `audit.json` is refused at startup.

## Upgrading

- Sessions files move to `schema_version` 2 (`kind` and `step_up_at`, see [sessions.md](sessions.md#storage-and-io)). Version 1 sessions load as passkey sessions with no step-up, so after upgrading the owner confirms with a passkey once before adding a passkey or creating an invite.
- With `--passkeys`, the `?token=` URL and `cockpit_serve` cookie stop working; use a passkey or the recovery token. The startup output no longer includes a tokenized URL.
- When every passkey origin is `https`, the session cookie is renamed to `__Host-cockpit_session`, so existing sessions on those origins sign in again once.

## Tests

- `test/recovery.test.mjs`: the token file and audit log: creation once, rotation (including over a damaged file), format checks, audit bounds, failures-first retention under a flood, and coalescing, fail-closed loading, concurrent first starts, and nothing secret on disk.
- `test/recovery-serve.test.mjs`: `serve.mjs` end to end: owner-only recovery sessions, the gate with no, stale, and fresh step-ups on registration and invites, step-up binding and member refusal, member precedence over a token, the account API from a recovery session, rate limits and audit entries, a 40-minute flood that leaves the successful sign-in in the log, audit fail-closed, rotation (including when the revoke fails), `--recovery-enroll`, `--step-up-window`, the CLI output, and the token absent from responses, log lines, and files.
- `test/recovery-page.test.mjs`: the login and settings page scripts in `node:vm`: the token only in POST bodies, the step-up retry, the recovery banner, and the activity list built with `textContent`.
- `test/passkey-ceremonies.test.mjs`: the step-up ceremony and session-bound registration challenges.
