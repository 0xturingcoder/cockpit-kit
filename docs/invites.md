# Invites

Phase 1 of passkeys and identity, after [passkey sign-in](passkeys.md) and [per-device sessions](sessions.md). With `serve.mjs --passkeys`, the owner can invite someone to sign in as a member without sharing any secret: the owner creates an invite from a signed-in session and gets a one-time link, and the invitee opens it and creates their own passkey. The link is then spent. Without `--passkeys` nothing here is active.

## Summary

| | |
| --- | --- |
| Who creates | Only the owner, from a live passkey session, through the account API (or the settings page). The server-token cookie and member sessions are refused. |
| Link | `<origin>/auth/invite/#<token>`. The token is 32 random bytes (`crypto.randomBytes`), base64url, in the URL fragment. |
| Stored | SHA-256 of the token, never the token itself, plus a public invite id, the new member's user id and display name, the role (always `member`), who created it, and when it expires. |
| Shown | The token appears once, in the create response. Listing never shows it or its hash. |
| Binding | The invite names the user it creates. The client never supplies a user id, name, or role. |
| Single use | Enrolling spends the invite; it cannot be used again. |
| Lifetime | 24 hours by default, fixed at creation. `--invite-lifetime` changes it for new invites (5 minutes to 7 days). |
| Invalid | A spent, expired, revoked, unknown, malformed, or mismatched invite gets the same `400 invite_invalid`. |
| File | `invites.json` in the identity store's directory, with the same file safety. |

## Quick start

1. Sign in as the owner with a passkey and open `/auth/settings/`.
2. Under **Invites**, enter the person's name and choose **Create invite link**. The link is shown once: copy it and send it to them privately.
3. They open the link, choose **Create a passkey**, and complete the browser's passkey prompt. They are then signed in and taken to `/`. Later they sign in at `/auth/login/` like any member.

Pending invites are listed under **Invites** with a **Revoke invite** button each. An invite that is not used before it expires simply stops working.

## Flow

```text
owner (session)                      server                         invitee's browser
POST /auth/account/invites  ───────► create invite, store hash
       { display_name }      ◄─────── 201 { invite, url }
send url privately  ──────────────────────────────────────────────► open /auth/invite/#<token>
                                                                     script: take token, replaceState strips #<token>
                                     ◄── POST /auth/passkey/invite/options { token }
                                     find pending invite by hash,
                                     issue challenge bound to it ──► 200 { challenge_id, publicKey }
                                                                     navigator.credentials.create()
                                     ◄── POST /auth/passkey/invite/verify { token, challenge_id, credential, label? }
                                     verify response, spend invite,
                                     create member + passkey,
                                     create session ───────────────► 201 + Set-Cookie: cockpit_session=...
```

### Creating an invite

`POST /auth/account/invites` with `{ "display_name": "Test Member" }`. The display name follows the identity store's rules (1 to 128 characters, no surrounding whitespace, no control, bidirectional, or invisible formatting characters); anything else is `400 invalid_request`. The server pre-generates the member's user id (`usr_` plus 16 random bytes) and returns:

```json
{
  "invite": {
    "id": "inv_EXAMPLEonlyAAAAAAAAAAA",
    "user_id": "usr_EXAMPLEonlyBBBBBBBBBB",
    "display_name": "Test Member",
    "role": "member",
    "created_by": "usr_3q2-7wEXAMPLEonlyAAAAA",
    "created_at": "2026-01-02T03:04:05.000Z",
    "expires_at": "2026-01-03T03:04:05.000Z"
  },
  "url": "https://cockpit.example.com/auth/invite/#<token>"
}
```

The origin in `url` is the create request's `Origin`, which the account API has already checked against the configured origins, so a link always points at a configured origin. No user exists until enrollment, so an invite that is revoked or expires leaves nothing behind in the identity store.

### Enrolling

The invite page's script reads the token from `location.hash`, immediately calls `history.replaceState` to remove the fragment from the address bar and history, and keeps the token in memory only. It then sends it in POST bodies:

1. `POST /auth/passkey/invite/options` with `{ token }`. If the token names a pending invite, the server issues a challenge for the `invitation` ceremony bound to that invite id, user id, and display name, and returns `{ challenge_id, publicKey }`: the same creation options as owner registration (`residentKey: "required"`, `userVerification: "required"`, `none` attestation, ES256 then RS256), with the invite's user and an empty `excludeCredentials`.
2. The page calls `navigator.credentials.create()`.
3. `POST /auth/passkey/invite/verify` with `{ token, challenge_id, credential, label? }`. The server:
   1. consumes the challenge (single use, two minutes, `invitation` ceremony only);
   2. verifies the registration response exactly as for owner registration ([supported subset](passkeys.md#supported-subset));
   3. spends the invite under the invites lock: the token must hash to a pending, unexpired invite whose id is the one the challenge was issued for, and that invite is deleted;
   4. writes the member and the passkey in one identity store write (`createUserWithCredential` with the invite's user id, display name, and the `member` role);
   5. creates a session for the new passkey, as a sign-in does, and returns `201 { enrolled: true, signed_in: true, user_id }` with the `cockpit_session` cookie.

If the session cannot be saved (for example the sessions store is busy), the member and passkey still exist and the invite is spent: the response is `201 { enrolled: true, signed_in: false, user_id }` without a cookie, and the page tells them to sign in at `/auth/login/`.

A browser that already has a session (for example another member's) can enroll; on success its cookie is replaced by the new member's session.

## Lifecycle and guarantees

- **Single use.** The invite is spent only after the registration response has verified, so a cancelled prompt or a bad response leaves it pending for another try. Spending re-reads the file and deletes the invite under its lock, so of any number of concurrent enrollments with one invite, in this process or another, exactly one gets it; the others get `invite_invalid`. The pre-generated user id makes the identity write single-winner too: a second write for the same user id fails with `duplicate_id` under the identity store lock.
- **Bound to its user.** The challenge is bound to the invite and its user when options are issued, and at verify the token must hash to that same invite. A challenge obtained with one invite's token cannot be finished with another invite's token (the request is refused and neither invite is spent), and nothing the client sends can change the user id, name, or role.
- **Expiry.** Each invite expires at `created_at + lifetime`, fixed when it is created. Expiry is checked when options are issued and again when the invite is spent, so options obtained just before expiry cannot be finished after it. Expired invites are ignored on read and pruned on every write.
- **Revocation.** Revoking deletes the invite. An enrollment already in progress then fails at verify with `invite_invalid` and creates no user.
- **Retries.** If the identity write fails with `store_busy` or `store_full`, no user was created, so the invite is put back (if it has not expired meanwhile) and the invitee can retry with the same link. Any other failure after the invite was spent leaves it spent; the owner can create a new one. If the server stops between spending the invite and writing the user, the invite is lost and no user exists.
- **Indistinguishable failures.** Spent and revoked invites are deleted and expired ones are ignored, so on every route they look exactly like an invite that never existed.

## Keeping the token out of logs and referrers

- The token is in the URL **fragment**. Browsers never send a fragment to the server, so it does not appear in request lines, server or proxy access logs, or `Referer` headers.
- The invite page strips the fragment with `history.replaceState` before it makes any request, so the token does not stay in the address bar or history entry, and keeps it only in a script variable. It is sent only in the JSON body of `POST` requests, never in a query string (the passkey routes refuse query strings anyway).
- The page and every API response carry `Referrer-Policy: no-referrer` (the page also sets `<meta name="referrer" content="no-referrer">`), and the page's own fetches use `referrerPolicy: 'no-referrer'`.
- Error responses use fixed messages and never include request data. The server logs refusals to stderr as codes only (for example `passkey invite_invalid (challenge_unknown)`), never the token or its hash.
- The create response is the only response that contains the token. The settings page shows the link once in a read-only field and does not keep it after the page is left.

## Routes

Account API (under `/auth/account`, owner only, with the account API's checks: a live session, exact `Origin` and fetch metadata on `POST`, JSON bodies of at most 64 KiB, `X-Cockpit-CSRF`, no query string; see [sessions.md, Account API](sessions.md#account-api)):

| Route | Behavior |
| --- | --- |
| `GET /auth/account/invites` | `{ invites: [{ id, user_id, display_name, role, created_by, created_at, expires_at }] }`: pending invites. No tokens or hashes. |
| `POST /auth/account/invites` `{ display_name }` | `201 { invite, url }`. |
| `POST /auth/account/invites/revoke` `{ invite_id }` | `{ revoked: true }`; `404 invite_not_found` for an unknown, spent, or expired invite. |

Enrollment (under `/auth/passkey`, with the passkey API's checks: `POST`, exact `Origin`, `Sec-Fetch-Site: same-origin` when present, JSON bodies of at most 64 KiB, no query string; see [passkeys.md, Requests](passkeys.md#requests)):

| Route | Behavior |
| --- | --- |
| `POST /auth/passkey/invite/options` `{ token }` | `200 { challenge_id, publicKey }`. |
| `POST /auth/passkey/invite/verify` `{ token, challenge_id, credential, label? }` | `201 { enrolled: true, signed_in, user_id }`, plus the session cookie when `signed_in` is true. |

Page: `GET /auth/invite/` (and its script `/auth/invite/cockpit-invite.js`), served by the kit before auth, never from the knowledge repo.

## Errors

| Status | Code | When |
| --- | --- | --- |
| 400 | `invite_invalid` | Enrollment: a spent, expired, revoked, unknown, malformed, missing, or mismatched token, and any challenge or verifier failure. One fixed message; the reason goes to stderr as a code only. |
| 400 | `invalid_request` | Enrollment: the body is not a JSON object, `challenge_id` or `credential` is missing, or `label` breaks the label rules. Account API: a bad `display_name` or `invite_id`. |
| 401 | `session_required` | Account API without a live session, including the server-token cookie alone. |
| 403 | `forbidden` / `csrf_invalid` / `origin_denied` | A member calling the invite routes; a missing or wrong CSRF token; wrong `Origin` or fetch metadata. |
| 404 | `invite_not_found` | Revoking an invite that is not pending. |
| 409 | `too_many_invites` | Creating a 33rd pending invite. Revoke one first. |
| 429 | `rate_limited` | The invite options or failures bucket is empty (`Retry-After`). |
| 503 | `store_busy` | A store lock stayed busy for 1 second. Retry. |
| 503 | `too_many_challenges` | 64 invitation ceremonies are already pending. |
| 503 | `identity_unavailable` | A store file is corrupt or unreadable. |
| 507 | `store_full` | The identity store would exceed 1 MiB. |

## Rate limits and capacity

Invite enrollment has its own pair of token buckets, separate from sign-in and owner registration, so invite traffic cannot rate-limit either of them, and neither can rate-limit invites:

- Options requests: 10 at once, refilling at 30 per minute.
- Failures: 10 at once, refilling at 10 per minute. An options request with a token that names no pending invite counts as a failure, as does any failed verify. While the bucket is empty, every invite options and verify request gets `429 rate_limited`.

Invitation challenges have their own pending cap (64), separate from sign-in and registration challenges. Like the other buckets, these are per server, not per client (#21).

## Configuration

| Flag | Meaning |
| --- | --- |
| `--invite-lifetime <duration>` | How long a new invite stays valid: a whole number of minutes, hours, or days, such as `24h`, `3d`, or `30m`, from `5m` to `7d`. Default `24h`. Requires `--passkeys`. Command line only, like the other passkey settings. Existing invites keep the expiry they were created with. |

The invites file is always `invites.json` next to the identity store (by default `${XDG_STATE_HOME:-~/.local/state}/cockpit-kit/<repo-hash>/invites.json`). It is not configurable on its own, so it shares the identity store's checks. An identity store named `invites.json` is refused at startup.

## Storage and I/O

`skill/lib/identity/invites.mjs` stores pending invites in a private JSON file:

```json
{
  "schema_version": 1,
  "invites": [
    {
      "id": "inv_EXAMPLEonlyAAAAAAAAAAA",
      "token_hash": "x3Xnt1ft5jDNCqERO9ECZhqziCnKUqZCKreChi8mhkY",
      "user_id": "usr_EXAMPLEonlyBBBBBBBBBB",
      "display_name": "Test Member",
      "role": "member",
      "created_by": "usr_3q2-7wEXAMPLEonlyAAAAA",
      "created_at": "2026-01-02T03:04:05.000Z",
      "expires_at": "2026-01-03T03:04:05.000Z"
    }
  ]
}
```

- **File safety:** the same code as the identity and sessions stores (`skill/lib/identity/private-file.mjs`): mode `0600` in a directory that is not a symlink and not writable by group or others, atomic temp-file-and-rename writes, a lock file for each change with a re-read under the lock, a 1 MiB cap, and loading that fails closed on any unknown field, bad value, a role other than `member`, a duplicate id, hash, or user id, more than 32 records, or an unsupported `schema_version`. See [identity-store.md, File safety](identity-store.md#file-safety).
- **Limits:** at most 32 pending invites. Every write prunes expired invites first, so they never count against the limit.
- **Lookups:** a token is looked up only after a strict format check (43 base64url characters), by its SHA-256 hash.
- **Blocking:** the API is synchronous like the other stores; `serve.mjs` waits at most 1 second for the lock and then returns `503 store_busy`.

### API

```js
import { openInviteStore } from '../lib/identity/invites.mjs';

const invites = openInviteStore({ file, root, lifetimeMs, lockWaitMs: 1000 });
const { token, invite } = invites.create({ displayName, createdBy }); // token: for the link, never stored
invites.list();                   // pending invites, no hashes
invites.find(token);              // pending invite, or null; does not write
invites.spend(token, inviteId);   // deletes and returns the invite, or null; single winner
invites.restore(token, invite);   // puts a spent invite back after a retryable failure; true or false
invites.revoke(inviteId);         // removed invite, or null
```

`openInviteStore({ file, root, now?, lifetimeMs?, lockWaitMs?, lockStaleMs? })` checks that `file` is absolute and outside `root`. Errors are `InviteStoreError` with a `code`: `invalid_store`, `unsupported_schema`, `duplicate_id`, `invalid_argument`, `too_many_invites`, `unsafe_path`, `unsafe_file`, `unsafe_permissions`, `unreadable`, `store_busy`, or `store_full`.

The ceremonies are `startInvitation({ token })` and `finishInvitation({ token, challengeId, response, label? })` in `skill/lib/identity/passkeys.mjs` (pass `invites` to `createPasskeyCeremonies`); `finishInvitation` returns `{ userId, role, credentialId, credentialLabel, inviteId }` and throws `PasskeyError` (`invite_invalid`), `ChallengeError`, `WebAuthnError`, or `IdentityStoreError`, which `createPasskeyApi()` collapses as described under [Errors](#errors).

## Not in this change

- **Adding a device for an existing member.** Each invite creates a new member with one passkey. Members cannot add more passkeys through the server yet.
- **Enabling or removing users.** Disabling is unchanged; there is no enable, removal, or ownership transfer.
- **Step-up for the owner.** Creating an invite needs a live owner passkey session but no fresh passkey check; owner recovery and step-up for sensitive actions such as this one are #11.
- **Per-client rate limits** (#21) and **async store writes** (#20).
- **The standalone `intents-service.mjs`** has no sign-in surface and is unchanged.

## Tests

- `test/invites.test.mjs`: the store, including hashing, single use, expiry with an injected clock, pruning, the pending cap, revocation, restore, fail-closed loading, file safety, and two processes spending one invite at once.
- `test/invite-serve.test.mjs`: `serve.mjs` end to end with synthetic credentials generated at runtime: owner-only creation, enrollment of the bound member, single use, expiry, revocation (including mid-enrollment), wrong user, replay of the verify body and of the token, concurrent enrollments with exactly one winner, one byte-identical error for every invalid case, member and server-token callers refused, the retry paths, the invite page headers and script, the token absent from every response except create and from log lines and the CLI's stderr, separate rate-limit buckets and challenge capacity, and `--invite-lifetime` parsing.
