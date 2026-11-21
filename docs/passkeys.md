# Passkey sign-in (WebAuthn)

Phase 1 of passkeys and identity, after the [users and credentials store](identity-store.md). `serve.mjs --passkeys` adds passkey registration and sign-in and a small login page. Verification is built on `node:crypto` with no dependencies, and it supports a deliberately narrow subset of WebAuthn.

A successful sign-in produces a verified user id, and `serve.mjs` creates a new per-device session for that user, owner or member, with its own `cockpit_session` cookie. Sessions, their lifetime, listing and revoking them, the settings page, and which routes accept them are described in [`sessions.md`](sessions.md).

## Quick start

```bash
node skill/scripts/serve.mjs --root /path/to/knowledge-repo --passkeys
```

The server prints two extra lines:

```text
Passkeys: sign in at http://localhost:18765/auth/login/ (relying party localhost)
Add a passkey: http://localhost:18765/auth/login/?token=<token>
Devices and sign out: http://localhost:18765/auth/settings/
```

1. Open the "Add a passkey" URL. The token sets the server-token cookie and redirects to the login page.
2. Enter your name (only used to create the owner, when the identity store does not exist yet), optionally a device label, and choose **Add a passkey**.
3. Later, from any browser that has the passkey, open `/auth/login/` and choose **Sign in with a passkey**. Each sign-in is a separate session; manage them at `/auth/settings/`.

Use `localhost`, not `127.0.0.1`: browsers do not allow an IP address as a relying-party id, so passkeys created on `localhost` work only on `localhost` origins.

## Configuration

All passkey settings come from the command line. None are read from `.cockpit/serve.toml`, because anyone who can write the knowledge repo could otherwise point sign-in at a store or relying party they control.

| Flag | Meaning |
| --- | --- |
| `--passkeys` | Enable the login page at `/auth/login/` and the API at `/auth/passkey/*`. Requires auth (`--passkeys --no-auth` is refused) and an identity store. |
| `--rp-id <domain>` | Relying-party id. Default `localhost`. A lowercase domain name of at least two labels (or `localhost`): no scheme, port, path, trailing dot, IP address, or bare top-level domain such as `com`. Requires `--passkeys`. |
| `--origin <origin>` | Exact browser origin, repeatable. Shared with `--write`. Without it, the only passkey origin is `http://localhost:<port>`. Each origin must use `https` (or `http` with the host `localhost`), and its host must be the rp id or a subdomain of it. |
| `--session-lifetime <duration>` | Lifetime of a sign-in session, such as `90d`, `12h`, or `30m` (default `90d`, from `5m` to `400d`). Requires `--passkeys`. See [`sessions.md`](sessions.md). |
| `--identity-store <path>` | The users and credentials file. With `--passkeys` it must come from this flag or the default state directory; `identity_store` in `.cockpit/serve.toml` is refused. If no store path can be resolved (no `HOME` or `XDG_STATE_HOME`), `--passkeys` refuses to start. |

Mismatches fail at startup. The relying-party id and origins are never taken from `Host`, `Origin`, `X-Forwarded-*`, or any other request header; the request `Origin` is only compared against the configured list.

Behind a TLS reverse proxy, pass the public names:

```bash
node skill/scripts/serve.mjs --root /path/to/knowledge-repo --passkeys \
  --rp-id example.com --origin https://cockpit.example.com
```

The proxy must still present a loopback `Host` header, as for any `serve.mjs` request. On an `https` origin the session cookie gets the `Secure` attribute. The server-token cookie set by the tokenized URL gets it too when every configured `--origin` is `https`.

## Ceremonies

### Registration (owner only)

Registration needs the server-token cookie (from the tokenized URL); a passkey session alone cannot add a passkey. If the identity store does not exist yet, the first registration creates the owner, writing the owner and the passkey in one store write so a failed first registration leaves no store behind; after that, registration adds a passkey to the owner. Members get passkeys through invites (#10).

1. `POST /auth/passkey/register/options` with `{ "display_name"?: string }`. Returns `{ challenge_id, publicKey }`, where `publicKey` is `PublicKeyCredentialCreationOptions` with base64url binary fields: `rp`, `user` (the user handle is the UTF-8 user id), `challenge`, `pubKeyCredParams` (-7, then -257), `timeout`, `attestation: "none"`, `authenticatorSelection` (`residentKey: "required"`, `userVerification: "required"`), and `excludeCredentials` (the owner's existing passkeys).
2. The page calls `navigator.credentials.create()`.
3. `POST /auth/passkey/register/verify` with `{ challenge_id, credential, label?: string }`. `credential` is the `PublicKeyCredential` as JSON (base64url fields, as `toJSON()` produces). Returns `201 { registered: true, user_id, credential_id, created_owner }`.

The challenge is bound to the user it was issued for, so the response can only add a credential to that user. Note that with `none` attestation nothing in the registration response is signed; registration is trusted because the server token authorized it, not because of the response.

### Sign-in (usernameless)

1. `POST /auth/passkey/login/options` with `{}`. Returns `{ challenge_id, publicKey }` with `challenge`, `rpId`, `timeout`, `userVerification: "required"`, and an empty `allowCredentials`. Nothing names a user, so the options never reveal who exists.
2. The page calls `navigator.credentials.get()`.
3. `POST /auth/passkey/login/verify` with `{ challenge_id, credential }`. The server consumes the challenge, looks up the credential by `rawId`, verifies the response against the stored public key (including that the user handle names the credential's owner), refuses disabled users, and stores the new signature counter. Returns `200 { signed_in: true, user_id }` and a new session: `Set-Cookie: cockpit_session=<token>; HttpOnly; SameSite=Strict; Path=/; Max-Age=7776000` (the session lifetime in seconds, plus `Secure` on https).

### Requests

Every passkey request must be a `POST` with `Content-Type: application/json`, a body of at most 64 KiB, no query string, and an `Origin` header that exactly matches a configured origin. If `Sec-Fetch-Site` is present it must be `same-origin`. Responses are JSON with `Cache-Control: no-store` and `Content-Security-Policy: default-src 'none'`.

## Supported subset

| Area | Rule |
| --- | --- |
| Attestation | Only `fmt: "none"` with an empty `attStmt`. Every other format, including `packed` self attestation, is rejected (`unsupported_attestation`). No trust chains, no metadata service. The attestation object must be a CBOR map with exactly `fmt`, `attStmt`, and `authData`. |
| Algorithms | ES256 (COSE -7): EC2 key, P-256 (`crv` 1), 32-byte `x` and `y`, point checked on the curve. RS256 (COSE -257): RSA key, 2048- to 4096-bit odd modulus without a leading zero byte, exponent 65537. Keys are imported with `crypto.createPublicKey` (JWK). Any other algorithm, key type, or `kty`/`alg`/`crv` combination is rejected at registration. A key with any extra COSE label (including private parameters) is rejected. |
| Signatures | Over `authenticatorData || SHA-256(clientDataJSON)`. ES256 signatures are strict DER (short-form lengths, minimal positive integers, 1 <= r, s < n, no trailing bytes), converted to raw r‖s for verification. High-S signatures are accepted: WebAuthn does not require low-S and authenticators produce both; malleability is harmless because signatures are never identifiers and challenges are single use. RS256 is RSASSA-PKCS1-v1_5 with SHA-256, and the signature must be exactly the modulus length. |
| clientDataJSON | At most 4 KiB, valid UTF-8 JSON object (a byte-order mark is refused). `type` must be exactly `webauthn.create` or `webauthn.get`. `challenge` is compared with the server's challenge (base64url string) using `crypto.timingSafeEqual`. `origin` must exactly match a configured origin. `crossOrigin: true` and any `topOrigin` are rejected, since only top-level same-origin ceremonies are supported. Other members are ignored, as the spec requires. |
| authenticatorData | At least 37 bytes. `rpIdHash` must equal SHA-256 of the configured rp id (constant-time compare). UP and UV must be set. BS without BE is invalid. With AT: a 16-byte AAGUID, a credential id of 1 to 1023 bytes that fits, and a COSE key; without AT nothing follows unless ED is set. With ED: a well-formed CBOR map with text keys, parsed and ignored (no authenticator extensions are requested). Nothing may follow. AT is required for registration and refused for sign-in. RFU flag bits are ignored. |
| Credential id | `id` must equal `rawId`, which must be canonical unpadded base64url of 1 to 1023 bytes. At registration it must equal the credential id in authenticatorData. |
| User handle | On sign-in a user handle is required and must equal the credential owner's user id. |
| Counter | If either the stored or the new counter is non-zero, the new one must be strictly greater (`counter_regression`, a possible cloned authenticator). Authenticators without a counter always report 0, which is accepted. The new counter is stored with `updateCounter`, which re-checks it under the store lock, so two concurrent sign-ins with the same counter cannot both succeed. |
| CBOR | `skill/lib/identity/cbor.mjs`: unsigned and negative integers (safe JS range), byte and text strings (valid UTF-8), definite arrays, and definite maps with integer or text keys. Tags, floats, simple values, indefinite lengths, reserved encodings, non-minimal lengths or integers, duplicate map keys, lengths past the end, trailing bytes, inputs over 16 KiB, and nesting deeper than 8 (1 for COSE keys) are rejected with a `CborError`. Map key order is not checked, because browsers re-encode attestation objects. |

## Challenges

`skill/lib/identity/challenges.mjs` keeps challenges in memory:

- 32 random bytes from `crypto.randomBytes`, with a separate random 32-byte handle (`challenge_id`) that the client sends back.
- Single use: the first `consume()` removes the challenge before any check, so a failed attempt uses it up too.
- Short TTL: 2 minutes. The same value is sent as the ceremony `timeout`.
- Bound to the ceremony (`registration` or `authentication`) and, for registration, to the user.
- Bounded per ceremony: at most 64 pending sign-in challenges and, separately, 64 pending registration challenges. When a ceremony is full, its new options requests get `503 too_many_challenges` instead of evicting a live ceremony. Because the limits are separate, anonymous sign-in requests cannot use up the slots that operator registration needs.
- A server restart drops every pending ceremony.

## Rate limits

Token buckets shared by all clients (a loopback server behind a proxy cannot tell clients apart without trusting forwarded headers). Sign-in and registration each have their own pair:

- Options requests: 10 at once, refilling at 30 per minute.
- Failed verifications: 10 at once, refilling at 10 per minute. While empty, every verify request for that ceremony gets `429 rate_limited` with `Retry-After`.

Because the sign-in buckets are shared, someone who can reach the server can keep passkey sign-in rate limited. The tokenized URL still works as a fallback, and operator registration is unaffected because it draws on its own buckets.

## Errors

Every error response is `{ "error": { "code", "message" } }` with a fixed message that never includes request data.

**Sign-in** (`/auth/passkey/login/verify`) returns one generic error for every verification failure, so a response never shows whether a credential or user exists or why it was refused:

| Status | Code | When |
| --- | --- | --- |
| 401 | `sign_in_failed` | Any verifier error, unknown or consumed or expired or wrong-ceremony challenge, unknown credential, disabled user, wrong user handle, counter regression. The specific reason is logged to stderr as a code only. |
| 503 | `store_busy` | The identity or sessions store lock was busy for more than 1 second while saving the counter or the new session. Retry. |
| 503 | `identity_unavailable` | Verified, but the session could not be saved (the sessions file is corrupt or unreadable). |

Timing: an unknown credential id is not refused early. The server runs the full verification against a dummy public key of the same algorithm family (ES256, or RS256 when the signature has RSA length), generated at startup with its private half discarded, and then refuses with the same generic error. A disabled user is refused only after the real verification. So a failed sign-in does the same parsing and one signature verification whether or not the credential id is registered. Residual differences: the dummy RSA key is 2048-bit, so a registered 3072- or 4096-bit RSA key verifies a little more slowly, and a successful verification is followed by a counter write. Credential ids are random values chosen by authenticators, so even a measurable difference would not reveal users.

**Registration** is operator-only, so it returns the specific reason:

| Status | Code | When |
| --- | --- | --- |
| 400 | verifier code (table below), `challenge_unknown`, `challenge_expired`, `wrong_ceremony` | The response or challenge was refused. |
| 400 | `invalid_argument` | A bad `display_name` or `label` (the message names the field and rule, never the value). |
| 401 | `authentication_required` | No server-token cookie. |
| 403 | `user_disabled` | The target user is disabled. |
| 409 | `credential_exists` | That credential is already registered. |
| 409 | `owner_conflict` / `user_missing` | The store changed during the ceremony; start again. |
| 503 | `store_busy` | The store lock was busy; retry (`Retry-After: 2`). |
| 507 | `store_full` | The store would exceed 1 MiB; remove unused passkeys. |

**Any route:** `400 invalid_request` (not a JSON object, missing fields, query string), `403 origin_denied`, `404 not_found`, `405 method_not_allowed`, `408 body_timeout`, `413 body_too_large`, `415 unsupported_media_type`, `429 rate_limited`, `503 too_many_challenges`, `503 identity_unavailable` (the store file is corrupt or unreadable; details go to stderr as a code), `500 internal_error`.

Verifier codes (`WebAuthnError.code`): `malformed_response`, `invalid_client_data`, `wrong_type`, `challenge_mismatch`, `origin_mismatch`, `cross_origin`, `invalid_authenticator_data`, `rp_id_mismatch`, `user_not_present`, `user_not_verified`, `invalid_attestation`, `unsupported_attestation`, `unsupported_algorithm`, `invalid_public_key`, `credential_id_mismatch`, `user_handle_mismatch`, `bad_signature`, `counter_regression`, `invalid_argument`.

## Login page

The page is part of the kit (`skill/templates/login/`), not the knowledge repo, and is served before auth at `/auth/login/` only when `--passkeys` is on. With `--passkeys`, `/auth/login/` and `/auth/passkey/` are handled by the kit and never served from the repo. The page:

- has no inline script, style, or event handler; it loads `/auth/login/cockpit-login.js` and `/auth/login/cockpit-login.css` from the same origin;
- is served with `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, plus `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`;
- uses only the browser's native `navigator.credentials.create()` and `get()`, with base64url conversion in its own script. No third-party hosts.

Before this change `serve.mjs` sent no CSP at all. Only the login page and the passkey API get one; knowledge-repo pages are unchanged.

## Verifier API (`skill/lib/identity/webauthn.mjs`)

Stable for #9 and later:

```js
import { verifyRegistration, verifyAuthentication, WebAuthnError } from '../lib/identity/webauthn.mjs';

const registered = verifyRegistration({
  response,                 // PublicKeyCredential JSON from navigator.credentials.create()
  expectedChallenge,        // Uint8Array, at least 16 bytes, from the caller's challenge store
  rpId: 'example.com',
  origins: ['https://example.com'],
});
// { credentialId, publicKey, counter, alg, aaguid, transports, backupEligible, backedUp }
// credentialId and publicKey are base64url, ready for store.addCredential().

const signedIn = verifyAuthentication({
  response,                 // PublicKeyCredential JSON from navigator.credentials.get()
  expectedChallenge,
  rpId: 'example.com',
  origins: ['https://example.com'],
  credential: { id, publicKey, counter },  // from the identity store (base64url id and COSE key)
  expectedUserHandle,       // optional Uint8Array: the owner's user handle
  requireUserHandle: true,  // optional, default false
});
// { credentialId, counter, userHandle, backedUp }; persist counter with store.updateCounter().
```

Both functions are pure and synchronous: they read no clock, generate no challenge, and touch no file. They throw `WebAuthnError` (with `code`, see above) on any failure. Also exported: `normalizeRelyingParty({ rpId, origins })`, `SUPPORTED_ALGORITHMS`, `COSE_ALG_ES256`, `COSE_ALG_RS256`, `LIMITS`, and `WEBAUTHN_ERROR_CODES`. The lower-level parsers (`parseAuthenticatorData`, `parseCoseKey`, `derToRawEcdsa`, `checkClientData`) are exported for tests and may change.

Ceremonies (`skill/lib/identity/passkeys.mjs`) tie the verifier to the challenge and identity stores:

```js
const ceremonies = createPasskeyCeremonies({ store, rpId, origins, challenges? });
ceremonies.startRegistration({ displayName? })       // { challengeId, publicKey }
ceremonies.finishRegistration({ challengeId, response, label? })  // { userId, credentialId, createdOwner }
ceremonies.startAuthentication()                      // { challengeId, publicKey }
ceremonies.finishAuthentication({ challengeId, response })        // { userId, role, credentialId, counter }
```

`finishAuthentication()` returns the verified user id, role, and the label of the passkey used, and leaves the session decision to the caller. It throws `WebAuthnError`, `ChallengeError`, `PasskeyError` (`unknown_credential`, `user_disabled`), or `IdentityStoreError`; network-facing callers must collapse them as described under [Errors](#errors). `createPasskeyApi()` in `skill/lib/identity/passkey-http.mjs` provides the HTTP routes; its `onSignIn(result, { origin, req })` callback returns the response headers that grant a session (`serve.mjs` creates one in the [sessions store](sessions.md)).

## Not in this phase

- Registering passkeys for members, invites (#10), and owner recovery (#11). Members whose passkeys were added through the identity store API can sign in and get a session.
- Passkey routes in the standalone `intents-service.mjs`. The issue scope mentions it, but it has no sign-in surface to cover: it serves only the intents API on loopback, behind an authenticating reverse proxy that owns operator sign-in and forwards the operator as `X-Cockpit-Principal` together with a shared proxy secret. It issues no cookie and has no session, login page, or token of its own, so a passkey sign-in there would have nothing to grant; sign-in belongs to the proxy (or to `serve.mjs --passkeys`). Per-device sessions (#9) were added to `serve.mjs` only; the service still accepts only the proxy's shared secret. `createPasskeyApi()` and `createAccountApi()` are transport-free, so mounting them there later is small.
- Attestation formats other than `none`, algorithms other than ES256 and RS256, cross-origin iframes, and conditional (autofill) UI.

## Tests

- `test/cbor.test.mjs`: the decoder, including malformed, truncated, non-minimal, oversized, and deeply nested input, and a mutation fuzz loop.
- `test/webauthn.test.mjs`: the verifier with synthetic ES256 and RS256 credentials generated at runtime, and one negative test per item in #8.
- `test/passkey-ceremonies.test.mjs`: challenges and ceremonies with a real identity store, including the unknown-credential dummy verification.
- `test/passkey-serve.test.mjs`: HTTP error mapping, rate limits, the login page CSP, and `serve.mjs` end to end. Session behavior is tested in `test/sessions.test.mjs` and `test/session-serve.test.mjs` (see [`sessions.md`](sessions.md)).
- `test/webauthn-fixtures.test.mjs`: recorded real-browser fixtures from `test/fixtures/webauthn/*.json`, plus its harness run on a synthetic fixture.

### Recorded fixtures

`test/fixtures/webauthn/` holds six recordings from real browsers on Linux: Google Chrome 156 (ES256 and RS256) and Mozilla Firefox 160 (ES256 only; its software token has no RS256), each with a platform (`internal`) and a roaming (`usb`) authenticator. The browsers really ran `navigator.credentials.create()` and then `get()` twice on `https://example.com` (routed to a local test server); the first sign-in lists the credential in `allowCredentials` and the second is usernameless (empty `allowCredentials`), as the server signs in. The browsers produced the `clientDataJSON`, attestation objects, authenticator data, and signatures. The authenticators were each browser's built-in virtual (software) authenticator: Chrome's DevTools WebAuthn domain, and Firefox's WebDriver WebAuthn extension through geckodriver with its software token. They are not physical devices, so the fixtures prove interoperability with real browser WebAuthn stacks, not with any particular hardware. No fixture was edited after capture. The capture scripts are in `tools/webauthn-capture/` (development tools, not part of the kit and not run in CI). Fixtures from physical authenticators, for example a platform authenticator on another OS or a hardware security key, can be added later in the same format.
