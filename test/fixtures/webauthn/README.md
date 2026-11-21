# Recorded WebAuthn fixtures

One JSON file per browser and authenticator, recorded from a real browser against a test relying party.

## What is here

| File | Browser | Authenticator | Algorithm |
| --- | --- | --- | --- |
| `chrome-internal-es256.json` | Google Chrome 156, Linux | Chrome virtual authenticator, platform (`internal`) | ES256 |
| `chrome-internal-rs256.json` | Google Chrome 156, Linux | Chrome virtual authenticator, platform (`internal`) | RS256 |
| `chrome-usb-es256.json` | Google Chrome 156, Linux | Chrome virtual authenticator, roaming (`usb`) | ES256 |
| `chrome-usb-rs256.json` | Google Chrome 156, Linux | Chrome virtual authenticator, roaming (`usb`) | RS256 |
| `firefox-internal-es256.json` | Mozilla Firefox 160, Linux | Firefox virtual authenticator, platform (`internal`) | ES256 |
| `firefox-usb-es256.json` | Mozilla Firefox 160, Linux | Firefox virtual authenticator, roaming (`usb`) | ES256 |

Provenance, precisely:

- **Real browsers.** Each file is the output of a real, unmodified Google Chrome or Mozilla Firefox calling `navigator.credentials.create()` and then `navigator.credentials.get()` twice on `https://example.com`, which was routed to a local test server. The browser built `clientDataJSON` and returned the attestation object, authenticator data, and signatures.
- **Virtual (software) authenticators, not physical devices.** Chrome used its built-in virtual authenticator (DevTools Protocol WebAuthn domain, CTAP2.1). Firefox used the WebDriver WebAuthn extension through geckodriver with its software token enabled (CTAP2). Both were configured with resident keys and user verification. Firefox's software token offers ES256 only, so there is no Firefox RS256 fixture.
- **Unedited.** No fixture was changed after capture. The `provenance` block in each file was written by the capture script.
- **Invented data.** The relying party is `example.com`, the user is "Ada Example" with a random user id, and the challenges are random bytes generated for the capture.
- **Capture tools** are in `tools/webauthn-capture/` with their own README. They are development tools: not imported by the kit, not run in CI, and without dependencies.

These fixtures show the verifier accepts what real browser WebAuthn stacks produce. They say nothing about specific hardware. Fixtures from physical authenticators (for example a platform authenticator on another OS, or a hardware security key) can be added later in the same format; add a row above and describe the device honestly in `provenance`.

## Format and test

`test/webauthn-fixtures.test.mjs` loads every `*.json` file here. It verifies the registration, then each authentication in order (the signature counter must behave), then negative mutations of the recorded data: a flipped signature byte, tampered authenticatorData, wrong origin and rp id configuration, a replay against a fresh challenge (plus a stale and an equal counter when the authenticator keeps one), a registration clientDataJSON used to sign in, and an unknown credential.

Fixtures are public. Use invented user data ("Ada Example") and a reserved name as the rp id and origin host: `example.com`, `example.net`, `example.org`, a subdomain of one of them, or a `.test`, `.example`, `.invalid`, or `localhost` name. The test rejects any other host. Do not record from a live deployment, and do not include real names, emails, or machine details in `provenance`.

```json
{
  "provenance": {
    "browser": "Example Browser",
    "browser_version": "1.2.3",
    "os": "Example OS 4",
    "authenticator": "platform authenticator (synced passkey)",
    "captured": "YYYY-MM-DD",
    "method": "how the responses were captured",
    "notes": "anything unusual"
  },
  "rp_id": "example.com",
  "origin": "https://example.com",
  "user": { "id": "<base64url user handle>", "name": "ada@example.com", "display_name": "Ada Example" },
  "registration": {
    "challenge": "<base64url>",
    "response": {
      "id": "<base64url>",
      "rawId": "<base64url>",
      "type": "public-key",
      "response": { "clientDataJSON": "<base64url>", "attestationObject": "<base64url>", "transports": ["internal"] },
      "authenticatorAttachment": "platform",
      "clientExtensionResults": {}
    }
  },
  "authentications": [
    {
      "challenge": "<base64url>",
      "response": {
        "id": "<base64url>",
        "rawId": "<base64url>",
        "type": "public-key",
        "response": { "clientDataJSON": "<base64url>", "authenticatorData": "<base64url>", "signature": "<base64url>", "userHandle": "<base64url>" }
      }
    }
  ]
}
```

Recording notes:

- Request `attestation: "none"`, `userVerification: "required"`, and ES256 (-7) or RS256 (-257). The verifier accepts only `none` attestation; a browser that returns another format (for example `packed` self attestation) fails registration by design.
- All binary fields are unpadded base64url, as `PublicKeyCredential.toJSON()` produces.
- Record at least two authentications so the counter rule is exercised (all six fixtures here have non-zero, increasing counters). Synced passkeys usually report a counter of 0 every time, which is valid.
