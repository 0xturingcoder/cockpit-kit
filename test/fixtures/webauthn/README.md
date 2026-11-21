# Recorded WebAuthn fixtures

One JSON file per browser and authenticator, recorded from a real browser against a test relying party. `test/webauthn-fixtures.test.mjs` loads every `*.json` file here. It verifies the registration, then each authentication in order (the signature counter must behave), then negative mutations of the recorded data: a flipped signature byte, tampered authenticatorData, wrong origin and rp id configuration, a replay against a fresh challenge (plus a stale counter when the authenticator keeps one), a registration clientDataJSON used to sign in, and an unknown credential.

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
- Record at least two authentications so the counter rule is exercised. Synced passkeys usually report a counter of 0 every time, which is valid.
