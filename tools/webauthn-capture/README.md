# WebAuthn fixture capture (development tool)

These scripts recorded the fixtures in `test/fixtures/webauthn/`. They are not part of the kit, are never loaded at runtime, and add no dependencies. They need a desktop browser, so they are not run in CI.

## What the fixtures are

Each fixture is the real output of a real browser's `navigator.credentials.create()` and `navigator.credentials.get()`: the browser built `clientDataJSON`, talked CTAP2 to an authenticator, and returned the `attestationObject`, `authenticatorData` and signature unmodified. Nothing in a fixture was edited after capture.

The authenticators are the browsers' built-in **virtual** authenticators, not physical devices:

- **Google Chrome:** the DevTools Protocol `WebAuthn` domain (`WebAuthn.addVirtualAuthenticator`, CTAP2.1, user verification on), once as a platform authenticator (`internal`) and once as a roaming security key (`usb`), each with ES256 and RS256 keys.
- **Mozilla Firefox:** the WebDriver WebAuthn extension through geckodriver (`/webauthn/authenticator`, CTAP2, user verification on) with `security.webauth.webauthn_enable_softtoken=true` and `security.webauth.webauthn_enable_usbtoken=false`, as `internal` and as `usb`. Firefox's soft token offers ES256 only.

Fixtures from physical authenticators (for example a platform authenticator on another OS, or a hardware security key) can be added later in the same format.

## How they were recorded

1. `server.mjs` serves a blank page over HTTPS on a local port with a throwaway certificate for `example.com`.
2. The browser reaches it as `https://example.com`: Chrome with `--host-resolver-rules="MAP example.com:443 127.0.0.1:8443"` and `--ignore-certificate-errors-spki-list=<leaf SPKI hash>`; Firefox through `proxy.mjs` (a CONNECT proxy that only forwards `example.com:443`) and a throwaway CA installed with an enterprise `Certificates` policy.
3. `capture-chrome.mjs <cdp-port> <label> <internal|usb> <-7|-257> <out.json>` or `capture-firefox.mjs <label> <internal|usb> <-7|-257> <out.json>` adds the virtual authenticator, registers one discoverable credential with `attestation: "none"` and `userVerification: "required"`, then signs in twice with fresh challenges. The first sign-in lists the credential in `allowCredentials`; the second is usernameless (empty `allowCredentials`), as the server's own sign-in is.

The relying party is `example.com`, the origin is `https://example.com`, and the user is invented ("Ada Example", random 16-byte user id). Challenges are random bytes generated for the capture and stored in the fixture so tests can replay the ceremony. The certificates and keys used for the capture were throwaway and are not included.
