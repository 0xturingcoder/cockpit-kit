# Cockpit Kit

Cockpit Kit is a global AI skill and script kit for operating a local-first knowledge repo from any supported AI environment.

It is an AI-agent local memory kit, not the Red Hat Cockpit Linux server administration console. The naming overlap is intentional for now, and this project is not affiliated with Red Hat Cockpit.

## What it does

- Installs one canonical `SKILL.md` into supported AI environments.
- Resolves a configured local knowledge repo from any working directory.
- Creates or links a starter Cockpit-compatible static HTML knowledge repo.
- Lints pages against the Cockpit Kit page contract.
- Generates a deterministic static search index.
- Serves the local repo over a loopback-only HTTP server with token auth by default, with optional passkey (WebAuthn) sign-in.
- Optionally accepts operator page comments and captures through an opt-in write service.
- Provides an advisory write lock so several agents can safely share one knowledge repo.

## Requirements

- Node.js 20 or newer.
- Git, when creating a new starter knowledge repo with the default initial commit.
- macOS or Linux for v1.

No package-manager install is required for v1. Runtime code uses Node.js built-in modules only.

## Install

Clone the kit wherever you want it to live. The documented convention is:

```bash
git clone https://github.com/autojeremy/cockpit-kit ~/.local/share/cockpit-kit
```

Create a new starter knowledge repo and install adapters:

```bash
node ~/.local/share/cockpit-kit/skill/scripts/setup.mjs \
  --cockpit-root ~/cockpit \
  --adapters agents,hermes,claude \
  --yes
```

Or link an existing Cockpit-compatible knowledge repo:

```bash
node ~/.local/share/cockpit-kit/skill/scripts/setup.mjs \
  --cockpit-root /path/to/knowledge-repo \
  --adapters agents,hermes,claude \
  --yes
```

Setup writes machine-local config to `${XDG_CONFIG_HOME:-~/.config}/cockpit/config.toml`. The knowledge repo stays separate from the kit repo.

## Common commands

Resolve the configured knowledge repo:

```bash
node ~/.local/share/cockpit-kit/skill/scripts/where.mjs --json
```

Generate search index data:

```bash
node ~/.local/share/cockpit-kit/skill/scripts/search-index.mjs --root /path/to/knowledge-repo
```

Lint a knowledge repo strictly:

```bash
node ~/.local/share/cockpit-kit/skill/scripts/lint.mjs --root /path/to/knowledge-repo --strict
```

Serve a knowledge repo locally:

```bash
node ~/.local/share/cockpit-kit/skill/scripts/serve.mjs --root /path/to/knowledge-repo
```

`serve.mjs` binds to loopback by default and prints a tokenized URL. Use `--no-auth` only on a trusted machine.

## Multi-agent write lock

When several agents edit the same knowledge repo (on one machine, or over SSH into the machine that hosts it), their edit, lint, index, commit, and push steps can collide on `.cockpit/nav.toml`, the search index, and the git index. `lock.mjs` provides an advisory, cockpit-scoped write lock to serialize those operations.

```bash
# Wrap one whole operation; the lock is released even if the command fails.
node ~/.local/share/cockpit-kit/skill/scripts/lock.mjs run --holder <agent-name> \
  --purpose "render inbox" --wait 2m --root /path/to/knowledge-repo -- \
  sh -c '<edit> && node <kit>/skill/scripts/search-index.mjs --root /path/to/knowledge-repo && git -C /path/to/knowledge-repo add <files> && git -C /path/to/knowledge-repo commit -m "docs: ..." && git -C /path/to/knowledge-repo pull --rebase && git -C /path/to/knowledge-repo push'

# Inspect, or hold the lock across several separate commands.
node ~/.local/share/cockpit-kit/skill/scripts/lock.mjs status [--json]
node ~/.local/share/cockpit-kit/skill/scripts/lock.mjs acquire --holder <agent-name> [--purpose <text>] [--ttl 10m] [--wait 2m] [--pid <pid>]
node ~/.local/share/cockpit-kit/skill/scripts/lock.mjs release --holder <agent-name>
node ~/.local/share/cockpit-kit/skill/scripts/lock.mjs release --force   # operator override
```

From another machine, run the same command over SSH on the host that holds the repo, for example `ssh <user>@<cockpit-host> 'node ~/cockpit-kit/skill/scripts/lock.mjs run --holder <agent-name> --root ~/<knowledge-repo> --wait 2m -- <command...>'`.

- **Where:** `<root>/.cockpit/lock`, a JSON record `{holder, purpose, pid, pid_bound, host, acquired_at, expires_at}`. It is created atomically (written to a temp file, then hard-linked into place, which fails if a lock already exists), so exactly one agent wins and readers never see a partial record. `.cockpit/` is not served (only `.cockpit/search-index.json` is), so the lock is never exposed over HTTP.
- **Gitignore:** keep it out of commits with `/.cockpit/lock*` in the repo's `.gitignore`. The starter template ships this; for existing repos, add the line yourself. `lock.mjs` warns when the lock is not ignored.
- **Holders:** `--holder` is a short label (letters, digits, `. _ @ : -`), unique per agent. The same holder acquiring again renews the lock instead of deadlocking. Only the holder may release it; `--force` is for operators clearing a stuck lock.
- **Expiry and stale locks:** every lock has a TTL (`--ttl`, default `10m`); `run` renews it while the command is running. An expired lock, or a `run` (or `acquire --pid`) lock whose process is gone on the same host, is taken over by the next acquirer with a message naming the previous holder. A detached `acquire` lock without `--pid` only expires by TTL.
- **Waiting:** `--wait <duration>` polls for a busy lock (default `0s`, fail immediately). A busy lock exits with status `75`, so scripts can retry.
- **`run`:** acquires, runs the command (no shell; use `sh -c '...'` for pipelines), releases, and exits with the command's status. Signals (`SIGINT`, `SIGTERM`, `SIGHUP`) are forwarded to the command’s process group, including shell workers. The lock remains held and renewed until all live group members stop, even if the immediate shell exits first. Commands must not daemonize or escape that group while writing. The command sees `COCKPIT_LOCK_HOLDER=<holder>`.
- **Kit commands honor it:** `search-index.mjs` checks the lock before writing. With no lock, nothing changes. If another holder has a live lock, it waits up to `--lock-wait` (default `10s`) and then exits `75` with the holder's details. Under `lock run`, or with `--holder <name>` / `COCKPIT_LOCK_HOLDER` matching the holder, it proceeds. A stale lock only triggers a warning.
- **Advisory:** the lock coordinates cooperating tools and agents. Plain `git`, editors, and scripts that do not check it are not blocked.

## Operator comments and capture (MVP, opt-in)

An optional write service lets the operator leave page comments and quick captures from the browser and follow them to an agent's outcome. It is off by default; plain `serve.mjs` stays read-only and static sites are unaffected.

- **Widget:** starter pages include `cockpit-intents.js` (plus `cockpit-intents.css`). It probes `GET /api/cockpit/v1/capabilities` and stays hidden when the service is absent. It offers Comment (on this page), Capture, and a Requests panel with Active and Done views (status, outcome, page link, commit id).
- **State:** one private JSON file per knowledge repo at `${XDG_STATE_HOME:-~/.local/state}/cockpit-kit/<repo-hash>/intents.json` (mode `0600`, atomic temp+rename), never inside the served tree, `.cockpit/`, or the search index.
- **Trust:** only `operator_message` and operator follow-ups are instructions; quotes, captured text, and URLs go in `payload` as untrusted data. Mutations require an exact `Origin`, a CSRF token from `capabilities`, `application/json`, and a body of 32 KiB or less. Client output paths and service-controlled fields are rejected; comment targets must be existing pages inside the root.

Local write mode, behind the existing cookie auth (`--write --no-auth` is refused):

```bash
node ~/.local/share/cockpit-kit/skill/scripts/serve.mjs --root /path/to/knowledge-repo --write
```

Behind an authenticating reverse proxy, run the standalone loopback service and route `/api/cockpit/v1/*` to it. The proxy must inject `X-Cockpit-Proxy-Secret` (contents of the printed secret file) and optionally `X-Cockpit-Principal`, and must strip both from client requests:

```bash
node ~/.local/share/cockpit-kit/skill/scripts/intents-service.mjs \
  --root /path/to/knowledge-repo --port 18767 \
  --origin https://cockpit.example.com \
  --origin https://cockpit.example.net
```

Allowed origins: repeat `--origin` once per browser origin (both servers accept `--origin <o>` and `--origin=<o>`). Each value must be exactly `scheme://host[:port]` with an `http` or `https` scheme. Values are normalized at startup (lowercase host, default port dropped, one trailing `/` tolerated). Wildcards (`*`), comma-separated lists, paths, queries, fragments, and credentials are rejected, so a typo fails at startup instead of silently allowing nothing. Request `Origin` headers must then match one configured origin exactly: no subdomain, scheme, port, or trailing-slash variants. The CSRF token from `capabilities` is tied to the operator, not the origin, so it works from any allowed origin. `serve.mjs --write` uses the same flag. Without `--origin` it allows only its own loopback origins.

Agents process the queue with the consumer CLI (see `skill/SKILL.md`, "Operator Request Queue"):

```bash
node ~/.local/share/cockpit-kit/skill/scripts/intents.mjs summary
node ~/.local/share/cockpit-kit/skill/scripts/intents.mjs claim --json
node ~/.local/share/cockpit-kit/skill/scripts/intents.mjs resolve <id> --claim <token> \
  --outcome changed --summary "..." --page /route/ --commit <sha>
```

Optional wake hook: `--webhook-url <url>` or `COCKPIT_INTENTS_WEBHOOK_URL` makes either server POST `{"event","intent_id","kind","at"}` (no request content) when a new intent or operator reply arrives. Failures are logged and ignored.

If the receiver needs an auth key, add `--webhook-headers-file <path>` (or `COCKPIT_INTENTS_WEBHOOK_HEADERS_FILE=<path>`). It works with both `intents-service.mjs` and `serve.mjs --write`, and requires a webhook URL. The file holds one `Header-Name: value` per line; blank lines and `#` comments are ignored:

```text
# chmod 600 this file
Authorization: Bearer <your-receiver-token>
X-Example-Key: <another-value>
```

The file is read once at startup. The server refuses to start if the file is a symlink, is not owned by the service user, or has any group or world permission bits (use `chmod 600`). It also refuses invalid header names, CR/LF or other control characters in values, empty values, duplicates, and headers the service manages itself (`Host`, `Content-Type`, `Content-Length`, ...). The headers go on every webhook POST. Their values are never logged or included in error messages, and startup output shows only how many headers were loaded.

This is a lean first version of the [design](docs/design/operator-comments-and-capture.md); see its "MVP implementation status" section for what is deferred.

## Users and credentials store

`skill/lib/identity/store.mjs` keeps users (stable opaque id, display name, `owner` or `member` role) and their passkey credentials (credential id, COSE public key, signature counter, transports, created time, label) in one private JSON file per knowledge repo. Passkey sign-in (below) reads and updates it.

- **Where:** `${XDG_STATE_HOME:-~/.local/state}/cockpit-kit/<repo-hash>/identity.json` by default. Override it with `serve.mjs --identity-store <path>` or `identity_store = "<path>"` in `.cockpit/serve.toml`. The path must be absolute (or start with `~/`) and must resolve outside the served root, comparing real paths; otherwise `serve.mjs` refuses to start.
- **Behavior change:** this check runs at every `serve.mjs` start, with or without `--passkeys`, and it covers the default path. If the served root is at or above `$HOME` (or above `XDG_STATE_HOME`), `serve.mjs` now refuses to start. Serve a narrower root, or set `--identity-store` to a path outside the root.
- **Safety:** writes are atomic (fsynced `0600` temp file, then rename), serialized by a short token lock, and capped at 1 MiB (`store_full`). Loading refuses symlinks and files with any group or world permission bit (`chmod 600`), and fails closed on anything invalid, including a store without exactly one `owner`. Error messages never include credential material.

Schema, API, and error codes: [`docs/identity-store.md`](docs/identity-store.md).

## Passkey sign-in (opt-in)

`serve.mjs --passkeys` adds WebAuthn passkey registration and sign-in, with a small login page at `/auth/login/`. It is built on `node:crypto` with no dependencies and accepts a narrow subset: `none` attestation only, ES256 and RS256 only, user verification required, single-use two-minute challenges, and the signature counter rule.

```bash
node ~/.local/share/cockpit-kit/skill/scripts/serve.mjs --root /path/to/knowledge-repo --passkeys
```

- **First passkey:** open the printed "Add a passkey" URL (`http://localhost:<port>/auth/login/?token=...`), enter your name, and add a passkey. The first registration creates the owner in the identity store. Use `localhost`, not `127.0.0.1`, for passkeys.
- **Sign in:** open `/auth/login/` and choose "Sign in with a passkey". Each sign-in, owner or member, gets its own server-side session (`cockpit_session` cookie: `HttpOnly`, `SameSite=Strict`, `Max-Age` equal to the lifetime, `Secure` on https). Only a hash of the session token is stored, in `sessions.json` next to the identity store.
- **Devices:** `/auth/settings/` lists your signed-in devices and lets you revoke any of them or sign out. The owner can also revoke any user's sessions and remove their passkeys (except the owner's last one). Revoked and expired sessions are refused on the next request.
- **Invites:** to let someone else sign in, the owner creates an invite under **Invites** on `/auth/settings/` and sends them the one-time link (`/auth/invite/#<token>`). They open it and create their own passkey, which makes them a member and signs them in. A link works once, expires after 24 hours (`--invite-lifetime`), and can be revoked while pending; only a hash of its token is stored, in `invites.json` next to the identity store, and the token stays in the URL fragment, so it never reaches server logs or referrers.
- **Intents:** with `--write`, the owner's passkey session works on every `/api/cockpit/v1` route, with a CSRF token bound to that session; the server token still works too. Member sessions can read pages but not use the intents API yet.
- **Config:** `--rp-id <domain>` (default `localhost`), `--origin <origin>` (repeatable; default `http://localhost:<port>`), `--session-lifetime <duration>` (default `90d`), and `--invite-lifetime <duration>` (default `24h`, at most `7d`), command line only. Each origin must be the rp id or a subdomain of it, over https except for `localhost`. `--passkeys` needs auth, and it refuses an `identity_store` set in `.cockpit/serve.toml`; use `--identity-store` or the default.
- **Safety:** the relying-party id and origins never come from request headers. Sign-in failures all return the same `401 sign_in_failed`, and failed attempts are rate limited. The login page has no inline script and is served with a strict Content-Security-Policy.

Ceremonies, the supported subset, error codes, and the verifier API: [`docs/passkeys.md`](docs/passkeys.md). Sessions, the account API, and which routes accept a session: [`docs/sessions.md`](docs/sessions.md). Invite links, their lifecycle, and how the token stays out of logs: [`docs/invites.md`](docs/invites.md).

## Themes: Light, Dark, System

The starter knowledge repo ships a light and a dark palette and a compact theme switcher on every starter page: three small icon buttons (System, Light, Dark) fixed in the top-right corner of the viewport.

- **System** (default) follows the operating system's `prefers-color-scheme`, including changes while the page is open. **Light** and **Dark** pin a palette.
- The choice is a non-private display preference stored only in the browser's `localStorage` under `cockpit-theme`. Nothing is sent anywhere.
- `cockpit-theme.js` is a tiny same-origin script loaded synchronously in `<head>`, right after `cockpit.css`. It sets `<html data-theme="system|light|dark">` and the `color-scheme` meta before the body is painted, so a stored choice does not flash the wrong palette. No inline script is required.
- The switcher is a native radio group, so arrow keys move between options and screen readers announce the option names; a polite live region reports which scheme System resolved to. It respects safe-area insets, has a visible focus ring, keeps at least a 32px tap target (36px on touch screens), and drops its transition under reduced motion. While it is visible, the stylesheet reserves room for it beside the search field on narrow screens and above the page column on mid widths.
- `cockpit.css` defines the palettes as custom-property token sets: `:root` / `:root[data-theme="light"]`, `:root[data-theme="dark"]`, and a `@media (prefers-color-scheme: dark)` block for System. Without JavaScript, pages still follow the operating system and the switcher stays hidden.

When writing or rendering pages, use the tokens (`var(--bg)`, `var(--surface)`, `var(--ink)`, `var(--ink-soft)`, `var(--accent)`, `var(--rule)`, and so on) instead of literal colors so the page follows the theme. Add new color tokens to every theme block with the same name. To opt a page into the switcher, copy the `<head>` script tag and the `fieldset.theme-switch` markup (at the end of the `<nav>`) from a starter page; the stylesheet positions it. See the page contract for the full guidance.

## AI adapters

Setup can install symlinked adapters. Each adapter symlink points at the kit's `skill/` directory (the isolated AI-skill payload), not the repo root:

- Generic agents: `~/.agents/skills/cockpit -> /absolute/path/to/cockpit-kit/skill`
- Hermes: `${HERMES_HOME:-~/.hermes}/skills/productivity/cockpit -> /absolute/path/to/cockpit-kit/skill`
- Claude Code: `~/.claude/skills/cockpit -> /absolute/path/to/cockpit-kit/skill`

Symlinked adapters are live agent policy. Review diffs before pulling updates into an installed kit clone, and prefer tagged releases for stable installs.

## Development

Run the test suite with Node's built-in test runner:

```bash
node --test
```

Check whitespace before committing:

```bash
git diff --check
```

The GitHub Actions workflow runs `node --test` on Ubuntu and macOS with Node 20 and 22.

## Documentation

- Page contract: [`skill/reference/page-contract.md`](skill/reference/page-contract.md)
- Users and credentials store (schema and API): [`docs/identity-store.md`](docs/identity-store.md)
- Passkey sign-in (ceremonies, supported subset, config, errors, verifier API): [`docs/passkeys.md`](docs/passkeys.md)
- Per-device sessions (lifetime, cookie, list and revoke, settings page, intents routes): [`docs/sessions.md`](docs/sessions.md)
- Invites (one-time links to enroll a member's passkey, lifecycle, routes, errors): [`docs/invites.md`](docs/invites.md)
- Design (lean MVP implemented, hardening deferred): [Operator comments and capture lifecycle](docs/design/operator-comments-and-capture.md) ([#10](https://github.com/autojeremy/cockpit-kit/issues/10)).

## Security

Cockpit Kit operates on local, private knowledge repositories. Do not publish your knowledge repo unless you have separately sanitized it.

Report suspected security issues through GitHub security advisories for this repository. See [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).
