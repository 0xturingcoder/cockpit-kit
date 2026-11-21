# Security Policy

Cockpit Kit is intended to be open source and operates on local, private knowledge repositories.

The `skill/scripts/serve.mjs` local server binds to loopback only by design and defaults to bearer-token cookie auth. Running it with `--no-auth` exposes the served tree to any local process or web page for as long as the server is running; only use `--no-auth` on a trusted machine.

The users and credentials store (`skill/lib/identity/store.mjs`, see `docs/identity-store.md`) must live outside the served root; the server refuses a path inside it, comparing real paths. The file is written atomically with mode `0600`, and loading refuses symlinks and group- or world-accessible files. Validation errors never include credential ids or public keys.

Please report suspected security issues privately by opening a GitHub security advisory for this repository. If advisories are not available to you, open a minimal public issue that says you have a security report to share, without including exploit details or private data.

Do not include private Cockpit data, tokens, machine-specific paths, or other sensitive material in public reports.
