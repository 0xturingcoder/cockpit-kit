# Users and credentials store

Phase 1 of passkeys and identity. The store records who may sign in to a Cockpit: users, their role, and the passkey (WebAuthn) credentials each user has registered. Later features (passkey sign-in, sessions, invites) read identities only through the API below, so the JSON file can be swapped for a small database without changing callers.

This phase adds the store and its validation only. Nothing verifies passkeys or serves a login page yet.

## Location

One private JSON file per knowledge repo. The path comes from the serve config, highest precedence first:

1. `serve.mjs --identity-store <path>` (or `--identity-store=<path>`).
2. `identity_store = "<path>"` in `<root>/.cockpit/serve.toml`.
3. Default: `${XDG_STATE_HOME:-~/.local/state}/cockpit-kit/<repo-hash>/identity.json`, next to the intents state.

Configured paths must be absolute or start with `~/`. `parseServeConfig()` returns the result as `identityStore` and refuses to start if the path is inside the served root. The default path is checked the same way, so an `XDG_STATE_HOME` or `HOME` inside the root is refused too. `openIdentityStore()` checks again. Both checks compare the resolved path, so `..` segments cannot lead back into the root, and the real path, so a symlinked directory that points at the root is refused too. A path that goes through the root is also refused, even if a symlink inside the root leads somewhere else.

## File safety

- **Owner-only:** a new store directory is created with mode `0700`. An existing directory is not changed, but it is refused (`unsafe_path`) if it is a symlink, and refused (`unsafe_permissions`) if group or others can write to it, since anyone who can write to the directory can rename a file over the store. The file is always written with mode `0600`.
- **Atomic writes:** each change goes to an exclusive temp file in the same directory (`0600`). The temp file is fsynced and renamed over the store, then the directory is fsynced where the platform allows it. Readers see the old file or the new one, never a partial one. If any step fails, the temp file is removed and the old file stays as it was.
- **One writer at a time:** each change takes a lock file (`<file>.lock`), re-reads the file, applies the change, validates the result, and writes it. Concurrent writers (for example the server and a CLI) do not lose each other's updates. The lock holds a random token naming its owner, and it is hard-linked into place, so it exists either fully written or not at all.
  - Release and stale takeover both rename the lock to a unique name first, so only one process can claim a given lock. The lock is deleted only if its token is the expected one. If a process moved a lock that someone had just re-taken, it links that lock straight back. A writer never deletes a lock it does not own.
  - A lock older than `lockStaleMs` (30 seconds by default) counts as abandoned and is taken over. A change takes milliseconds, so this only happens after a crash. A writer checks that the lock still carries its token right before it renames the new file into place. If the lock was taken over, it writes nothing and throws `store_busy`.
  - Limit: the lock is advisory and only this module honors it. Two writers can overlap only if all of these happen at once: a writer crashed and left a stale lock, two others take it over at the same moment, and a third writer takes the lock in the instant before the moved lock is linked back.
- **Size cap (1 MiB):** `load()` refuses a file larger than 1 MiB (1,048,576 bytes). Every change is serialized first, and a change that would make the file larger than that is refused with `store_full` before anything is written. The previous file stays loadable, and removing credentials or users still works. The cap, not the per-field limits below, is the binding limit. One credential at the field maxima (1023-byte id, 2048-byte key) takes about 4.5 KB, so about 230 fit. A typical passkey (32-byte id, P-256 key) takes about 0.4 KB, so about 2,500 fit.
- **Permissions are enforced, not repaired:** loading refuses a symlink, a non-regular file, a file owned by another user, or a file with any group or world permission bit. Fix it with `chmod 600 <file>`; the store never widens or silently repairs permissions. On Windows, mode bits are not checked.
- **One open, then checks:** the file is opened once with `O_NOFOLLOW` (where the platform has it; on Windows a symlink is refused before opening). The type, mode, owner, and size checks run on that open file, and the content is read from it, at most 1 MiB plus one byte. Swapping the path after it is opened has no effect. Open and read failures become `unsafe_file` (a symlink) or `unreadable`, without the path or the underlying system error.
- **Fails closed:** invalid JSON, an unknown or missing field, an unsupported `schema_version`, a bad or duplicate id, an unknown role, or anything other than exactly one owner makes `load()` and every change throw. A missing file is an error too (`missing`) until the owner is created.
- **No credential material in errors:** messages name fields by position (`users[0].credentials[1].id`) and never include ids, public keys, or file content. `JSON.parse` messages are not passed through, because they can quote the file.

## Schema (`schema_version = 1`)

```json
{
  "schema_version": 1,
  "users": [
    {
      "id": "usr_3q2-7wEXAMPLEonlyAAAAA",
      "display_name": "Ada Example",
      "role": "owner",
      "disabled": false,
      "created_at": "2026-01-02T03:04:05.000Z",
      "credentials": [
        {
          "id": "q83vEjRWeJA",
          "public_key": "pQECAyYgASFYIA...",
          "counter": 0,
          "transports": ["internal", "hybrid"],
          "created_at": "2026-01-02T03:05:00.000Z",
          "label": "Work laptop"
        }
      ]
    }
  ]
}
```

User fields:

| Field | Rule |
| --- | --- |
| `id` | Stable, opaque, unique. 8 to 64 characters of `A-Z a-z 0-9 _ -`. Generated as `usr_` plus 16 random bytes in base64url unless the caller supplies one. Never reused, never derived from the name. |
| `display_name` | 1 to 128 characters, no leading or trailing whitespace, no control characters, and no bidirectional or invisible formatting characters (U+200B to U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066 to U+2069, U+061C, U+180E, U+FEFF), so one name cannot be made to look like another. |
| `role` | `owner` or `member`. Exactly one user is the `owner`. |
| `disabled` | `true` or `false`. Disabled users must not sign in. |
| `created_at` | ISO 8601 UTC timestamp, as written by `Date.prototype.toISOString()`. |
| `credentials` | Up to 32 credentials. May be empty, for example before a user's first passkey is registered. |

Credential fields:

| Field | Rule |
| --- | --- |
| `id` | WebAuthn credential id (raw id bytes), canonical unpadded base64url, 1 to 1023 bytes. Unique across all users, not just within one user. |
| `public_key` | The credential's COSE_Key bytes from attestation, canonical unpadded base64url, at most 2048 bytes. The store checks only that it is a CBOR map. Decoding and algorithm checks happen at verification time. |
| `counter` | Last accepted signature counter, an integer from 0 to 2^32-1. |
| `transports` | Up to 8 distinct lowercase transport hints (`usb`, `nfc`, `ble`, `smart-card`, `hybrid`, `internal`, ...), as reported by the browser. |
| `created_at` | ISO 8601 UTC timestamp. |
| `label` | Operator-facing name for the device, 0 to 64 characters, with the same character rules as `display_name`. |

The per-field limits (1000 users, 32 credentials per user, and the sizes above) bound each record. The whole file must also fit in 1 MiB, and that cap is reached first (see [File safety](#file-safety)).

Unknown fields are rejected at every level. Any future change to the format bumps `schema_version`.

## API (`skill/lib/identity/store.mjs`)

```js
import { openIdentityStore, findCredential, findUser } from '../lib/identity/store.mjs';

const store = openIdentityStore({ file: config.identityStore, root: config.root });
const owner = store.createUser({ displayName: 'Ada Example', role: 'owner' });
const member = store.createUser({ displayName: 'Test Member' });
const credential = store.addCredential(member.id, {
  id: rawIdBytes,              // Uint8Array or base64url string
  publicKey: coseKeyBytes,     // Uint8Array or base64url string
  counter: 0,
  transports: ['internal'],
  label: 'Phone',
});

const data = store.load();
const hit = findCredential(data, credential.id); // { user, credential } or null
```

| Function | Behavior |
| --- | --- |
| `openIdentityStore({ file, root, now?, lockWaitMs?, lockStaleMs? })` | Checks that `file` is absolute and outside `root`, then returns a frozen store object. Nothing is read or written yet. `now` is an optional clock for tests. `lockWaitMs` (default 5000) is how long a change waits for a busy lock, and `lockStaleMs` (default 30000) is the age after which a lock counts as abandoned. |
| `store.load()` | Reads and fully validates the file. Returns a copy of the document. Throws `missing` if the file does not exist. |
| `store.createUser({ displayName, role = 'member', id? })` | Adds an enabled user with no credentials. The first user must be the `owner`, and creating it creates the file. A second owner is refused. |
| `store.addCredential(userId, { id, publicKey, counter = 0, transports = [], label = '' })` | Registers a credential for an enabled user. The credential id must not exist for any user. |
| `store.updateCounter(credentialId, counter)` | Stores a newer signature counter. The counter only moves forward: a value less than or equal to the stored one throws `counter_regression`, which the caller should treat as a possibly cloned authenticator. `0` to `0` is accepted without writing, because authenticators without a counter always report 0. Refused for disabled users. |
| `store.removeCredential(credentialId)` | Removes the credential and returns it. Allowed for disabled users. |
| `store.disableUser(userId)` | Disables a member. Calling it again does nothing. The owner cannot be disabled; ownership transfer is out of scope for this phase. |
| `findUser(data, userId)` / `findCredential(data, credentialId)` | Pure lookups over a loaded document. They return `null` when nothing matches. |
| `validateIdentityData(data)` | Validates a whole document (used by `load()` and before every write). |
| `assertOutsideRoot(file, root)` | The path check used by the store and the serve config. |

The API is synchronous. A change that finds the lock busy blocks the calling thread until the lock frees up or `lockWaitMs` passes (5 seconds by default). In `serve.mjs` that blocks the event loop, so passkey sign-in (#8) should keep changes such as `updateCounter` off the hot path, or account for the wait. `load()` takes no lock and does not wait.

Every function returns plain copies. Changing a returned object does not change the store. Callers decide policy: for example, sign-in code must check `user.disabled` after `findCredential()`.

Failures throw `IdentityStoreError` with a stable `code`:

| Code | Meaning |
| --- | --- |
| `missing` | The file does not exist yet. |
| `invalid_store` | The file on disk is bad: invalid JSON, a missing or unknown field, a value out of range, or a file larger than 1 MiB. |
| `store_full` | The change would make the file larger than 1 MiB. Nothing was written. |
| `unsupported_schema` | `schema_version` is not `1`. |
| `invalid_id` / `invalid_role` | A malformed user id, or a role other than `owner` / `member`. |
| `duplicate_id` | A user id or credential id that already exists. |
| `owner_required` | Not exactly one owner, the first user is not the owner, or an attempt to disable the owner. |
| `not_found` | No user or credential with that id. |
| `user_disabled` | Adding a credential to, or updating a counter for, a disabled user. |
| `counter_regression` | The signature counter did not increase. |
| `unsafe_path` / `unsafe_file` / `unsafe_permissions` | The path is inside the root or its directory is a symlink; the file is a symlink or not a regular file; or the file has the wrong owner or mode, or its directory is writable by group or others. |
| `store_busy` | Another writer held the lock for longer than `lockWaitMs` (5 seconds by default). |
| `invalid_argument` | A bad argument to an API call, such as a malformed base64url credential id or public key, a counter out of range, or a display name or label that breaks the field rules. This is bad caller (client) input, not a corrupt store. |
| `unreadable` | The file exists but could not be opened or read (for example, permission denied). |
