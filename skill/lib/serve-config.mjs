import fs from 'node:fs';
import path from 'node:path';
import { ArgumentError, resolveRoot, validateCockpitRoot } from './config.mjs';
import { parseToml } from './toml.mjs';
import { normalizeOrigin, normalizeOrigins } from './intents/origins.mjs';
import { stateDirFor } from './intents/store.mjs';
import { IDENTITY_STORE_FILE, IdentityStoreError, assertOutsideRoot } from './identity/store.mjs';
import { expandHome } from './paths.mjs';
import { normalizeRelyingParty } from './identity/webauthn.mjs';
import { DEFAULT_SESSION_LIFETIME_MS, MAX_SESSION_LIFETIME_MS, MIN_SESSION_LIFETIME_MS, SESSIONS_FILE } from './identity/sessions.mjs';
import { DEFAULT_INVITE_LIFETIME_MS, INVITES_FILE, MAX_INVITE_LIFETIME_MS, MIN_INVITE_LIFETIME_MS } from './identity/invites.mjs';

export const DEFAULT_SERVE_HOST = '127.0.0.1';
export const DEFAULT_SERVE_PORT = 18765;

function takeValue(argv, index, arg) {
  const value = argv[index + 1];
  if (!value || value.startsWith('-')) throw new ArgumentError(`${arg} requires a value`);
  return value;
}

function takePathValue(argv, index, arg) {
  const value = argv[index + 1];
  if (value === '--') {
    const escaped = argv[index + 2];
    if (!escaped) throw new ArgumentError(`${arg} requires a path argument`);
    return { value: escaped, index: index + 2 };
  }
  if (!value || value.startsWith('-')) throw new ArgumentError(`${arg} requires a path argument`);
  return { value, index: index + 1 };
}

function isLoopbackHost(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
}

function parseHost(value, source) {
  if (typeof value !== 'string' || value.trim() === '') throw new ArgumentError(`${source} must be a non-empty string`);
  if (!isLoopbackHost(value)) throw new ArgumentError(`${source} must be localhost, 127.0.0.1, ::1, or [::1]`);
  return value;
}

function parsePort(value, source) {
  const port = typeof value === 'number' ? value : Number.parseInt(String(value), 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535 || String(value).trim() !== String(port)) {
    throw new ArgumentError(`${source} must be an integer from 0 to 65535`);
  }
  return port;
}

export const DEFAULT_RP_ID = 'localhost';

// Passkey settings come only from the command line. The relying-party id and
// origins are checked here so a mismatch fails at startup; without --origin
// the server's own http://localhost:<port> origin is used (port 0 binds later,
// so the check uses the bare localhost origin).
const DURATION_UNITS = Object.freeze({ m: 60 * 1000, h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000 });

// A whole number of minutes, hours, or days, such as 90d, 12h, or 30m,
// between `min` and `max` (both given as milliseconds and as text).
export function parseDuration(value, { source, min, max, range, examples }) {
  const match = /^([1-9][0-9]{0,5})([mhd])$/.exec(String(value));
  const ms = match ? Number(match[1]) * DURATION_UNITS[match[2]] : Number.NaN;
  if (!(ms >= min && ms <= max)) {
    throw new ArgumentError(`${source} must be a whole number of minutes, hours, or days (for example ${examples}) from ${range}`);
  }
  return ms;
}

export function parseSessionLifetime(value, source = '--session-lifetime') {
  return parseDuration(value, { source, min: MIN_SESSION_LIFETIME_MS, max: MAX_SESSION_LIFETIME_MS, range: '5m to 400d', examples: '90d, 12h, or 30m' });
}

export function parseInviteLifetime(value, source = '--invite-lifetime') {
  return parseDuration(value, { source, min: MIN_INVITE_LIFETIME_MS, max: MAX_INVITE_LIFETIME_MS, range: '5m to 7d', examples: '24h, 3d, or 30m' });
}

function resolvePasskeys(flags, { auth, identityStore, origins, port }) {
  if (!flags.passkeys) {
    if (flags.rpId !== undefined) throw new ArgumentError('--rp-id requires --passkeys');
    if (flags.sessionLifetime !== undefined) throw new ArgumentError('--session-lifetime requires --passkeys');
    if (flags.inviteLifetime !== undefined) throw new ArgumentError('--invite-lifetime requires --passkeys');
    return { passkeys: false, rpId: null, sessionStore: null, sessionLifetimeMs: null, inviteStore: null, inviteLifetimeMs: null };
  }
  if (!auth) throw new ArgumentError('serve --passkeys requires authentication; --passkeys --no-auth is not supported');
  if (!identityStore) throw new ArgumentError('serve --passkeys needs an identity store: pass --identity-store <path> or set HOME or XDG_STATE_HOME');
  if (flags.identityStore === undefined && flags.fileIdentityStore) {
    throw new ArgumentError('serve --passkeys does not accept identity_store from .cockpit/serve.toml, because anyone who can write the repo could point sign-in at their own store; pass --identity-store instead');
  }
  const rpId = flags.rpId ?? DEFAULT_RP_ID;
  const checkOrigins = origins.length ? origins : [port ? `http://localhost:${port}` : 'http://localhost'];
  try {
    normalizeRelyingParty({ rpId, origins: checkOrigins });
  } catch {
    throw new ArgumentError(`--rp-id must be a lowercase domain name with at least two labels, or localhost (not an IP address), and every passkey origin must be https://<rp-id or a subdomain>[:port], or http://localhost[:port] with --rp-id localhost${origins.length ? '' : '; pass --origin for a non-localhost --rp-id'}`);
  }
  // Sessions and invites live next to the identity store, so they share its
  // directory checks; the identity store path is already known to be outside
  // the root.
  const sessionStore = path.join(path.dirname(identityStore), SESSIONS_FILE);
  const inviteStore = path.join(path.dirname(identityStore), INVITES_FILE);
  for (const [file, name, what] of [[sessionStore, SESSIONS_FILE, 'sessions'], [inviteStore, INVITES_FILE, 'invites']]) {
    if (file === identityStore) throw new ArgumentError(`--identity-store must not be named ${name}; that name is used for the ${what} file next to it`);
  }
  const sessionLifetimeMs = flags.sessionLifetime === undefined ? DEFAULT_SESSION_LIFETIME_MS : parseSessionLifetime(flags.sessionLifetime);
  const inviteLifetimeMs = flags.inviteLifetime === undefined ? DEFAULT_INVITE_LIFETIME_MS : parseInviteLifetime(flags.inviteLifetime);
  return { passkeys: true, rpId, sessionStore, sessionLifetimeMs, inviteStore, inviteLifetimeMs };
}

export function parseOrigin(value, source = '--origin') {
  return normalizeOrigin(value, source);
}

function parseArgs(argv) {
  const flags = { rootArgs: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') {
      flags.rootArgs.push(...argv.slice(index));
      break;
    }
    if (arg === '--help' || arg === '-h') flags.help = true;
    else if (arg === '--host') {
      flags.host = parseHost(takeValue(argv, index, arg), '--host');
      index += 1;
    } else if (arg.startsWith('--host=')) flags.host = parseHost(arg.slice('--host='.length), '--host');
    else if (arg === '--port') {
      flags.port = parsePort(takeValue(argv, index, arg), '--port');
      index += 1;
    } else if (arg.startsWith('--port=')) flags.port = parsePort(arg.slice('--port='.length), '--port');
    else if (arg === '--write') flags.write = true;
    else if (arg === '--passkeys') flags.passkeys = true;
    else if (arg === '--rp-id') {
      flags.rpId = takeValue(argv, index, arg);
      index += 1;
    } else if (arg.startsWith('--rp-id=')) flags.rpId = arg.slice('--rp-id='.length);
    else if (arg === '--session-lifetime') {
      flags.sessionLifetime = takeValue(argv, index, arg);
      index += 1;
    } else if (arg.startsWith('--session-lifetime=')) flags.sessionLifetime = arg.slice('--session-lifetime='.length);
    else if (arg === '--invite-lifetime') {
      flags.inviteLifetime = takeValue(argv, index, arg);
      index += 1;
    } else if (arg.startsWith('--invite-lifetime=')) flags.inviteLifetime = arg.slice('--invite-lifetime='.length);
    else if (arg === '--origin') {
      flags.origins = [...(flags.origins ?? []), parseOrigin(takeValue(argv, index, arg), '--origin')];
      index += 1;
    } else if (arg.startsWith('--origin=')) flags.origins = [...(flags.origins ?? []), parseOrigin(arg.slice('--origin='.length), '--origin')];
    else if (arg === '--webhook-headers-file') {
      flags.webhookHeadersFile = takeValue(argv, index, arg);
      index += 1;
    } else if (arg.startsWith('--webhook-headers-file=')) flags.webhookHeadersFile = arg.slice('--webhook-headers-file='.length);
    else if (arg === '--webhook-url') {
      flags.webhookUrl = takeValue(argv, index, arg);
      index += 1;
    } else if (arg.startsWith('--webhook-url=')) flags.webhookUrl = arg.slice('--webhook-url='.length);
    else if (arg === '--identity-store') {
      const pathValue = takePathValue(argv, index, arg);
      flags.identityStore = pathValue.value;
      index = pathValue.index;
    } else if (arg.startsWith('--identity-store=')) flags.identityStore = arg.slice('--identity-store='.length);
    else if (arg === '--no-auth') flags.auth = false;
    else if (arg === '--auth') flags.auth = true;
    else if (arg === '--root' || arg === '--cockpit-root') {
      const pathValue = takePathValue(argv, index, arg);
      flags.rootArgs.push(arg, pathValue.value);
      index = pathValue.index;
    } else if (arg.startsWith('--root=') || arg.startsWith('--cockpit-root=')) flags.rootArgs.push(arg);
    else throw new ArgumentError(`Unknown option: ${arg}`);
  }
  return flags;
}

function readServeFile(root) {
  const file = path.join(root, '.cockpit', 'serve.toml');
  if (!fs.existsSync(file)) return { file, values: {} };
  const values = parseToml(fs.readFileSync(file, 'utf8'));
  return { file, values };
}

function serveFileOptions(values) {
  const options = {};
  if (Object.hasOwn(values, 'host')) {
    options.host = parseHost(values.host, '.cockpit/serve.toml host');
  }
  if (Object.hasOwn(values, 'port')) options.port = parsePort(values.port, '.cockpit/serve.toml port');
  if (Object.hasOwn(values, 'auth')) {
    if (typeof values.auth !== 'boolean') throw new ArgumentError('.cockpit/serve.toml auth must be true or false');
    options.auth = values.auth;
  }
  if (Object.hasOwn(values, 'identity_store')) {
    if (typeof values.identity_store !== 'string' || values.identity_store === '') throw new ArgumentError('.cockpit/serve.toml identity_store must be a non-empty path string');
    options.identityStore = values.identity_store;
  }
  return options;
}

function defaultIdentityStore(root, env) {
  const hasStateBase = (env.XDG_STATE_HOME && env.XDG_STATE_HOME.trim() !== '') || env.HOME;
  return hasStateBase ? path.join(stateDirFor(root, env), IDENTITY_STORE_FILE) : null;
}

function checkOutsideRoot(file, root, source) {
  try {
    return path.resolve(assertOutsideRoot(file, root, source));
  } catch (error) {
    if (error instanceof IdentityStoreError) throw new ArgumentError(error.message);
    throw error;
  }
}

// The identity store holds credentials, so it must never be servable: the
// path must be absolute (or start with ~/) and resolve outside the root. The
// default state-dir path is checked too, since XDG_STATE_HOME or HOME can
// point inside the root.
export function resolveIdentityStorePath(value, { root, env, source }) {
  if (value === undefined) {
    const fallback = defaultIdentityStore(root, env);
    return fallback && checkOutsideRoot(fallback, root, 'default identity store (XDG_STATE_HOME or HOME state dir)');
  }
  const expanded = expandHome(value, env);
  if (!path.isAbsolute(expanded)) throw new ArgumentError(`${source} must be an absolute path or start with ~/`);
  return checkOutsideRoot(expanded, root, source);
}

/**
 * Resolve serve options from argv, the user config, and .cockpit/serve.toml.
 *
 * `identityStore` in the result is the absolute identity store path, always
 * outside the served root (startup fails otherwise, including for the default
 * path). It is null when no path is configured and neither HOME nor
 * XDG_STATE_HOME is set. Callers must treat null as "identity disabled" and
 * fail closed: no passkey sign-in, never a fallback location.
 */
export function parseServeConfig({ argv = [], env, stderr } = {}) {
  if (!env) throw new Error('parseServeConfig requires an explicit env object');
  const flags = parseArgs(argv);
  if (flags.help) return { help: true };

  const resolved = resolveRoot({ argv: flags.rootArgs, env, stderr });
  const validated = validateCockpitRoot(resolved.root);
  const root = fs.realpathSync.native(validated.root);
  const serveFile = readServeFile(root);
  const fileOptions = serveFileOptions(serveFile.values);

  const auth = flags.auth ?? fileOptions.auth ?? true;
  const write = flags.write === true;
  const identityStoreSource = flags.identityStore !== undefined ? '--identity-store' : '.cockpit/serve.toml identity_store';
  const identityStore = resolveIdentityStorePath(flags.identityStore ?? fileOptions.identityStore, { root, env, source: identityStoreSource });
  if (write && !auth) throw new ArgumentError('serve --write requires authentication; --write --no-auth is not supported');
  const origins = normalizeOrigins(flags.origins ?? []);
  const port = flags.port ?? fileOptions.port ?? DEFAULT_SERVE_PORT;
  const passkeys = resolvePasskeys({ ...flags, fileIdentityStore: fileOptions.identityStore !== undefined }, { auth, identityStore, origins, port });
  return {
    root,
    write,
    ...passkeys,
    origins,
    webhookUrl: flags.webhookUrl ?? env.COCKPIT_INTENTS_WEBHOOK_URL ?? null,
    webhookHeadersFile: flags.webhookHeadersFile ?? (env.COCKPIT_INTENTS_WEBHOOK_HEADERS_FILE || null),
    host: flags.host ?? fileOptions.host ?? DEFAULT_SERVE_HOST,
    port,
    auth,
    identityStore,
    configPath: resolved.configPath,
    source: resolved.source,
    serveConfigPath: serveFile.file,
  };
}
