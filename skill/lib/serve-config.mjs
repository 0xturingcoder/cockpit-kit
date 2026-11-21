import fs from 'node:fs';
import path from 'node:path';
import { ArgumentError, resolveRoot, validateCockpitRoot } from './config.mjs';
import { parseToml } from './toml.mjs';
import { normalizeOrigin, normalizeOrigins } from './intents/origins.mjs';
import { stateDirFor } from './intents/store.mjs';
import { IDENTITY_STORE_FILE, IdentityStoreError, assertOutsideRoot } from './identity/store.mjs';
import { expandHome } from './paths.mjs';

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
  return {
    root,
    write,
    origins: normalizeOrigins(flags.origins ?? []),
    webhookUrl: flags.webhookUrl ?? env.COCKPIT_INTENTS_WEBHOOK_URL ?? null,
    webhookHeadersFile: flags.webhookHeadersFile ?? (env.COCKPIT_INTENTS_WEBHOOK_HEADERS_FILE || null),
    host: flags.host ?? fileOptions.host ?? DEFAULT_SERVE_HOST,
    port: flags.port ?? fileOptions.port ?? DEFAULT_SERVE_PORT,
    auth,
    identityStore,
    configPath: resolved.configPath,
    source: resolved.source,
    serveConfigPath: serveFile.file,
  };
}
