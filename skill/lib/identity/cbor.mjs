// Minimal, strict CBOR (RFC 8949) decoder for WebAuthn: just enough for an
// attestationObject, a COSE_Key, and authenticator extension outputs.
//
// Accepted: unsigned and negative integers (as safe JS numbers), byte strings
// (Buffer), UTF-8 text strings, definite-length arrays, and definite-length
// maps (JS Map) whose keys are integers or text strings.
//
// Rejected, always with CborError and a fixed message that never quotes the
// input: tags, floats, simple values (false/true/null/undefined included),
// indefinite lengths, reserved additional-information values, non-minimal
// ("non-shortest") length or integer encodings, integers outside the safe JS
// range, invalid UTF-8, duplicate map keys, map keys of other types, lengths
// that run past the end of the input, nesting deeper than `maxDepth`, inputs
// larger than `maxBytes`, and trailing bytes after the top-level item
// (decodeCbor only; decodeCborPrefix reports where the item ended).
//
// Map key order is not checked: browsers re-encode attestation objects, so
// canonical ordering is not guaranteed in the wild.

export const CBOR_MAX_BYTES = 16 * 1024;
export const CBOR_MAX_DEPTH = 8;

export class CborError extends Error {
  constructor(reason) {
    super(`Invalid CBOR (${reason})`);
    this.name = 'CborError';
    this.code = 'cbor_invalid';
    this.reason = reason;
  }
}

const fail = (reason) => { throw new CborError(reason); };

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

// Read the argument that follows an initial byte. Returns { value, offset }.
// `value` is a Number; 8-byte arguments above Number.MAX_SAFE_INTEGER fail.
const readArgument = (bytes, offset, info) => {
  if (info < 24) return { value: info, offset };
  if (info > 27) fail(info === 31 ? 'indefinite_length' : 'reserved_info');
  const size = 1 << (info - 24); // 1, 2, 4, or 8 bytes
  if (offset + size > bytes.length) fail('truncated');
  let value;
  if (size === 1) value = bytes[offset];
  else if (size === 2) value = bytes.readUInt16BE(offset);
  else if (size === 4) value = bytes.readUInt32BE(offset);
  else {
    const big = bytes.readBigUInt64BE(offset);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) fail('integer_too_large');
    value = Number(big);
  }
  // Shortest form only: each width must be needed for the value it holds.
  const minimum = [24, 0x100, 0x10000, 0x100000000][info - 24];
  if (value < minimum) fail('non_minimal');
  return { value, offset: offset + size };
};

const decodeItem = (bytes, start, depth, maxDepth) => {
  if (depth > maxDepth) fail('too_deep');
  if (start >= bytes.length) fail('truncated');
  const initial = bytes[start];
  const major = initial >> 5;
  if (major === 6) fail('tag');
  if (major === 7) fail('simple_or_float');
  const { value: arg, offset } = readArgument(bytes, start + 1, initial & 0x1f);

  switch (major) {
    case 0:
      return { value: arg, offset };
    case 1:
      // -1 - arg must stay a safe integer.
      if (arg >= Number.MAX_SAFE_INTEGER) fail('integer_too_large');
      return { value: -1 - arg, offset };
    case 2:
    case 3: {
      if (arg > bytes.length - offset) fail('truncated');
      const end = offset + arg;
      const slice = bytes.subarray(offset, end);
      if (major === 2) return { value: Buffer.from(slice), offset: end };
      let text;
      try {
        text = utf8.decode(slice);
      } catch {
        fail('invalid_utf8');
      }
      return { value: text, offset: end };
    }
    case 4: {
      // Every item takes at least one byte, so a count larger than what is
      // left is truncated input; this also bounds the allocation.
      if (arg > bytes.length - offset) fail('truncated');
      const items = [];
      let at = offset;
      for (let index = 0; index < arg; index += 1) {
        const item = decodeItem(bytes, at, depth + 1, maxDepth);
        items.push(item.value);
        at = item.offset;
      }
      return { value: items, offset: at };
    }
    case 5: {
      if (arg > (bytes.length - offset) / 2) fail('truncated');
      const map = new Map();
      let at = offset;
      for (let index = 0; index < arg; index += 1) {
        const key = decodeItem(bytes, at, depth + 1, maxDepth);
        if (typeof key.value !== 'number' && typeof key.value !== 'string') fail('unsupported_map_key');
        if (map.has(key.value)) fail('duplicate_map_key');
        const entry = decodeItem(bytes, key.offset, depth + 1, maxDepth);
        map.set(key.value, entry.value);
        at = entry.offset;
      }
      return { value: map, offset: at };
    }
    default:
      return fail('malformed');
  }
};

const asBuffer = (input) => {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  return fail('not_bytes');
};

const checkBounds = (bytes, { maxBytes, maxDepth }) => {
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || !Number.isInteger(maxDepth) || maxDepth < 0) fail('bad_limits');
  if (bytes.length === 0) fail('empty');
  if (bytes.length > maxBytes) fail('too_large');
};

/**
 * Decode one CBOR item from the start of `input` and report where it ended.
 * Used where CBOR is followed by more data (COSE key inside authenticatorData).
 *
 * @param {Uint8Array} input
 * @param {{ maxBytes?: number, maxDepth?: number }} [limits]
 * @returns {{ value: unknown, length: number }}
 */
export const decodeCborPrefix = (input, { maxBytes = CBOR_MAX_BYTES, maxDepth = CBOR_MAX_DEPTH } = {}) => {
  const bytes = asBuffer(input);
  checkBounds(bytes, { maxBytes, maxDepth });
  try {
    const { value, offset } = decodeItem(bytes, 0, 0, maxDepth);
    return { value, length: offset };
  } catch (error) {
    if (error instanceof CborError) throw error;
    // Defensive: no raw engine error (RangeError etc.) escapes.
    throw new CborError('malformed');
  }
};

/**
 * Decode exactly one CBOR item that spans all of `input`.
 *
 * @param {Uint8Array} input
 * @param {{ maxBytes?: number, maxDepth?: number }} [limits]
 * @returns {unknown}
 */
export const decodeCbor = (input, limits = {}) => {
  const { value, length } = decodeCborPrefix(input, limits);
  if (length !== asBuffer(input).length) fail('trailing_bytes');
  return value;
};
