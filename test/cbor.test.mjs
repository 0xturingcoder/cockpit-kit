import test from 'node:test';
import assert from 'node:assert/strict';
import { CBOR_MAX_BYTES, CBOR_MAX_DEPTH, CborError, decodeCbor, decodeCborPrefix } from '../skill/lib/identity/cbor.mjs';
import { cbor } from './support/webauthn-synthetic.mjs';

const hex = (text) => Buffer.from(text.replace(/\s+/g, ''), 'hex');

const rejects = (input, reason, limits) => {
  assert.throws(() => decodeCbor(input, limits), (error) => {
    assert.ok(error instanceof CborError, `expected CborError, got ${error?.name}`);
    assert.equal(error.code, 'cbor_invalid');
    assert.equal(error.reason, reason);
    return true;
  });
};

test('cbor decodes the supported types: integers, byte and text strings, arrays, maps', () => {
  assert.equal(decodeCbor(hex('00')), 0);
  assert.equal(decodeCbor(hex('17')), 23);
  assert.equal(decodeCbor(hex('1818')), 24);
  assert.equal(decodeCbor(hex('1903e8')), 1000);
  assert.equal(decodeCbor(hex('1a000f4240')), 1000000);
  assert.equal(decodeCbor(hex('1b001fffffffffffff')), Number.MAX_SAFE_INTEGER);
  assert.equal(decodeCbor(hex('20')), -1);
  assert.equal(decodeCbor(hex('26')), -7);
  assert.equal(decodeCbor(hex('390100')), -257);
  assert.deepEqual(decodeCbor(hex('43010203')), Buffer.from([1, 2, 3]));
  assert.equal(decodeCbor(hex('64 6e6f6e65')), 'none');
  assert.equal(decodeCbor(hex('62 c3bc')), 'ü');
  assert.deepEqual(decodeCbor(hex('83 01 02 03')), [1, 2, 3]);
  const map = decodeCbor(hex('a2 01 02 63 666d74 64 6e6f6e65'));
  assert.ok(map instanceof Map);
  assert.equal(map.get(1), 2);
  assert.equal(map.get('fmt'), 'none');
  assert.deepEqual(decodeCbor(hex('80')), []);
  assert.equal(decodeCbor(hex('a0')).size, 0);
  assert.deepEqual(decodeCbor(hex('40')), Buffer.alloc(0));
  assert.equal(decodeCbor(hex('60')), '');
});

test('cbor round-trips a COSE key and an attestation object built by the test encoder', () => {
  const value = new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', Buffer.alloc(37, 7)]]);
  const decoded = decodeCbor(cbor(value));
  assert.equal(decoded.get('fmt'), 'none');
  assert.equal(decoded.get('attStmt').size, 0);
  assert.deepEqual(decoded.get('authData'), Buffer.alloc(37, 7));
});

test('cbor rejects tags', () => {
  rejects(hex('c0 74 323031332d30332d32315432303a30343a30305a'), 'tag');
  rejects(hex('d8 18 41 00'), 'tag');
  rejects(hex('a1 01 c1 00'), 'tag');
});

test('cbor rejects floats and simple values, including true, false, null, and undefined', () => {
  for (const input of ['f4', 'f5', 'f6', 'f7', 'f0', 'f818', 'f93c00', 'fa47c35000', 'fb3ff199999999999a']) {
    rejects(hex(input), 'simple_or_float');
  }
  rejects(hex('81 f5'), 'simple_or_float');
});

test('cbor rejects indefinite lengths and reserved additional information', () => {
  rejects(hex('5f 41 01 ff'), 'indefinite_length');
  rejects(hex('7f 61 61 ff'), 'indefinite_length');
  rejects(hex('9f 01 ff'), 'indefinite_length');
  rejects(hex('bf 01 02 ff'), 'indefinite_length');
  rejects(hex('ff'), 'simple_or_float');
  for (const input of ['1c', '1d', '1e', '3c', '5c', '7d', '9e', 'bc']) rejects(hex(input), 'reserved_info');
});

test('cbor rejects non-minimal integer and length encodings', () => {
  rejects(hex('1800'), 'non_minimal');
  rejects(hex('1817'), 'non_minimal');
  rejects(hex('190018'), 'non_minimal');
  rejects(hex('1a0000ffff'), 'non_minimal');
  rejects(hex('1b00000000ffffffff'), 'non_minimal');
  rejects(hex('3800'), 'non_minimal');
  rejects(hex('5801 00'), 'non_minimal');
  rejects(hex('7801 61'), 'non_minimal');
  rejects(hex('9800'), 'non_minimal');
  rejects(hex('b800'), 'non_minimal');
});

test('cbor rejects integers outside the safe JavaScript range', () => {
  rejects(hex('1b0020000000000000'), 'integer_too_large');
  rejects(hex('1bffffffffffffffff'), 'integer_too_large');
  rejects(hex('3bffffffffffffffff'), 'integer_too_large');
  rejects(hex('3b001fffffffffffff'), 'integer_too_large');
});

test('cbor rejects truncated input at every position', () => {
  const full = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.alloc(32, 1)], [-3, Buffer.alloc(32, 2)]]));
  for (let length = 1; length < full.length; length += 1) {
    assert.throws(() => decodeCbor(full.subarray(0, length)), CborError, `prefix of ${length} bytes`);
  }
  rejects(hex('19 01'), 'truncated');
  rejects(hex('1a 0000'), 'truncated');
  rejects(hex('1b 00000000'), 'truncated');
  rejects(hex('43 0102'), 'truncated');
  rejects(hex('63 6162'), 'truncated');
  rejects(hex('82 01'), 'truncated');
  rejects(hex('a1 01'), 'truncated');
});

test('cbor rejects lengths larger than the remaining input without allocating them', () => {
  rejects(hex('5a ffffffff 00'), 'truncated');
  rejects(hex('7a 7fffffff 00'), 'truncated');
  rejects(hex('9a ffffffff 00'), 'truncated');
  rejects(hex('ba ffffffff 00'), 'truncated');
  rejects(hex('5b 001fffffffffffff 00'), 'truncated');
});

test('cbor rejects trailing bytes after the top-level item', () => {
  rejects(hex('01 00'), 'trailing_bytes');
  rejects(Buffer.concat([cbor(new Map([['fmt', 'none']])), Buffer.from([0])]), 'trailing_bytes');
});

test('decodeCborPrefix reports where the item ended instead of rejecting trailing data', () => {
  const key = cbor(new Map([[1, 2]]));
  const { value, length } = decodeCborPrefix(Buffer.concat([key, Buffer.from([0xa0, 0xff])]));
  assert.equal(length, key.length);
  assert.equal(value.get(1), 2);
});

test('cbor rejects duplicate map keys', () => {
  rejects(hex('a2 01 02 01 03'), 'duplicate_map_key');
  rejects(hex('a2 61 61 01 61 61 02'), 'duplicate_map_key');
});

test('cbor rejects map keys that are not integers or text strings', () => {
  rejects(hex('a1 41 01 02'), 'unsupported_map_key');
  rejects(hex('a1 80 02'), 'unsupported_map_key');
  rejects(hex('a1 a0 02'), 'unsupported_map_key');
});

test('cbor rejects invalid UTF-8 in text strings', () => {
  rejects(hex('62 c328'), 'invalid_utf8');
  rejects(hex('61 ff'), 'invalid_utf8');
  rejects(hex('63 eda080'), 'invalid_utf8'); // UTF-16 surrogate
});

test('cbor bounds nesting depth', () => {
  const nested = (depth) => Buffer.concat([Buffer.alloc(depth, 0x81), Buffer.from([0x00])]);
  assert.doesNotThrow(() => decodeCbor(nested(CBOR_MAX_DEPTH)));
  rejects(nested(CBOR_MAX_DEPTH + 1), 'too_deep');
  rejects(nested(1000), 'too_deep');
  rejects(hex('81 81 00'), 'too_deep', { maxDepth: 1 });
  assert.deepEqual(decodeCbor(hex('81 00'), { maxDepth: 1 }), [0]);
  // Map nesting counts too.
  rejects(hex('a1 01 a1 01 00'), 'too_deep', { maxDepth: 1 });
});

test('cbor bounds input size', () => {
  const big = cbor(Buffer.alloc(CBOR_MAX_BYTES));
  rejects(big, 'too_large');
  rejects(hex('43 010203'), 'too_large', { maxBytes: 3 });
  assert.deepEqual(decodeCbor(hex('43 010203'), { maxBytes: 4 }), Buffer.from([1, 2, 3]));
  rejects(Buffer.alloc(0), 'empty');
});

test('cbor rejects non-byte input and bad limits with CborError, never a raw error', () => {
  for (const input of [undefined, null, 'a0', 42, {}, [0xa0]]) {
    assert.throws(() => decodeCbor(input), CborError);
  }
  assert.throws(() => decodeCbor(hex('a0'), { maxDepth: -1 }), CborError);
  assert.throws(() => decodeCbor(hex('a0'), { maxBytes: 0 }), CborError);
});

test('cbor error messages never quote the input', () => {
  const secret = Buffer.from('63 736563726574 00'.replace(/\s/g, ''), 'hex');
  try {
    decodeCbor(secret);
    assert.fail('expected a throw');
  } catch (error) {
    assert.doesNotMatch(error.message, /secret|736563/);
  }
});

test('cbor fuzz: random and mutated inputs only ever throw CborError', () => {
  const seed = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', Buffer.alloc(80, 3)], [-7, [1, 'x', Buffer.alloc(2)]]]));
  let state = 12345;
  const rand = () => {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return state;
  };
  for (let i = 0; i < 3000; i += 1) {
    const input = Buffer.from(seed);
    const flips = 1 + (rand() % 4);
    for (let f = 0; f < flips; f += 1) input[rand() % input.length] = rand() & 0xff;
    const cut = rand() % 3 === 0 ? input.subarray(0, 1 + (rand() % input.length)) : input;
    try {
      decodeCbor(cut);
    } catch (error) {
      assert.ok(error instanceof CborError, `unexpected ${error?.name}: ${error?.message}`);
    }
  }
});
