import {describe, expect, it} from 'vitest';
import {
  Asn1Error,
  bitString,
  boolean,
  Choice,
  choice,
  decode,
  encode,
  explicit,
  implicit,
  integer,
  nullType,
  octetString,
  oid,
  optional,
  sequence,
  sequenceOf,
  set,
  setOf,
  utf8String,
  withDefault,
} from '../src/index.js';

const hex = (bytes: Uint8Array) =>
  Buffer.from(bytes).toString('hex');
const fromHex = (s: string) =>
  new Uint8Array(Buffer.from(s.replace(/\s+/g, ''), 'hex'));

function expectRejected(bytes: Uint8Array, schema: Parameters<typeof decode>[0]) {
  expect(() => decode(schema, bytes)).toThrowError(Asn1Error);
}

/* ------------------------ tagging and SET fields ------------------------ */

describe('implicit / explicit tagging', () => {
  it('round-trips implicit and explicit context tags', () => {
    const s = sequence([
      ['a', implicit(integer(), 0)],
      ['b', explicit(utf8String(), 1)],
      ['c', optional(implicit(boolean(), 2))],
    ]);
    const v = {a: 7n, b: 'x', c: true};
    const bytes = encode(s, v);
    // [0] primitive 07 ; [1] constructed wrapping 0c0178 ; [2] primitive ff
    expect(hex(bytes)).toBe('300b 800107 a1030c0178 8201ff'.replace(/ /g, ''));
    expect(hex(encode(s, decode(s, bytes)))).toBe(hex(bytes));
  });

  it('decodes absent optional and rejects an unknown context tag', () => {
    const s = sequence([['a', optional(implicit(integer(), 0))]]);
    const decoded = decode(s, fromHex('3000')) as Record<string, unknown>;
    expect(decoded.a).toBeUndefined();
    expectRejected(fromHex('3003 81 01 01'), s);
  });

  it('round-trips high-tag-number form (tag 1000)', () => {
    const s = sequence([['a', implicit(integer(), 1000)]]);
    const bytes = encode(s, {a: 1n});
    // context primitive, high number 1000 = 0b1111101000 -> 87 68
    expect(hex(bytes)).toBe('3005 9f8768 0101'.replace(/ /g, ''));
    expect(hex(encode(s, decode(s, bytes)))).toBe(hex(bytes));
    expectRejected(fromHex('3005 9f 80 68 0101'), s); // non-minimal 0x80 0x68
  });
});

describe('SET with named fields', () => {
  const s = set([
    ['a', implicit(integer(), 0)],
    ['b', implicit(utf8String(), 1)],
  ]);

  it('emits fields in canonical tag order regardless of object order', () => {
    const b1 = encode(s, {a: 1n, b: 'z'});
    const b2 = encode(s, {b: 'z', a: 1n});
    expect(hex(b2)).toBe(hex(b1));
    expect(hex(b1)).toBe('3106 800101 81017a'.replace(/ /g, ''));
    const decoded = decode(s, b1) as Record<string, unknown>;
    expect(decoded.a).toBe(1n);
    expect(decoded.b).toBe('z');
  });

  it('rejects SET fields presented out of canonical order', () => {
    expectRejected(fromHex('3108 81017a 800101'), s);
  });

  it('refuses to build a SET whose fields share a tag', () => {
    expect(() => set([['a', implicit(integer(), 0)], ['b', implicit(boolean(), 0)]])).toThrowError(Asn1Error);
  });
});

describe('DEFAULT on composite values', () => {
  const s = sequence([
    ['flags', withDefault(setOf(integer()), [1n, 2n, 3n])],
    ['name', utf8String()],
  ]);

  it('omits equal defaults and inserts them on decode', () => {
    const omitted = encode(s, {name: 'n'});
    // Hand-built: same SEQUENCE but with the DEFAULTed SET OF present.
    const present = fromHex('300e 3109 020101 020102 020103 0c016e');
    const decoded = decode(s, omitted) as Record<string, unknown>;
    expect(decoded.flags).toEqual([1n, 2n, 3n]);
    expectRejected(present, s); // explicit DEFAULT is non-DER
    // lenient mode accepts it
    expect(() => decode(s, present, {strict: false})).not.toThrow();
  });
});

describe('depth limits', () => {
  it('rejects encoding beyond maxDepth with a clear error', () => {
    const s = sequenceOf(sequenceOf(integer()));
    // outer SEQUENCE OF (depth 1) -> inner SEQUENCE OF (depth 2) -> INTEGER (3)
    expect(() => encode(s, [[1n]], {maxDepth: 1})).toThrowError(/nesting depth/);
    expect(() => encode(s, [[1n]], {maxDepth: 3})).not.toThrow();
  });
});

/* ----------------------------- known vectors ---------------------------- */
describe('known DER vectors', () => {
  it('encodes INTEGER boundaries in minimal two’s complement', () => {
    const cases: Array<[bigint, string]> = [
      [0n, '020100'],
      [1n, '020101'],
      [127n, '02017f'],
      [128n, '02020080'],
      [256n, '02020100'],
      [-1n, '0201ff'],
      [-128n, '020180'],
      [-129n, '0202ff7f'],
      [65535n, '020300ffff'],
      [-32768n, '02028000'],
      [-32769n, '0203ff7fff'],
    ];
    for (const [value, expected] of cases) {
      expect(hex(encode(integer(), value))).toBe(expected);
    }
  });

  it('encodes a large INTEGER beyond safe integer range', () => {
    const v = 2n ** 256n + 123n;
    const bytes = encode(integer(), v);
    expect(decode(integer(), bytes)).toBe(v);
    const content = Buffer.concat([
      Buffer.from([0x01]),
      Buffer.alloc(31, 0),
      Buffer.from([0x7b]),
    ]);
    expect(hex(bytes)).toBe('0221' + content.toString('hex'));
  });

  it('encodes BOOLEAN, NULL, OID and long-form length', () => {
    expect(hex(encode(boolean(), true))).toBe('0101ff');
    expect(hex(encode(boolean(), false))).toBe('010100');
    expect(hex(encode(nullType(), null))).toBe('0500');
    // OID 1.2.840.113549
    expect(hex(encode(oid(), '1.2.840.113549'))).toBe('06062a864886f70d');
    // 128 content octets -> long form length 81 80
    expect(hex(encode(octetString(), new Uint8Array(128)))).toBe(
      '048180' + '00'.repeat(128),
    );
  });

  it('encodes BIT STRING with canonicalized unused bits', () => {
    const bytes = encode(bitString(), {
      unused: 4,
      data: Uint8Array.from([0b10101010, 0b11110101]),
    });
    // trailing four bits forced to zero
    expect(hex(bytes)).toBe('030304aaf0');
  });

  it('encodes UTF8String', () => {
    const text = 'héllo 世界';
    const content = Buffer.from(text, 'utf8');
    expect(hex(encode(utf8String(), text))).toBe(
      '0c' + content.length.toString(16).padStart(2, '0') + content.toString('hex'),
    );
  });
});

/* ------------------------------ round trips ----------------------------- */

const complexSchema = sequence([
  ['version', integer()],
  ['name', utf8String()],
  ['active', boolean()],
  ['nothing', nullType()],
  ['algo', oid()],
  ['blob', octetString()],
  ['bits', bitString()],
  ['modes', withDefault(implicit(integer(), 0), 5n)],
  ['remark', optional(implicit(utf8String(), 5))],
  [
    'thing',
    choice({number: integer(), text: utf8String(), flag: boolean()}),
  ],
  ['tags', setOf(oid())],
  ['ints', sequenceOf(integer())],
  ['bag', set([
    ['a', implicit(integer(), 0)],
    ['b', explicit(utf8String(), 1)],
    ['c', optional(implicit(octetString(), 2))],
  ])],
]);

const sampleValue = {
  version: 3n,
  name: 'root',
  active: true,
  nothing: null,
  algo: '1.2.840.113549.1.1.11',
  blob: Uint8Array.from([1, 2, 3, 250]),
  bits: {unused: 3, data: Uint8Array.from([0xff, 0b10100000])},
  // modes omitted -> default 5
  thing: {[Choice]: 'text', value: 'chosen'},
  tags: ['2.5.4.3', '1.2.3', '0.9.2342.19200300.100.1.25', '1.2.840'],
  ints: [1n, -2n, 300n, 0n, -300n],
  bag: {
    a: 42n,
    b: 'inside',
  },
};

describe('round trip consistency', () => {
  it('decodes an encoded complex value and re-encodes to identical bytes', () => {
    const bytes = encode(complexSchema, sampleValue);
    const decoded = decode(complexSchema, bytes) as Record<string, unknown>;
    expect(decoded.version).toBe(3n);
    expect(decoded.name).toBe('root');
    expect(decoded.active).toBe(true);
    expect(decoded.nothing).toBe(null);
    expect(decoded.algo).toBe('1.2.840.113549.1.1.11');
    expect(hex(decoded.blob as Uint8Array)).toBe('010203fa');
    expect(decoded.modes).toBe(5n); // default filled in
    expect(decoded.remark).toBeUndefined();
    expect(decoded.thing).toEqual({[Choice]: 'text', value: 'chosen'});
    expect(hex(encode(complexSchema, decoded))).toBe(hex(bytes));
  });

  it('preserves OPTIONAL present / absent across the round trip', () => {
    const withRemark = {...sampleValue, remark: 'note'};
    const bytes = encode(complexSchema, withRemark);
    const decoded = decode(complexSchema, bytes) as Record<string, unknown>;
    expect(decoded.remark).toBe('note');
    expect(hex(encode(complexSchema, decoded))).toBe(hex(bytes));
  });

  it('omits values equal to DEFAULT', () => {
    const bytesDefault = encode(complexSchema, sampleValue);
    const bytesExplicit = encode(complexSchema, {...sampleValue, modes: 5n});
    expect(hex(bytesExplicit)).toBe(hex(bytesDefault));
  });
});

/* --------------------------- SET OF ordering ---------------------------- */

describe('SET OF canonical ordering', () => {
  const schema = setOf(integer());

  it('produces identical bytes regardless of input order', () => {
    const values = Array.from({length: 200}, (_, i) => BigInt((i * 37) % 201) - 100n);
    const a = encode(schema, values);
    const b = encode(schema, [...values].reverse());
    const c = encode(schema, [...values].sort(() => Math.random() - 0.5));
    expect(hex(b)).toBe(hex(a));
    expect(hex(c)).toBe(hex(a));
  });

  it('sorts nested SET OF elements recursively', () => {
    const nested = setOf(setOf(integer()));
    const v1 = [
      [3n, 1n, 2n],
      [9n, 7n, 8n],
      [6n, 4n, 5n],
    ];
    const v2 = [
      [5n, 4n, 6n],
      [2n, 3n, 1n],
      [8n, 7n, 9n],
    ];
    expect(hex(encode(nested, v1))).toBe(hex(encode(nested, v2)));
    // decoder accepts the sorted output
    const bytes = encode(nested, v1);
    expect(hex(encode(nested, decode(nested, bytes)))).toBe(hex(bytes));
  });

  it('rejects an unsorted SET OF in strict mode', () => {
    // SET OF containing INTEGER 1 then INTEGER 0 (wrong order).
    const bad = fromHex('3106 020101 020100');
    expectRejected(bad, schema);
    // lenient mode accepts it, and re-encoding canonicalizes it
    const decoded = decode(schema, bad, {strict: false});
    expect(hex(encode(schema, decoded))).toBe('3106 020100 020101'.replace(/ /g, ''));
  });
});

/* -------------------------- strict rejections --------------------------- */

describe('strict DER rejection', () => {
  it('rejects indefinite length', () => {
    expectRejected(fromHex('02 80 05 00 00'), integer());
  });

  it('rejects non-minimal long-form length', () => {
    expectRejected(fromHex('02 82 00 01 05'), integer());
  });

  it('rejects length claiming more octets than remain', () => {
    const t0 = performance.now();
    expectRejected(fromHex('04 84 ff ff ff ff'), octetString());
    // must fail immediately without allocating against the declared length
    expect(performance.now() - t0).toBeLessThan(50);
  });

  it('rejects INTEGER padding', () => {
    expectRejected(fromHex('02 02 00 05'), integer());
    expectRejected(fromHex('02 02 ff 80'), integer());
    expectRejected(fromHex('02 00'), integer());
  });

  it('lenient mode accepts padded INTEGER and canonicalizes on re-encode', () => {
    const decoded = decode(integer(), fromHex('02 02 00 05'), {strict: false});
    expect(decoded).toBe(5n);
    expect(hex(encode(integer(), decoded))).toBe('020105');
  });

  it('rejects non-canonical BOOLEAN', () => {
    expectRejected(fromHex('01 01 01'), boolean());
  });

  it('rejects NULL with content and constructed primitives', () => {
    expectRejected(fromHex('05 01 00'), nullType());
    expectRejected(fromHex('21 00'), integer()); // constructed INTEGER
  });

  it('rejects malformed OID encodings', () => {
    expectRejected(fromHex('06 00'), oid());
    expectRejected(fromHex('06 02 80 01'), oid()); // leading 0x80
    expectRejected(fromHex('06 02 41'), oid()); // truncated continuation
  });

  it('rejects BIT STRING with nonzero unused bits', () => {
    expectRejected(fromHex('03 03 04 aa f5'), bitString());
    expectRejected(fromHex('03 01 01'), bitString()); // unused=1, no data
  });

  it('rejects invalid UTF-8', () => {
    expectRejected(fromHex('0c 02 ff fe'), utf8String());
  });

  it('rejects trailing octets', () => {
    expectRejected(fromHex('02 01 05 00'), integer());
  });

  it('rejects an explicitly DEFAULT-valued field', () => {
    const schema = sequence([['v', withDefault(integer(), 7n)]]);
    const bad = fromHex('30 03 02 01 07');
    const err = assertAsn1Error(() => decode(schema, bad));
    expect(err.message).toMatch(/DEFAULT/);
  });

  it('rejects out-of-order SEQUENCE fields', () => {
    const schema = sequence([['a', integer()], ['b', utf8String()]]);
    // UTF8String first, then INTEGER
    const bad = fromHex('30 06 0c 01 78 02 01 01');
    expectRejected(bad, schema);
  });

  it('rejects unknown and duplicate tags in a SEQUENCE', () => {
    const schema = sequence([['a', integer()]]);
    expectRejected(fromHex('30 03 0c 01 78'), schema);
    expectRejected(fromHex('30 06 02 01 01 02 01 02'), schema);
  });

  it('rejects truncated input at every layer', () => {
    expectRejected(fromHex('04 03 01 02'), octetString());
    expectRejected(fromHex('30 05 02 01 01 02'), sequence([['a', integer()]]));
    expectRejected(fromHex(''), integer());
  });

  it('rejects explicit tag with missing or trailing inner value', () => {
    const schema = explicit(integer(), 0);
    expectRejected(fromHex('a0 00'), schema);
    expectRejected(fromHex('a0 04 02 01 01 00'), schema);
  });
});

/* ------------------------------ diagnostics ----------------------------- */

describe('error locations', () => {
  const certSchema = sequence([
    ['certs', sequenceOf(sequence([
      ['validity', sequence([
        ['notBefore', integer()],
        ['notAfter', integer()],
      ])],
    ]))],
  ]);

  it('reports byte offset and a certs[3].validity-style path', () => {
    const validitySchema = sequence([
      ['notBefore', integer()],
      ['notAfter', integer()],
    ]);
    const goodValidity = encode(validitySchema, {notBefore: 1n, notAfter: 2n});
    // notAfter is an empty INTEGER: non-DER, error must land deep in the path.
    const badValidity = fromHex('30 05 02 01 01 02 00');
    const certs = [0, 1, 2, 3].map((i) =>
      wrap(0x30, i === 3 ? badValidity : goodValidity),
    );
    const rebuilt = wrap(0x30, wrap(0x30, concatBytes(certs)));

    const err = assertAsn1Error(() => decode(certSchema, rebuilt));
    expect(err.offset).not.toBeNull();
    expect(err.path).toContain('certs');
    expect(err.path).toContain(3);
    expect(err.message).toContain('certs[3]');
    expect(err.message).toContain('validity');
    expect(err.message).toContain('byte offset');
    expect(err.offset).toBeGreaterThan(0);
  });
});

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

function wrap(tag: number, content: Uint8Array): Uint8Array {
  const len = encodeTestLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

function encodeTestLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.from([length]);
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.push(n & 0xff);
    n = Math.floor(n / 256);
  }
  const out = new Uint8Array(bytes.length + 1);
  out[0] = 0x80 | bytes.length;
  for (let i = 0; i < bytes.length; i++) out[1 + i] = bytes[bytes.length - 1 - i];
  return out;
}

/**
 * Wrap `inner` in `depth` SEQUENCEs with O(depth) work: fill the total buffer
 * once from the outside in, writing each length where it belongs.
 */
function nestSequences(depth: number, inner: Uint8Array): Uint8Array {
  // total[i] = total length of the value nested i levels deep (0 = innermost)
  const total: number[] = [inner.length];
  for (let i = 0; i < depth; i++) {
    total.push(1 + encodeTestLength(total[i]).length + total[i]);
  }
  const out = new Uint8Array(total[depth]);
  let pos = 0;
  for (let level = depth; level >= 1; level--) {
    out[pos++] = 0x30;
    const l = encodeTestLength(total[level - 1]);
    out.set(l, pos);
    pos += l.length;
  }
  out.set(inner, pos);
  return out;
}

function assertAsn1Error(fn: () => unknown): Asn1Error {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(Asn1Error);
    return err as Asn1Error;
  }
  throw new Error('expected Asn1Error');
}

/* ------------------------------ performance ----------------------------- */

describe('large SET OF', () => {
  it('encodes and decodes 100k elements within 2s each', () => {
    const n = 100_000;
    const values = new Array<bigint>(n);
    for (let i = 0; i < n; i++) values[i] = BigInt((i * 2654435761) % 1_000_000);

    let t0 = performance.now();
    const bytes = encode(setOf(integer()), values);
    const encodeMs = performance.now() - t0;
    expect(encodeMs).toBeLessThan(2000);

    t0 = performance.now();
    const decoded = decode(setOf(integer()), bytes) as bigint[];
    const decodeMs = performance.now() - t0;
    expect(decodeMs).toBeLessThan(2000);
    expect(decoded.length).toBe(n);
    expect(hex(encode(setOf(integer()), decoded))).toBe(hex(bytes));
  });
});

/* ---------------------------- attack surface ---------------------------- */

describe('hostile input', () => {
  it('fails cleanly on nesting tens of thousands deep', () => {
    const depth = 50_000;
    const bytes = nestSequences(depth, fromHex('02 01 01'));

    // Self-referential schema: SEQUENCE { x ↦ itself | INTEGER }
    const deepSchema = sequence([['x', integer()]]);
    (deepSchema as {fields: Array<{schema: unknown}>}).fields[0].schema =
      deepSchema;

    const err = assertAsn1Error(() => decode(deepSchema, bytes));
    expect(err.message).toMatch(/nesting depth/);
  });

  it('rejects absurd declared length immediately', () => {
    const huge = fromHex('30 88 ff ff ff ff ff ff ff ff');
    const t0 = performance.now();
    const err = assertAsn1Error(() => decode(sequence([]), huge));
    expect(performance.now() - t0).toBeLessThan(50);
    expect(err.offset).not.toBeNull();
  });
});
