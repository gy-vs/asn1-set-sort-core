import { describe, expect, it } from 'vitest';
import {
  asn1,
  BitString,
  Choice,
  decode,
  DERError,
  encode,
  sequence,
} from '../src/index.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));

describe('OPTIONAL and DEFAULT', () => {
  const schema = sequence([
    ['a', asn1.integer],
    ['b', asn1.boolean.optional()],
    ['c', asn1.integer.default(0n)],
    ['d', asn1.utf8String.default('x')],
  ]);

  it('omits OPTIONAL absent and DEFAULT-equal fields', () => {
    expect(hex(encode(schema, { a: 1n, c: 0n, d: 'x' }))).toBe('3003020101');
    expect(hex(encode(schema, { a: 1n, b: true }))).toBe('30060201010101ff');
    expect(hex(encode(schema, { a: 1n, c: 7n, d: 'y' }))).toBe(
      '3009020101' + '020107' + '0c0179',
    );
  });

  it('round trips with defaults filled back in', () => {
    const enc = encode(schema, { a: 1n });
    expect(decode(schema, enc)).toEqual({ a: 1n, c: 0n, d: 'x' });
  });

  it('rejects an explicitly encoded DEFAULT field in strict mode', () => {
    // c = 0 encoded explicitly (020100)
    const bad = bytes('3006' + '020101' + '020100');
    expect(() => decode(schema, bad)).toThrowError(/DEFAULT/);
  });

  it('accepts explicit DEFAULT in non-strict mode', () => {
    const bad = bytes('3006' + '020101' + '020100');
    const v = decode(schema, bad, { strict: false }) as Record<string, unknown>;
    expect(v.a).toBe(1n);
    expect(v.c).toBe(0n);
  });

  it('fails on missing required field', () => {
    expect(() => decode(schema, bytes('30030101ff'))).toThrow(/missing required field "a"|unexpected/);
    expect(() => encode(schema, { b: true })).toThrow(/missing required field "a"/);
  });
});

describe('CHOICE', () => {
  const schema = sequence([
    ['which', asn1.choice([
      ['i', asn1.integer],
      ['s', asn1.utf8String],
      ['nested', asn1.sequence([['x', asn1.boolean]])],
    ])],
  ]);

  it('encodes/decodes each alternative', () => {
    for (const val of [{ i: 5n }, { s: 'hi' }, { nested: { x: true } }]) {
      const enc = encode(schema, { which: val });
      const back = decode(schema, enc) as Record<string, Choice>;
      expect(back.which).toBeInstanceOf(Choice);
      const round = { [back.which.name]: back.which.value };
      expect(round).toEqual(val);
    }
  });

  it('accepts Choice instance input as well', () => {
    const enc = encode(schema, { which: new Choice('i', 9n) });
    expect(decode(schema, enc)).toEqual({ which: new Choice('i', 9n) });
  });
});

describe('explicit and implicit tags', () => {
  it('explicit [0] wraps a complete TLV in a constructed context tag', () => {
    const schema = asn1.integer.explicit(0);
    expect(hex(encode(schema, 5n))).toBe('a003' + '020105');
    expect(decode(schema, bytes('a003020105'))).toBe(5n);
  });

  it('implicit [0] on INTEGER rewrites the identifier, keeping content', () => {
    const schema = asn1.integer.implicit(0);
    expect(hex(encode(schema, 5n))).toBe('800105');
    expect(decode(schema, bytes('800105'))).toBe(5n);
  });

  it('implicit [3] on a SEQUENCE stays constructed (a3)', () => {
    const inner = sequence([['x', asn1.boolean]]);
    const schema = inner.implicit(3);
    const enc = encode(schema, { x: true });
    expect(hex(enc)).toBe('a303' + '0101ff');
    expect(decode(schema, enc)).toEqual({ x: true });
  });

  it('implicit [1] on OCTET STRING stays primitive (81)', () => {
    const schema = asn1.octetString.implicit(1);
    const enc = encode(schema, bytes('aabb'));
    expect(hex(enc)).toBe('8102aabb');
    expect(hex(decode(schema, enc) as Uint8Array)).toBe('aabb');
  });

  it('tags inside SEQUENCE fields round trip with paths', () => {
    const schema = sequence([
      ['version', asn1.integer.implicit(0).default(0n)],
      ['value', asn1.octetString.explicit(1)],
    ]);
    const v = { version: 2n, value: bytes('01') };
    const enc = encode(schema, v);
    // 80 01 02, a1 03 04 01 01
    expect(hex(enc)).toBe('3008' + '800102' + 'a103040101');
    expect(decode(schema, enc)).toEqual(v);
  });
});
