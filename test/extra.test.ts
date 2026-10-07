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

describe('empty values', () => {
  it('empty collections and strings round trip', () => {
    expect(hex(encode(asn1.setOf(asn1.integer), []))).toBe('3100');
    expect(hex(encode(asn1.sequenceOf(asn1.integer), []))).toBe('3000');
    expect(hex(encode(asn1.octetString, new Uint8Array(0)))).toBe('0400');
    expect(decode(asn1.octetString, bytes('0400'))).toEqual(new Uint8Array(0));
    const bs = encode(asn1.bitString, new BitString(new Uint8Array(0)));
    expect(hex(bs)).toBe('030100');
    expect(decode(asn1.bitString, bs)).toEqual(new BitString(new Uint8Array(0)));
  });
});

describe('large values', () => {
  it('handles integers larger than Number.MAX_SAFE_INTEGER', () => {
    const v = (1n << 100n) + 7n;
    expect(decode(asn1.integer, encode(asn1.integer, v))).toBe(v);
    const neg = -(1n << 200n) - 1n;
    expect(decode(asn1.integer, encode(asn1.integer, neg))).toBe(neg);
  });

  it('uses long-form length for content >= 128 bytes', () => {
    const data = new Uint8Array(200).fill(0x30);
    const enc = encode(asn1.octetString, data);
    // 04 81 c8 ...
    expect(enc[0]).toBe(0x04);
    expect(enc[1]).toBe(0x81);
    expect(enc[2]).toBe(200);
    expect(hex(decode(asn1.octetString, enc) as Uint8Array)).toBe(hex(data));
  });
});

describe('high tag numbers', () => {
  it('implicit tag >= 31 uses high-tag-number form and round trips', () => {
    const schema = asn1.integer.implicit(1000);
    const enc = encode(schema, 5n);
    expect(hex(enc)).toBe('9f87680105');
    expect(decode(schema, enc)).toBe(5n);
  });

  it('constructed high tag number on a SEQUENCE', () => {
    const schema = asn1.sequence([['x', asn1.boolean]]).implicit(31);
    const enc = encode(schema, { x: true });
    expect(hex(enc)).toBe('bf1f030101ff');
    expect(decode(schema, enc)).toEqual({ x: true });
  });
});

describe('tag modifier chains', () => {
  it('implicit then explicit', () => {
    const schema = asn1.integer.implicit(2).explicit(4);
    const enc = encode(schema, 7n);
    expect(hex(enc)).toBe('a403820107');
    expect(decode(schema, enc)).toBe(7n);
  });

  it('explicit then implicit replaces the wrapper', () => {
    const schema = asn1.integer.explicit(3).implicit(6);
    const enc = encode(schema, 7n);
    expect(hex(enc)).toBe('a603020107');
    expect(decode(schema, enc)).toBe(7n);
  });

  it('optional implicit field present/absent', () => {
    const schema = sequence([['v', asn1.octetString.implicit(9).optional()]]);
    expect(decode(schema, encode(schema, { v: bytes('01') }))).toEqual({
      v: bytes('01'),
    });
    expect(decode(schema, encode(schema, {}))).toEqual({});
  });
});

describe('IMPLICIT applied to a CHOICE', () => {
  const schema = sequence([
    ['w', asn1.choice([
      ['i', asn1.integer],
      ['coll', asn1.sequenceOf(asn1.integer)],
    ]).implicit(5)],
  ]);

  it('propagates the context tag, distinguishing via constructed bit', () => {
    for (const [val, wire] of [
      [{ i: 5n }, '3003850105'],
      [{ coll: [1n, 2n] }, '3008a506020101020102'],
    ] as const) {
      const enc = encode(schema, { w: val });
      expect(hex(enc)).toBe(wire);
      const back = decode(schema, enc) as { w: Choice };
      expect(back.w).toBeInstanceOf(Choice);
      expect(hex(encode(schema, { w: { [back.w.name]: back.w.value } }))).toBe(wire);
    }
  });

  it('reports ambiguity when two primitive alternatives share the propagated tag', () => {
    const badSchema = sequence([
      ['w', asn1.choice([
        ['i', asn1.integer],
        ['raw', asn1.octetString],
      ]).implicit(5)],
    ]);
    const enc = bytes('3003850105');
    expect(() => decode(badSchema, enc)).toThrowError(/ambiguous/);
  });
});

describe('error shape', () => {
  it('DERError carries offset and path', () => {
    let err: unknown;
    try {
      decode(asn1.integer, bytes('02020005'));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(DERError);
    expect((err as DERError).offset).toBe(2);
    expect((err as DERError).path).toBe('$');
  });
});
