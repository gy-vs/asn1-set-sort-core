import { describe, expect, it } from 'vitest';
import {
  asn1,
  BitString,
  decode,
  encode,
  integer,
  sequence,
  setOf,
} from '../src/index.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));

describe('primitive types — known DER vectors', () => {
  it('BOOLEAN', () => {
    expect(hex(encode(asn1.boolean, true))).toBe('0101ff');
    expect(hex(encode(asn1.boolean, false))).toBe('010100');
    expect(decode(asn1.boolean, bytes('0101ff'))).toBe(true);
    expect(decode(asn1.boolean, bytes('010100'))).toBe(false);
  });

  it('INTEGER positive and negative, minimal form', () => {
    const cases: [bigint, string][] = [
      [0n, '020100'],
      [1n, '020101'],
      [127n, '02017f'],
      [128n, '02020080'],
      [255n, '020200ff'],
      [256n, '02020100'],
      [-1n, '0201ff'],
      [-128n, '020180'],
      [-129n, '0202ff7f'],
      [65535n, '020300ffff'],
      [-32768n, '02028000'],
      [-32769n, '0203ff7fff'],
      [-255n, '0202ff01'],
      [-256n, '0202ff00'],
      [-65536n, '0203ff0000'],
      [-65535n, '0203ff0001'],
    ];
    for (const [v, h] of cases) {
      expect(hex(encode(asn1.integer, v))).toBe(h);
      expect(decode(asn1.integer, bytes(h))).toBe(v);
    }
    expect(typeof decode(asn1.integer, bytes('020105'))).toBe('bigint');
  });

  it('OCTET STRING', () => {
    const b = bytes('03040506');
    expect(hex(encode(asn1.octetString, b))).toBe('040403040506');
    expect(hex(decode(asn1.octetString, bytes('040403040506')) as Uint8Array)).toBe('03040506');
  });

  it('BIT STRING with/without unused bits', () => {
    const v = new BitString(bytes('0a3b40'), 5);
    expect(hex(encode(asn1.bitString, v))).toBe('0304050a3b40');
    const back = decode(asn1.bitString, bytes('0304050a3b40')) as BitString;
    expect(back).toBeInstanceOf(BitString);
    expect(back.unusedBits).toBe(5);
    expect(hex(back.bytes)).toBe('0a3b40');
  });

  it('NULL', () => {
    expect(hex(encode(asn1.null, null))).toBe('0500');
    expect(decode(asn1.null, bytes('0500'))).toBeNull();
  });

  it('OBJECT IDENTIFIER', () => {
    const cases: [string, string][] = [
      ['1.2', '06012a'],
      ['2.100.3', '0603813403'],
      ['1.2.840.113549.1.1.11', '06092a864886f70d01010b'],
    ];
    for (const [oid, h] of cases) {
      expect(hex(encode(asn1.objectIdentifier, oid))).toBe(h);
      expect(decode(asn1.objectIdentifier, bytes(h))).toBe(oid);
    }
  });

  it('UTF8String', () => {
    const s = 'héllo 🙂';
    const enc = encode(asn1.utf8String, s);
    expect(hex(enc)).toBe('0c0b' + hex(Buffer.from(s, 'utf8')));
    expect(decode(asn1.utf8String, enc)).toBe(s);
  });
});

describe('constructed round trips', () => {
  it('SEQUENCE of named fields', () => {
    const schema = sequence([
      ['a', asn1.integer],
      ['b', asn1.boolean],
    ]);
    const enc = encode(schema, { a: 5n, b: true });
    expect(hex(enc)).toBe('30060201050101ff');
    const obj = decode(schema, enc) as Record<string, unknown>;
    expect(obj.a).toBe(5n);
    expect(obj.b).toBe(true);
  });

  it('SEQUENCE OF preserves order', () => {
    const schema = asn1.sequenceOf(asn1.integer);
    const v = [3n, 1n, 2n];
    const enc = encode(schema, v);
    expect(hex(enc)).toBe('3009020103020101020102');
    expect(decode(schema, enc)).toEqual([3n, 1n, 2n]);
  });

  it('nested structures round trip', () => {
    const schema = asn1.sequence([
      ['items', asn1.sequenceOf(asn1.sequence([['x', asn1.integer]]))],
      ['name', asn1.utf8String.optional()],
    ]);
    const v = { items: [{ x: 1n }, { x: 2n }], name: 'n' };
    expect(decode(schema, encode(schema, v))).toEqual(v);
  });

  it('small SET OF orders by encoded bytes (duplicates kept)', () => {
    const schema = setOf(integer);
    const v = [3n, 1n, 2n, 1n];
    expect(hex(encode(schema, v))).toBe('310c020101020101020102020103');
  });
});
