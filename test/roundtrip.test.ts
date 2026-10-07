import { describe, expect, it } from 'vitest';
import {
  asn1,
  BitString,
  Choice,
  decode,
  encode,
  AsnType,
  sequence,
} from '../src/index.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** Small deterministic PRNG so failures are reproducible. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

function randomBigInt(rand: () => number, bytes: number): bigint {
  let v = 0n;
  for (let i = 0; i < bytes; i++) v = (v << 8n) | BigInt(Math.floor(rand() * 256));
  // Randomize sign and force boundary values frequently.
  if (rand() < 0.5) v = -v;
  return v;
}

describe('encode → decode → encode stability (randomized)', () => {
  const intSet = asn1.setOf(asn1.integer);

  it('random integers round trip and re-encode identically', () => {
    for (let seed = 1; seed <= 20; seed++) {
      const rand = rng(seed);
      const values: bigint[] = [];
      for (let i = 0; i < 500; i++) {
        // bias the width to exercise 1/2/3-byte boundaries heavily
        const width = rand() < 0.6 ? 1 : rand() < 0.8 ? 2 : 4;
        values.push(randomBigInt(rand, width));
      }
      // Include exact boundary values.
      values.push(0n, 127n, 128n, 255n, 256n, -1n, -128n, -129n, -255n, -256n, -32768n, -32769n);

      const enc1 = encode(intSet, values.slice().reverse());
      const enc2 = encode(intSet, values.slice().sort(() => (rand() - 0.5)));
      expect(hex(enc1)).toBe(hex(enc2));

      const back = decode(intSet, enc1) as bigint[];
      const enc3 = encode(intSet, back);
      expect(hex(enc3)).toBe(hex(enc1));
      // Every decoded value must be a bigint.
      for (const v of back) expect(typeof v).toBe('bigint');
    }
  });

  it('random structured values round trip', () => {
    const schema = sequence([
      ['id', asn1.integer],
      ['name', asn1.utf8String.optional()],
      ['flags', asn1.boolean],
      ['blob', asn1.octetString],
      ['bits', asn1.bitString],
      ['oid', asn1.objectIdentifier],
      ['kids', asn1.sequenceOf(asn1.integer)],
      ['which', asn1.choice([
        ['i', asn1.integer],
        ['s', asn1.utf8String],
      ])],
    ]);

    const rand = rng(42);
    const words = ['alpha', 'βήτα', 'γ', '', 'delta 🙂', 'e'];
    const oids = ['1.2', '1.2.840.113549', '2.100.3.7', '1.3.6.1'];

    for (let iter = 0; iter < 30; iter++) {
      const blob = new Uint8Array(Math.floor(rand() * 20));
      for (let i = 0; i < blob.length; i++) blob[i] = Math.floor(rand() * 256);

      const kids: bigint[] = [];
      for (let i = 0; i < Math.floor(rand() * 5); i++) kids.push(randomBigInt(rand, 2));

      const value: Record<string, unknown> = {
        id: randomBigInt(rand, 3),
        flags: rand() < 0.5,
        blob,
        // unused bits 0..7 with the low bits forced clear
        bits: new BitString(new Uint8Array([0xf0]), 4),
        oid: oids[Math.floor(rand() * oids.length)],
        kids,
        which: rand() < 0.5 ? { i: randomBigInt(rand, 2) } : { s: words[Math.floor(rand() * words.length)] },
      };
      if (rand() > 0.3) value.name = words[Math.floor(rand() * words.length)];

      const enc = encode(schema, value);
      const back = decode(schema, enc);
      const enc2 = encode(schema, back);
      expect(hex(enc2)).toBe(hex(enc));
    }
  });
});

describe('explicit/implicit tagging vectors', () => {
  it('implicit BIT STRING content semantics preserved', () => {
    const schema = asn1.bitString.implicit(2);
    const v = new BitString(new Uint8Array([0xaa]), 0);
    const enc = encode(schema, v);
    expect(hex(enc)).toBe('820200aa');
    const back = decode(schema, enc) as BitString;
    expect(back.unusedBits).toBe(0);
    expect(hex(back.bytes)).toBe('aa');
  });

  it('explicit tag wrapping an OPTIONAL field behaves like the field', () => {
    const schema = sequence([
      ['x', asn1.integer.explicit(0).optional()],
      ['y', asn1.integer],
    ]);
    expect(decode(schema, encode(schema, { y: 1n }))).toEqual({ y: 1n });
    const both = { x: 5n, y: 1n };
    const enc = encode(schema, both);
    expect(decode(schema, enc)).toEqual(both);
  });
});

describe('strict decoder never accepts encoder output as invalid', () => {
  it('encoder output for all schema kinds passes the strict decoder', () => {
    const s = sequence([
      ['a', asn1.integer.default(0n)],
      ['b', asn1.boolean.default(false)],
      ['c', asn1.setOf(asn1.integer)],
    ]);
    const v = { c: [3n, 1n, 2n] }; // defaults omitted
    const enc = encode(s, v);
    const back = decode(s, enc) as { c: bigint[]; a: bigint; b: boolean };
    expect(back.a).toBe(0n);
    expect(back.b).toBe(false);
    expect(back.c).toEqual([1n, 2n, 3n]);
    expect(hex(encode(s, back))).toBe(hex(enc));
  });
});
