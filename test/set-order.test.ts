import { describe, expect, it } from 'vitest';
import { asn1, decode, encode, sequence, set, setOf } from '../src/index.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));

describe('SET OF canonical ordering', () => {
  const schema = setOf(asn1.integer);

  it('emits identical bytes regardless of input order', () => {
    const orders: bigint[][] = [
      [1n, 2n, 3n, 4n, 5n],
      [5n, 4n, 3n, 2n, 1n],
      [3n, 1n, 5n, 2n, 4n],
      [1n, 3n, 2n, 5n, 4n],
    ];
    const expected = hex(encode(schema, orders[0]));
    for (const o of orders) expect(hex(encode(schema, o))).toBe(expected);
    expect(expected).toBe('310f020101020102020103020104020105');
  });

  it('ordering compares full encoded TLVs, not decoded integer values', () => {
    // positive 0 → 020100, negative -1 → 0201ff: ff sorts after 00
    const v = [-1n, 0n];
    const enc = encode(schema, v);
    expect(hex(enc)).toBe('31060201000201ff');
  });

  it('nested SET OF is canonical at every level', () => {
    const schema = setOf(setOf(asn1.integer));
    // 300 needs 2 content bytes (0202012c); -5 one (0201fb): the short
    // element sorts first, proving the inner level sorted.
    const a = [3n, 1n, 2n];
    const b = [300n, -5n];
    const inputA = [b, a, b, a];
    const shuffled = [a, b, a, b];
    expect(hex(encode(schema, inputA))).toBe(hex(encode(schema, shuffled)));
    const enc = encode(schema, inputA);
    expect(decode(schema, enc)).toEqual([[-5n, 300n], [-5n, 300n], [1n, 2n, 3n], [1n, 2n, 3n]]);
  });

  it('SET OF of structured elements sorts by child encoding', () => {
    const inner = sequence([['n', asn1.integer]]);
    const schema = setOf(inner);
    const input = [{ n: 9n }, { n: 1n }, { n: 200n }];
    const enc = encode(schema, input);
    // 3003 020101; 3003 020109; 3004 020200c8  (content total 0x10)
    expect(hex(enc)).toBe('3110300302010130030201093004020200c8');
    expect(decode(schema, enc)).toEqual([{ n: 1n }, { n: 9n }, { n: 200n }]);
  });

  it('SET (named fields) sorts members by their encoded TLVs', () => {
    // Integer field sorts before boolean regardless of declaration order on wire:
    // 02.. < 01.. actually 01 < 02, so boolean comes first on wire.
    const schema = set([
      ['i', asn1.integer],
      ['flag', asn1.boolean],
    ]);
    const enc = encode(schema, { i: 1n, flag: true });
    expect(hex(enc)).toBe('31060101ff020101');
    expect(decode(schema, enc)).toEqual({ flag: true, i: 1n });
  });
});
