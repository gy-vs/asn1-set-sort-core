import { describe, expect, it } from 'vitest';
import {
  asn1,
  AsnType,
  Choice,
  decode,
  DERError,
  encode,
  lazy,
} from '../src/index.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));

/** Build `depth` nested SEQUENCE wrappers around a final INTEGER 0 TLV. */
function nestedDer(depth: number): Uint8Array {
  let body = bytes('020100');
  for (let level = 1; level <= depth; level++) {
    const len = body.length;
    const lenEnc: number[] =
      len < 0x80
        ? [len]
        : (() => {
            const o: number[] = [];
            for (let v = len; v > 0; v >>>= 8) o.unshift(v & 0xff);
            return [0x80 | o.length, ...o];
          })();
    const next = new Uint8Array(1 + lenEnc.length + len);
    next[0] = 0x30;
    lenEnc.forEach((b, i) => (next[1 + i] = b));
    next.set(body, 1 + lenEnc.length);
    body = next;
  }
  return body;
}

/**
 * Recursive schema: `Node ::= CHOICE { leaf INTEGER, node SEQUENCE OF Node }`.
 */
function recursiveSchema(): AsnType {
  const node: AsnType = asn1.choice([
    ['leaf', asn1.integer],
    ['children', asn1.sequenceOf(lazy(() => node))],
  ]);
  return node;
}

describe('nesting depth limits', () => {
  const schema = recursiveSchema();

  it('rejects ~20k nested TLVs without exhausting the call stack', () => {
    const deep = nestedDer(20000);
    let err: unknown;
    try {
      decode(schema, deep);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(DERError);
    expect((err as DERError).message).toMatch(/nesting depth/);
  });

  it('rejects deep nesting at a configured small limit with a clear error', () => {
    const deep = nestedDer(50);
    let err: unknown;
    try {
      decode(schema, deep, { maxDepth: 10 });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(DERError);
    expect((err as DERError).message).toMatch(/exceeds the allowed maximum of 10/);
  });

  it('accepts nesting up to the configured limit', () => {
    const depth = 8;
    const data = nestedDer(depth);
    const decoded = decode(schema, data, { maxDepth: depth + 1 });
    // unwrap 8 nested Choice(children=[...]) wrappers → leaf 0
    let cur: unknown = decoded;
    for (let i = 0; i < depth; i++) {
      expect(cur).toBeInstanceOf(Choice);
      cur = (cur as Choice).value;
      expect(Array.isArray(cur)).toBe(true);
      cur = (cur as unknown[])[0];
    }
    expect(cur).toEqual(new Choice('leaf', 0n));
  });

  it('encoder also enforces depth', () => {
    // Build nested values; each level is { children: [...] } for the CHOICE.
    let v: unknown = new Choice('leaf', 0n);
    for (let i = 0; i < 6; i++) v = new Choice('children', [v]);
    let err: unknown;
    try {
      encode(schema, v, { maxDepth: 3 });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(DERError);
    expect((err as DERError).message).toMatch(/nesting depth/);
  });

  it('shallow recursion encodes/decodes identically under a generous limit', () => {
    let v: unknown = new Choice('leaf', 7n);
    for (let i = 0; i < 5; i++) v = new Choice('children', [v]);
    const enc = encode(schema, v, { maxDepth: 64 });
    const back = decode(schema, enc, { maxDepth: 64 });
    expect(back).toEqual(v);
  });
});

describe('declared-length attacks', () => {
  it('fails immediately when the declared length exceeds the available bytes', () => {
    // OCTET STRING claiming 0x01000000 bytes with none following.
    const evil = bytes('048401000000');
    const start = performance.now();
    expect(() => decode(asn1.octetString, evil)).toThrowError(/truncated|declared length/);
    expect(performance.now() - start).toBeLessThan(50);
  });

  it('rejects length encodings beyond the supported 4-byte form before allocating', () => {
    const evil = bytes('04850100000000');
    expect(() => decode(asn1.octetString, evil)).toThrowError();
  });

  it('declared giant nested length does not allocate memory', () => {
    // SEQUENCE declaring 0x7fffffff bytes but the buffer is tiny.
    const evil = bytes('30847fffffff');
    const start = performance.now();
    expect(() => decode(asn1.sequence([]), evil)).toThrowError(/truncated|declared length/);
    // The failure is bounds-only; it must not scale with the declared length.
    expect(performance.now() - start).toBeLessThan(500);
  });
});

describe('100 000-element SET OF performance', () => {
  const N = 100_000;
  const schema = asn1.setOf(asn1.integer);
  const values: bigint[] = [];
  for (let i = 0; i < N; i++) {
    values.push(BigInt(((i * 7919 + 104729) % 200000) - 100000));
  }
  const shuffled = values.slice().reverse();

  it('encodes 100k unordered elements under 2s, independent of input order', () => {
    const t = performance.now();
    const a = encode(schema, shuffled);
    const elapsed = performance.now() - t;
    const b = encode(schema, values.slice().sort(() => Math.random() - 0.5));
    expect(hex(a)).toBe(hex(b));
    expect(elapsed).toBeLessThan(2000);
  });

  it('decodes 100k elements under 2s and re-encodes to identical bytes', () => {
    const enc = encode(schema, shuffled);
    const t = performance.now();
    const dec = decode(schema, enc) as bigint[];
    const elapsed = performance.now() - t;
    expect(elapsed).toBeLessThan(2000);
    expect(dec.length).toBe(N);
    expect(hex(encode(schema, dec))).toBe(hex(enc));
  });
});
