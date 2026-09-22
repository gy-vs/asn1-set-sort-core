import { describe, expect, it } from 'vitest';
import {
  Asn1Error,
  compareDer,
  createMemoryTempStore,
  encodeDerLength,
  encodeSetOf,
  planSetOf,
  type TempStore,
} from '../src/index.js';

// --- DER element builders -------------------------------------------------

function tlv(tag: number, value: number[]): Uint8Array {
  return Uint8Array.from([tag, value.length, ...value]);
}

/** DER INTEGER (minimal two's complement, non-negative values). */
function int(value: number): Uint8Array {
  const bytes: number[] = [];
  for (let n = value; n > 0; n = n >> 8) bytes.unshift(n & 0xff);
  if (bytes.length === 0) bytes.push(0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, bytes);
}

function octets(...value: number[]): Uint8Array {
  return tlv(0x04, value);
}

/** OCTET STRING of `size` bytes filled with `fill`, long-form length. */
function bigOctets(fill: number, size: number): Uint8Array {
  const header = encodeDerLength(size);
  const out = new Uint8Array(1 + header.length + size);
  out[0] = 0x04;
  out.set(header, 1);
  out.fill(fill, 1 + header.length);
  return out;
}

function setOfRaw(...elements: Uint8Array[]): Uint8Array {
  const content = elements.flatMap((e) => [...e]);
  const header = encodeDerLength(content.length);
  return Uint8Array.from([0x31, ...header, ...content]);
}

/** Reference encoder: sort complete encodings lexicographically, concat. */
function referenceSetOf(elements: Uint8Array[]): Uint8Array {
  const sorted = elements.map((e) => e.slice()).sort(compareDer);
  const content = sorted.flatMap((e) => [...e]);
  const header = encodeDerLength(content.length);
  return Uint8Array.from([0x31, ...header, ...content]);
}

function permutations<T>(items: T[]): T[][] {
  if (items.length <= 1) return [items.slice()];
  const out: T[][] = [];
  for (let i = 0; i < items.length; i++) {
    for (const rest of permutations([
      ...items.slice(0, i),
      ...items.slice(i + 1),
    ])) {
      out.push([items[i], ...rest]);
    }
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

// --- comparison and length encoding ---------------------------------------

describe('compareDer', () => {
  it('orders by full TLV bytes, not by tag or logical value', () => {
    // BOOLEAN true (01 01 ff) before INTEGER 0 (02 01 00): the tag byte decides.
    expect(compareDer(tlv(0x01, [0xff]), int(0))).toBeLessThan(0);
    // INTEGER 300 (02 02 01 2c) sorts AFTER INTEGER 5 (02 01 05): the length
    // byte (02 vs 01) differs before any content byte — full-TLV order.
    expect(compareDer(int(300), int(5))).toBeGreaterThan(0);
    // INTEGER -1 (02 01 ff) sorts after INTEGER 1 (02 01 01): content byte
    // 0xff > 0x01 even though -1 < 1 numerically.
    expect(compareDer(tlv(0x02, [0xff]), int(1))).toBeGreaterThan(0);
  });

  it('places a strict prefix before its extension', () => {
    expect(compareDer(octets(1, 2), octets(1, 2, 3))).toBeLessThan(0);
    expect(compareDer(octets(1, 2, 3), octets(1, 2))).toBeGreaterThan(0);
  });

  it('treats equal encodings as equal (duplicates)', () => {
    expect(compareDer(int(7), int(7))).toBe(0);
  });
});

describe('encodeDerLength', () => {
  it('uses short form below 128 and minimal long form above', () => {
    expect([...encodeDerLength(0)]).toEqual([0]);
    expect([...encodeDerLength(127)]).toEqual([127]);
    expect([...encodeDerLength(128)]).toEqual([0x81, 0x80]);
    expect([...encodeDerLength(255)]).toEqual([0x81, 0xff]);
    expect([...encodeDerLength(256)]).toEqual([0x82, 0x01, 0x00]);
    expect([...encodeDerLength(65536)]).toEqual([0x83, 0x01, 0x00, 0x00]);
  });
});

// --- canonical ordering ----------------------------------------------------

describe('encodeSetOf ordering', () => {
  it('sorts elements sharing a long common prefix by the first differing byte', () => {
    const prefix = Array.from({ length: 64 }, (_, i) => i & 0xff);
    const a = octets(...prefix, 0x00, 0xff);
    const b = octets(...prefix, 0x00, 0x01);
    const c = octets(...prefix, 0x00, 0x7f);
    const encoded = encodeSetOf([a, b, c]);
    expect(encoded).toEqual(referenceSetOf([a, b, c]));
    // b (…00 01) < c (…00 7f) < a (…00 ff) regardless of input order.
    expect(hex(encoded)).toBe(hex(setOfRaw(b, c, a)));
  });

  it('orders different-length elements with a shared prefix correctly', () => {
    const short = octets(1, 2);
    const long = octets(1, 2, 3);
    const other = octets(1, 3);
    // short is a prefix of long => short first; other (04 02 01 03) shares
    // short's length byte but differs at content[1]; long (04 03 …) differs
    // at the length byte, so it sorts last.
    expect(encodeSetOf([long, other, short])).toEqual(
      setOfRaw(short, other, long),
    );
  });

  it('keeps duplicate elements', () => {
    const plan = planSetOf([int(1), int(1), int(2), int(1)]);
    expect(plan.elementCount).toBe(4);
    expect(plan.toBytes()).toEqual(setOfRaw(int(1), int(1), int(1), int(2)));
  });

  it('sorts nested SET encodings as opaque TLVs', () => {
    const inner1 = setOfRaw(int(2)); // 31 03 02 01 02
    const inner2 = setOfRaw(int(1), int(3)); // 31 06 02 01 01 02 01 03
    const inner3 = setOfRaw(int(1)); // 31 03 02 01 01
    // inner3 < inner1 (last content byte 01 < 02); inner2 sorts last because
    // its length byte 0x06 differs before any content byte.
    expect(encodeSetOf([inner1, inner2, inner3])).toEqual(
      setOfRaw(inner3, inner1, inner2),
    );
    expect(encodeSetOf([inner1, inner2, inner3])).toEqual(
      referenceSetOf([inner1, inner2, inner3]),
    );
  });

  it('encodes an empty SET OF as 31 00', () => {
    expect([...encodeSetOf([])]).toEqual([0x31, 0x00]);
  });

  it('emits a long-form length when content reaches 128 bytes', () => {
    const elements = Array.from({ length: 40 }, (_, i) => octets(i, i, i));
    const encoded = encodeSetOf(elements);
    expect(encoded[0]).toBe(0x31);
    expect(encoded[1]).toBe(0x81);
    expect(encoded[2]).toBe(200);
    expect(encoded.length).toBe(3 + 200);
    expect(encoded).toEqual(referenceSetOf(elements));
  });
});

// --- determinism -----------------------------------------------------------

describe('determinism', () => {
  it('produces byte-identical output for every input permutation', () => {
    const elements = [
      int(0),
      int(255),
      int(256),
      octets(1, 2),
      octets(1, 2, 3),
      setOfRaw(int(9)),
      tlv(0x01, [0xff]),
    ];
    const expected = referenceSetOf(elements);
    for (const perm of permutations(elements)) {
      expect(hex(encodeSetOf(perm))).toBe(hex(expected));
    }
  });

  it('produces identical bytes when elements move between memory and spill paths', () => {
    const elements = [bigOctets(0x10, 600), bigOctets(0x20, 600), int(1), octets(9)];
    const allInMemory = encodeSetOf(elements);
    const allSpilled = encodeSetOf(elements, { memoryThresholdBytes: 0 });
    const mixed = encodeSetOf(elements, { memoryThresholdBytes: 100 });
    expect(hex(allSpilled)).toBe(hex(allInMemory));
    expect(hex(mixed)).toBe(hex(allInMemory));
    expect(hex(allInMemory)).toBe(hex(referenceSetOf(elements)));
  });
});

// --- two-phase plan --------------------------------------------------------

describe('planSetOf', () => {
  it('reports the exact length before anything is written', () => {
    const elements = [int(1), octets(1, 2, 3), setOfRaw(int(4))];
    const plan = planSetOf(elements);
    expect(plan.elementCount).toBe(3);
    expect(plan.contentLength).toBe(3 + 5 + 5);
    expect(plan.totalLength).toBe(2 + 13);
    expect(plan.toBytes().length).toBe(plan.totalLength);
  });

  it('streams exactly totalLength bytes, identical to toBytes()', () => {
    const plan = planSetOf([int(3), int(1), int(2)]);
    const chunks: Uint8Array[] = [];
    let streamed = 0;
    plan.writeTo((chunk) => {
      chunks.push(chunk);
      streamed += chunk.length;
    });
    expect(streamed).toBe(plan.totalLength);
    expect(hex(Uint8Array.from(chunks.flatMap((c) => [...c])))).toBe(
      hex(plan.toBytes()),
    );
  });

  it('rejects elements that are not byte-encodable', () => {
    expect(() => planSetOf([{}])).toThrowError(Asn1Error);
    expect(() => planSetOf([new Uint8Array(0)])).toThrowError(/too short/);
  });

  it('refuses to write after disposal', () => {
    const plan = planSetOf([int(1)]);
    plan.dispose();
    plan.dispose(); // idempotent
    expect(() => plan.toBytes()).toThrowError(/disposed/);
  });
});

// --- external merge over bounded temp storage ------------------------------

describe('spill and merge', () => {
  it('spills oversized elements and k-way merges runs in sorted order', () => {
    // 6 elements of 100 bytes, threshold 0 => all spilled; maxOpenRuns 2
    // forces repeated mergeAll passes (6 -> 3 -> 2 -> 1 runs).
    const fills = [0x50, 0x10, 0x40, 0x20, 0x60, 0x30];
    const elements = fills.map((f) => bigOctets(f, 100));
    const encoded = encodeSetOf(elements, {
      memoryThresholdBytes: 0,
      maxOpenRuns: 2,
    });
    expect(encoded).toEqual(referenceSetOf(elements));
    // Content is 6 * 102 bytes => SET OF header is 31 82 02 64; the first
    // sorted element is the 0x10-filled one at offset 4.
    expect(encoded[4]).toBe(0x04);
    expect(encoded[6]).toBe(0x10);
  });

  it('merges spilled runs and in-memory elements into one sorted stream', () => {
    const small = [int(1), octets(0x05)];
    const big = [bigOctets(0x03, 200), bigOctets(0x07, 200)];
    const encoded = encodeSetOf([...big, ...small], {
      memoryThresholdBytes: 100,
    });
    expect(encoded).toEqual(referenceSetOf([...big, ...small]));
  });

  it('keeps duplicates across the spill path', () => {
    const dup = bigOctets(0x2a, 150);
    const elements = [dup, bigOctets(0x11, 150), dup];
    const plan = planSetOf(elements, { memoryThresholdBytes: 0 });
    expect(plan.elementCount).toBe(3);
    expect(plan.toBytes()).toEqual(referenceSetOf(elements));
  });

  it('fails when the temp budget is exceeded and leaves no success state', () => {
    const elements = [bigOctets(0x01, 100), bigOctets(0x02, 100)];
    expect(() =>
      encodeSetOf(elements, { memoryThresholdBytes: 0, tempBudgetBytes: 150 }),
    ).toThrowError(/temp budget exceeded/);

    // Nothing may be written when planning fails: no header, no partial elements.
    const sink: number[] = [];
    let plan;
    try {
      plan = planSetOf(elements, {
        memoryThresholdBytes: 0,
        tempBudgetBytes: 150,
      });
      plan.writeTo((chunk) => sink.push(...chunk));
    } catch {
      // expected
    }
    expect(plan).toBeUndefined();
    expect(sink).toEqual([]);
  });

  it('releases all temp storage when planning fails mid-spill', () => {
    // A store that tracks live bytes and fails once 150 bytes are outstanding.
    let live = 0;
    const tracking: TempStore = {
      createRun() {
        const chunks: Uint8Array[] = [];
        let size = 0;
        return {
          append(chunk) {
            if (live + chunk.length > 150) {
              throw new Asn1Error('ERR_TEMP_STORE', 'disk full');
            }
            chunks.push(chunk);
            live += chunk.length;
            size += chunk.length;
          },
          byteLength: () => size,
          *[Symbol.iterator]() {
            yield* chunks;
          },
          close() {
            live -= size;
            size = 0;
            chunks.length = 0;
          },
        };
      },
    };
    const elements = [bigOctets(0x01, 100), bigOctets(0x02, 100)];
    expect(() =>
      encodeSetOf(elements, { memoryThresholdBytes: 0, tempStore: tracking }),
    ).toThrowError(/disk full/);
    expect(live).toBe(0); // every run closed during cleanup
  });

  it('releases the merged run when the plan is disposed', () => {
    let live = 0;
    const tracking: TempStore = {
      createRun() {
        const inner = createMemoryTempStore(1 << 20).createRun();
        return {
          append(chunk) {
            inner.append(chunk);
            live += chunk.length;
          },
          byteLength: () => inner.byteLength(),
          *[Symbol.iterator]() {
            yield* inner;
          },
          close() {
            live -= inner.byteLength();
            inner.close();
          },
        };
      },
    };
    const elements = [bigOctets(0x01, 100), bigOctets(0x02, 100)];
    const totalBytes = elements.reduce((n, e) => n + e.length, 0);
    const plan = planSetOf(elements, {
      memoryThresholdBytes: 0,
      tempStore: tracking,
    });
    expect(live).toBe(totalBytes); // one merged run backs the plan
    expect(plan.toBytes()).toEqual(referenceSetOf(elements));
    plan.dispose();
    expect(live).toBe(0);
  });

  it('one-shot encodeSetOf disposes its temp runs', () => {
    let live = 0;
    const tracking: TempStore = {
      createRun() {
        const inner = createMemoryTempStore(1 << 20).createRun();
        return {
          append(chunk) {
            inner.append(chunk);
            live += chunk.length;
          },
          byteLength: () => inner.byteLength(),
          *[Symbol.iterator]() {
            yield* inner;
          },
          close() {
            live -= inner.byteLength();
            inner.close();
          },
        };
      },
    };
    encodeSetOf([bigOctets(0x01, 100)], {
      memoryThresholdBytes: 0,
      tempStore: tracking,
    });
    expect(live).toBe(0);
  });
});

// --- cancellation ----------------------------------------------------------

describe('cancellation', () => {
  function* infinite(): Generator<Uint8Array> {
    for (let i = 0; ; i++) yield int(i & 0xff);
  }

  it('aborts planning on an already-aborted signal without writing anything', () => {
    const controller = new AbortController();
    controller.abort();
    const sink: number[] = [];
    expect(() => planSetOf([int(1)], { signal: controller.signal })).toThrowError(
      Asn1Error,
    );
    expect(sink).toEqual([]);
  });

  it('stops mid-iteration when the signal aborts, with no success state', () => {
    const controller = new AbortController();
    const yielded: Uint8Array[] = [];
    const iterable: Iterable<Uint8Array> = {
      *[Symbol.iterator]() {
        for (const e of infinite()) {
          yielded.push(e);
          yield e;
          if (yielded.length === 10) controller.abort();
        }
      },
    };
    let plan;
    try {
      plan = planSetOf(iterable, { signal: controller.signal });
    } catch (error) {
      expect(error).toBeInstanceOf(Asn1Error);
      expect((error as Asn1Error).code).toBe('ERR_CANCELLED');
    }
    expect(plan).toBeUndefined();
    expect(yielded.length).toBeLessThan(100); // iteration actually stopped
  });

  it('does not consult the signal during the write phase', () => {
    const controller = new AbortController();
    const plan = planSetOf([int(2), int(1)], { signal: controller.signal });
    controller.abort(); // abort after planning: the plan stays valid
    expect(plan.toBytes()).toEqual(setOfRaw(int(1), int(2)));
  });
});

// --- randomized cross-check ------------------------------------------------

describe('randomized equivalence', () => {
  /** Deterministic PRNG so failures reproduce. */
  function lcg(seed: number): () => number {
    let s = seed >>> 0;
    return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
  }

  it('matches the reference for shuffled inputs across memory/spill configs', () => {
    const rand = lcg(0x5eed);
    const tags = [0x01, 0x02, 0x04, 0x30, 0x31];
    const elements: Uint8Array[] = [];
    for (let i = 0; i < 120; i++) {
      const size = 2 + Math.floor(rand() * 300);
      const el = new Uint8Array(size);
      el[0] = tags[Math.floor(rand() * tags.length)];
      el[1] = size - 2; // opaque to the encoder; need not be a valid length
      for (let j = 2; j < size; j++) el[j] = Math.floor(rand() * 256);
      elements.push(el);
    }
    // Inject duplicates, including of a spilled-sized element.
    elements.push(elements[3].slice(), elements[3].slice(), elements[50].slice());

    const expected = hex(referenceSetOf(elements));
    const configs = [
      {},
      { memoryThresholdBytes: 0 },
      { memoryThresholdBytes: 64, maxOpenRuns: 3 },
      { memoryThresholdBytes: 32, maxOpenRuns: 2 },
    ];
    for (const options of configs) {
      for (let trial = 0; trial < 4; trial++) {
        const shuffled = elements.slice();
        for (let i = shuffled.length - 1; i > 0; i--) {
          const j = Math.floor(rand() * (i + 1));
          [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        expect(hex(encodeSetOf(shuffled, options))).toBe(expected);
      }
    }
  });
});

// --- options validation ----------------------------------------------------

describe('options validation', () => {
  it('rejects unusable merge fan-in and negative budgets', () => {
    expect(() => planSetOf([int(1)], { maxOpenRuns: 1 })).toThrowError(
      Asn1Error,
    );
    expect(() => planSetOf([int(1)], { memoryThresholdBytes: -1 })).toThrowError(
      Asn1Error,
    );
    expect(() => planSetOf([int(1)], { tempBudgetBytes: -1 })).toThrowError(
      Asn1Error,
    );
  });
});
