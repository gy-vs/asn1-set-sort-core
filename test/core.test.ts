import { expect, it } from 'vitest';
import {
  CanceledError,
  compareTlvBytes,
  concatBytes,
  encodeDerLength,
  encodeSetOf,
  kWayExternalMerge,
  MemoryTempStorage,
  parseTlv,
  prepareSetOf,
  RunInput,
  TempBudgetExceededError,
  TempHandle,
  TempStorage,
  TempStorageFailureError,
  tlv,
} from '../src/index.js';

/* ----------------------------- helpers ----------------------------- */

const INT = 0x02;
const OCTET_STRING = 0x04;
const SET = 0x31;

function integer(value: number | bigint): Uint8Array {
  let v = BigInt(value);
  const bytes: number[] = [];
  if (v < 0n) {
    // Minimal two's complement: smallest n with v >= -2^(8n-1).
    let width = 1;
    while (v < -(1n << BigInt(8 * width - 1))) width += 1;
    let rest = v + (1n << BigInt(8 * width));
    for (let i = 0; i < width; i++) {
      bytes.push(Number(rest & 0xffn));
      rest >>= 8n;
    }
    bytes.reverse();
  } else if (v === 0n) {
    bytes.push(0);
  } else {
    let rest = v;
    while (rest > 0n) {
      bytes.push(Number(rest & 0xffn));
      rest >>= 8n;
    }
    bytes.reverse();
    if (bytes[0]! & 0x80) bytes.unshift(0);
  }
  return tlv(INT, Uint8Array.from(bytes));
}

function octetString(...bytes: number[]): Uint8Array {
  return tlv(OCTET_STRING, Uint8Array.from(bytes));
}

function setOf(...elements: Uint8Array[]): Uint8Array {
  return concatBytes([Uint8Array.of(SET), encodeDerLength(concatBytes(elements).length), ...elements]);
}

function permutations<T>(items: readonly T[]): T[][] {
  if (items.length <= 1) return [[...items]];
  const out: T[][] = [];
  items.forEach((item, index) => {
    const rest = [...items.slice(0, index), ...items.slice(index + 1)];
    for (const perm of permutations(rest)) out.push([item, ...perm]);
  });
  return out;
}

function shuffled<T>(items: readonly T[], seed: number): T[] {
  const out = [...items];
  let state = seed;
  const rand = () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

/** Content TLVs of an encoded SET OF, in encoded order. */
function members(encoded: Uint8Array): Uint8Array[] {
  const outer = parseTlv(encoded, 0);
  const out: Uint8Array[] = [];
  let offset = outer.valueStart;
  while (offset < outer.end) {
    const part = parseTlv(encoded, offset);
    out.push(encoded.slice(offset, part.end));
    offset = part.end;
  }
  return out;
}

class CollectSink {
  readonly chunks: Uint8Array[] = [];
  write(chunk: Uint8Array): void {
    this.chunks.push(chunk);
  }
  bytes(): Uint8Array {
    return concatBytes(this.chunks);
  }
}

/* --------------------------- basic sorting -------------------------- */

it('sorts by complete TLV bytes, common long prefix decides at first diff', () => {
  const a = octetString(0x01, 0x02, 0x03, 0x04, 0x01);
  const b = octetString(0x01, 0x02, 0x03, 0x04, 0x02);
  const c = octetString(0x01, 0x02, 0x03, 0x04, 0xff);
  const expected = setOf(a, b, c);

  for (const order of permutations([a, b, c])) {
    expect(compareTlvBytes(order[0]!, order[0]!)).toBe(0);
    const encoded = setOf(
      ...[...order].sort(compareTlvBytes),
    );
    expect(encoded).toEqual(expected);
  }
});

it('encodes SET OF with identical bytes for every input permutation', async () => {
  const elements = [integer(1), integer(2), integer(127), integer(128), integer(0), integer(255)];
  const expected = await encodeSetOf({ elements });
  for (const order of permutations(elements)) {
    expect(await encodeSetOf({ elements: order })).toEqual(expected);
  }
  // Sanity: integers happen to land in ascending logical order here.
  expect(members(expected).map((m) => parseTlv(m).valueStart)).toHaveLength(6);
});

it('orders by encoding length octets, not logical value, when a prefix is shorter', async () => {
  // Tag and leading octets equal: 04 03 01 02 03 vs 04 04 01 02 03 04.
  const short = octetString(1, 2, 3);
  const long = octetString(1, 2, 3, 4);
  // 0x03 < 0x04 in the length octet, so the short TLV comes first even
  // though its value bytes are a strict prefix.
  expect(compareTlvBytes(short, long)).toBeLessThan(0);
  const expected = setOf(short, long);
  expect(await encodeSetOf({ elements: [long, short] })).toEqual(expected);
});

it('keeps all duplicate elements', async () => {
  const x = octetString(9, 9);
  const y = integer(42);
  const elements = [x, x, y, x, y, y, x];
  const encoded = await encodeSetOf({ elements });
  const found = members(encoded);
  expect(found).toHaveLength(7);
  expect(found.filter((m) => compareTlvBytes(m, x) === 0)).toHaveLength(4);
  expect(found.filter((m) => compareTlvBytes(m, y) === 0)).toHaveLength(3);
});

it('handles empty SET OF with length zero', async () => {
  expect(await encodeSetOf({ elements: [] })).toEqual(Uint8Array.of(0x31, 0x00));
});

/* ----------------------------- nesting ------------------------------ */

it('sorts nested SET OF elements by their complete outer encoding', async () => {
  // Inner SET OF members are themselves sorted; outer sort sees full TLVs.
  const nestedA = tlv(SET, setOf(integer(5)).subarray(2)); // SET TLV: 31 03 02 01 05
  const nestedB = tlv(SET, setOf(integer(1), integer(2)).subarray(2));
  const plain = integer(3);

  // 0x02 (INTEGER tag) < 0x31 (SET tag) at first octet.
  const expected = setOf(plain, nestedA, nestedB);
  for (const order of permutations([nestedA, nestedB, plain])) {
    expect(await encodeSetOf({ elements: order })).toEqual(expected);
  }

  // The inner SET OF is independently DER ordered regardless of input order.
  expect(await encodeSetOf({ elements: [tlv(SET, (await encodeSetOf({ elements: [integer(9), integer(1)] })).subarray(2))] }))
    .toEqual(
      await encodeSetOf({ elements: [tlv(SET, (await encodeSetOf({ elements: [integer(1), integer(9)] })).subarray(2))] }),
    );
});

/* ------------------------- oversized elements ----------------------- */

function bigOctetString(size: number, marker: number): Uint8Array {
  const value = new Uint8Array(size);
  value.fill(marker);
  return tlv(OCTET_STRING, value);
}

it('spills oversized elements to bounded temp storage and merges them back', async () => {
  const small = integer(7);
  const hugeA = bigOctetString(50_000, 0x01);
  const hugeB = bigOctetString(50_000, 0x02);
  const elements = [hugeB, small, hugeA];

  const storage = new MemoryTempStorage(1 << 20);
  const encoded = await encodeSetOf({ elements, memoryBytes: 4096, tempStorage: storage });
  // Temp handles are released after streaming.
  expect(storage.usedBytes).toBe(0);

  const found = members(encoded);
  expect(found).toHaveLength(3);
  expect(found[0]).toEqual(small);
  expect(found[1]).toEqual(hugeA);
  expect(found[2]).toEqual(hugeB);

  // Byte-identical to the pure in-memory encoding and to reordered input.
  const memoryEncoded = await encodeSetOf({ elements: shuffled(elements, 7) });
  expect(encoded).toEqual(memoryEncoded);
});

it('handles one member larger than the whole memory limit on its own run', async () => {
  const giant = bigOctetString(10_000, 0x05);
  const storage = new MemoryTempStorage();
  const encoded = await encodeSetOf({
    elements: [giant],
    memoryBytes: 1024,
    tempStorage: storage,
  });
  expect(members(encoded)).toEqual([giant]);
  expect(storage.usedBytes).toBe(0);
});

it('uses long-form length for a SET OF larger than 127 content bytes', async () => {
  const elements = Array.from({ length: 64 }, () => integer(0x42424242));
  const encoded = await encodeSetOf({ elements });
  expect(encoded[0]).toBe(0x31);
  const lenOctets = encoded[1]! & 0x7f;
  expect(encoded[1]! & 0x80).toBe(0x80);
  let declared = 0;
  for (let i = 0; i < lenOctets; i++) declared = declared * 0x100 + encoded[2 + i]!;
  expect(declared).toBe(encoded.length - 2 - lenOctets);
  expect(declared).toBeGreaterThan(127);
  expect(members(encoded)).toHaveLength(64);
});

it('streams through the external merge interface with sorted run inputs', async () => {
  // memoryBytes=1 means nearly every member becomes its own run.
  const elements = [integer(9), integer(1), integer(5), integer(3), integer(7)];
  const storage = new MemoryTempStorage();
  let runsSeen = 0;
  const customMerge = {
    mergeRuns(runs: readonly RunInput[], sink: { write(c: Uint8Array): void }, cancel?: unknown) {
      runsSeen = runs.length;
      return kWayExternalMerge.mergeRuns(runs, sink, cancel as never);
    },
  };
  const encoded = await encodeSetOf({
    elements,
    memoryBytes: 1,
    tempStorage: storage,
    externalMerge: customMerge,
  });
  expect(runsSeen).toBeGreaterThanOrEqual(2);
  const values = members(encoded).map((m) => m[m.length - 1]);
  expect(values).toEqual([1, 3, 5, 7, 9]);
});

/* ----------------------------- budgets ------------------------------ */

it('fails without success state when encoded data exceeds RAM and no temp storage exists', async () => {
  const giant = bigOctetString(10_000, 0x09);
  await expect(encodeSetOf({ elements: [giant], memoryBytes: 1024 })).rejects.toBeInstanceOf(
    TempBudgetExceededError,
  );
});

it('rejects when temp storage budget is too small and releases earlier runs', async () => {
  const elements = [bigOctetString(10_000, 1), bigOctetString(10_000, 2), bigOctetString(10_000, 3)];
  const storage = new MemoryTempStorage(15_000);
  await expect(
    encodeSetOf({ elements, memoryBytes: 1024, tempBytes: 15_000, tempStorage: storage }),
  ).rejects.toBeInstanceOf(TempBudgetExceededError);
  expect(storage.usedBytes).toBe(0);
});

it('wraps temp storage failures and still releases prior handles', async () => {
  const released: number[] = [];
  let call = 0;
  const failingStorage: TempStorage = {
    store(bytes: Uint8Array): TempHandle {
      call += 1;
      if (call === 2) throw new Error('disk full');
      const data = bytes.slice();
      return {
        size: data.length,
        read: (offset, size) => data.subarray(offset, offset + size),
        release: () => {
          released.push(data.length);
        },
      };
    },
  };
  const elements = [bigOctetString(5_000, 1), bigOctetString(5_000, 2)];
  await expect(
    encodeSetOf({ elements, memoryBytes: 1024, tempStorage: failingStorage }),
  ).rejects.toBeInstanceOf(TempStorageFailureError);
  expect(released).toHaveLength(1);
});

/* ---------------------------- cancellation --------------------------- */

it('cancellation before prepare resolves without writing anything', async () => {
  const sink = new CollectSink();
  const prepared = await prepareSetOf({ elements: [integer(1)] });
  const controller = new AbortController();
  controller.abort();
  await expect(prepared.writeTo(sink, controller.signal)).rejects.toBeInstanceOf(CanceledError);
  expect(sink.chunks).toHaveLength(0);
});

it('cancellation while encoding members aborts prepare and releases temp runs', async () => {
  const storage = new MemoryTempStorage();
  const controller = new AbortController();
  const elements = [
    bigOctetString(5_000, 1),
    {
      encode: () => {
        controller.abort();
        return bigOctetString(5_000, 2);
      },
    },
    bigOctetString(5_000, 3),
  ];
  await expect(
    prepareSetOf({ elements, memoryBytes: 1024, tempStorage: storage, cancel: controller.signal }),
  ).rejects.toBeInstanceOf(CanceledError);
  expect(storage.usedBytes).toBe(0);
});

it('cancellation during merge stops the stream and marks the prepared value failed', async () => {
  const elements = Array.from({ length: 20 }, (_unused, index) => bigOctetString(2_000, index));
  const storage = new MemoryTempStorage();
  const prepared = await prepareSetOf({
    elements,
    memoryBytes: 1024,
    tempStorage: storage,
  });
  const controller = new AbortController();
  let seen = 0;
  const sink = {
    async write(_chunk: Uint8Array) {
      seen += 1;
      if (seen === 5) controller.abort();
    },
  };
  await expect(prepared.writeTo(sink, controller.signal)).rejects.toBeInstanceOf(CanceledError);
  expect(storage.usedBytes).toBe(0);
  // A canceled write is not a success terminal state: retry is refused.
  await expect(prepared.writeTo(new CollectSink())).rejects.toThrow(/previously failed/);
});

it('does not allow writing a prepared SET OF twice', async () => {
  const prepared = await prepareSetOf({ elements: [integer(1)] });
  await prepared.writeTo(new CollectSink());
  await expect(prepared.writeTo(new CollectSink())).rejects.toThrow(/already been written/);
});

/* ---------------------- order invariance at scale -------------------- */

it('produces byte-identical output for randomized large and small members', async () => {
  const elements: Uint8Array[] = [
    integer(1),
    integer(0x7fffffff),
    integer(0x80000000),
    octetString(0, 0, 0),
    octetString(0, 0),
    bigOctetString(3_000, 0x01),
    bigOctetString(3_000, 0x02),
    bigOctetString(1_500, 0x01),
    octetString(0xff),
    integer(-1),
  ];
  const baseline = await encodeSetOf({ elements });
  for (let seed = 1; seed <= 5; seed++) {
    const storage = new MemoryTempStorage();
    const encoded = await encodeSetOf({
      elements: shuffled(elements, seed),
      memoryBytes: 2048,
      tempStorage: storage,
    });
    expect(storage.usedBytes).toBe(0);
    expect(encoded).toEqual(baseline);
  }
});

/* ------------------------- extra merge guarantees -------------------- */

it('retains duplicate records that land in different spilled runs', async () => {
  const dup = integer(0x77);
  // Three copies of the same TLV, separated by bigger members so they
  // almost certainly spill into distinct runs.
  const elements = [dup, bigOctetString(3_000, 0x10), dup, bigOctetString(3_000, 0x20), dup];
  const encoded = await encodeSetOf({
    elements,
    memoryBytes: 1024,
    tempStorage: new MemoryTempStorage(),
  });
  expect(members(encoded).filter((m) => compareTlvBytes(m, dup) === 0)).toHaveLength(3);
});

it('works with a temp backend whose reads return short chunks', async () => {
  const store = new Map<number, Uint8Array>();
  let nextId = 1;
  const shortReadStorage: TempStorage = {
    store(bytes: Uint8Array): TempHandle {
      const id = nextId++;
      store.set(id, bytes.slice());
      return {
        get size() {
          return store.get(id)!.length;
        },
        read(offset, size) {
          // Hand back at most 7 bytes at a time, straddling frame headers.
          const data = store.get(id)!;
          const take = Math.min(7, size, data.length - offset);
          return data.subarray(offset, offset + take);
        },
        release() {
          store.delete(id);
        },
      };
    },
  };
  const elements = [
    bigOctetString(2_000, 0x03),
    integer(5),
    bigOctetString(2_000, 0x01),
    integer(2),
    bigOctetString(2_000, 0x02),
  ];
  const encoded = await encodeSetOf({
    elements,
    memoryBytes: 1024,
    tempStorage: shortReadStorage,
  });
  expect(members(encoded).map((m) => m[0])).toEqual([0x02, 0x02, 0x04, 0x04, 0x04]);
  expect(store.size).toBe(0);
  // Identical to an in-memory encode.
  expect(encoded).toEqual(await encodeSetOf({ elements }));
});

it('accepts async element encoders and async iterables', async () => {
  const asyncElements = {
    async *[Symbol.asyncIterator]() {
      const values = [3, 1, 2];
      for (const value of values) {
        yield {
          encode: () => Promise.resolve(integer(value)),
        };
      }
    },
  };
  expect(await encodeSetOf({ elements: asyncElements })).toEqual(
    await encodeSetOf({ elements: [integer(1), integer(2), integer(3)] }),
  );
});

it('reports content length before writing and emits exactly encodedLength bytes', async () => {
  const elements = [bigOctetString(1_000, 1), integer(9), integer(1)];
  const prepared = await prepareSetOf({
    elements,
    memoryBytes: 512,
    tempStorage: new MemoryTempStorage(),
  });
  const sink = new CollectSink();
  await prepared.writeTo(sink);
  const bytes = sink.bytes();
  expect(bytes.length).toBe(prepared.encodedLength);
  const outer = parseTlv(bytes);
  expect(outer.end).toBe(bytes.length);
  expect(prepared.contentLength).toBe(bytes.length - (outer.valueStart));
});
