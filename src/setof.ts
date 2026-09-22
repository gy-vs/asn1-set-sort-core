/**
 * DER SET OF encoding with canonical ordering.
 *
 * X.690 §11.6: the components of a SET OF are sorted by their complete DER
 * encodings (tag + length + value) compared as octet strings — not by logical
 * value and not by tag. Duplicate components are kept.
 *
 * Encoding runs in two phases so the caller never observes a successful
 * terminal state after a failure:
 *   1. plan  — encode every element privately, sort, compute the total
 *              length. Cancellation and temp-store failures abort here,
 *              before a single byte is written to the sink.
 *   2. write — stream the header and the sorted elements to the sink.
 *
 * Elements whose encoded size fits the in-memory threshold are sorted in
 * memory. Larger elements are spilled to a bounded temp store and merged
 * back with a k-way merge over sorted runs; the merge keeps at most one
 * chunk per run in memory at a time.
 */

export class Asn1Error extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'Asn1Error';
    this.code = code;
  }
}

export interface SetOfOptions {
  /** Aborted before or during planning => nothing is written to the sink. */
  signal?: AbortSignal;
  /** Elements encoded to at most this many bytes are sorted in memory. Default 64 KiB. */
  memoryThresholdBytes?: number;
  /** Total byte budget for spilled elements; exceeding it fails the plan. Default 8 MiB. */
  tempBudgetBytes?: number;
  /** Merge fan-in; also the max number of simultaneously open spill runs. Minimum 2, default 16. */
  maxOpenRuns?: number;
  /** Temp store override; defaults to an in-memory store with the same interface. */
  tempStore?: TempStore;
}

export interface SetOfPlan {
  /** Byte length of the complete SET OF TLV (header + content). */
  totalLength: number;
  /** Byte length of the content octets only. */
  contentLength: number;
  /** Number of elements, duplicates included. */
  elementCount: number;
  /** Stream the planned encoding to `sink`. */
  writeTo(sink: (chunk: Uint8Array) => void): void;
  /** Concatenated SET OF TLV. */
  toBytes(): Uint8Array;
  /**
   * Release the temp run backing this plan, if any. Idempotent; the plan
   * cannot be written after disposal. Plans whose elements all fit in
   * memory hold no temp resources.
   */
  dispose(): void;
}

/** Bounded scratch space for elements too large to sort in memory. */
export interface TempStore {
  createRun(): TempRun;
}

export interface TempRun {
  append(chunk: Uint8Array): void;
  byteLength(): number;
  /** Chunks in append order. Iterating a finished run must not fail. */
  [Symbol.iterator](): Iterator<Uint8Array>;
  /** Idempotent. */
  close(): void;
}

const DER_TAG_SET_OF = 0x31;
const DEFAULT_MEMORY_THRESHOLD = 64 * 1024;
const DEFAULT_TEMP_BUDGET = 8 * 1024 * 1024;
const DEFAULT_MAX_OPEN_RUNS = 16;

/** Lexicographic comparison of complete DER encodings (X.690 §11.6). */
export function compareDer(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a[i] - b[i];
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** DER length octets (short form below 128, minimal long form otherwise). */
export function encodeDerLength(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Asn1Error('ERR_LENGTH', `invalid length ${length}`);
  }
  if (length < 0x80) return Uint8Array.of(length);
  const bytes: number[] = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function encodeElement(element: unknown): Uint8Array {
  let encoded: Uint8Array;
  try {
    encoded =
      element instanceof Uint8Array
        ? element
        : new Uint8Array(element as ArrayBufferLike);
  } catch {
    throw new Asn1Error('ERR_ELEMENT', 'element is not byte-encodable');
  }
  if (encoded.length < 2) {
    throw new Asn1Error(
      'ERR_ELEMENT',
      `element encoding too short (${encoded.length} bytes)`,
    );
  }
  return encoded;
}

function checkCancelled(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new Asn1Error('ERR_CANCELLED', 'SET OF planning cancelled');
  }
}

/** In-memory temp store; honours the same bounded interface as a disk store. */
export function createMemoryTempStore(budgetBytes: number): TempStore {
  let used = 0;
  return {
    createRun(): TempRun {
      const chunks: Uint8Array[] = [];
      let size = 0;
      let closed = false;
      return {
        append(chunk: Uint8Array): void {
          if (closed) {
            throw new Asn1Error('ERR_TEMP_STORE', 'append to closed run');
          }
          if (used + chunk.length > budgetBytes) {
            throw new Asn1Error(
              'ERR_TEMP_BUDGET',
              `temp budget exceeded: ${used + chunk.length} > ${budgetBytes}`,
            );
          }
          const copy = chunk.slice();
          chunks.push(copy);
          used += copy.length;
          size += copy.length;
        },
        byteLength: () => size,
        *[Symbol.iterator](): Iterator<Uint8Array> {
          yield* chunks;
        },
        close(): void {
          if (closed) return;
          closed = true;
          used -= size;
          chunks.length = 0;
          size = 0;
        },
      };
    },
  };
}

interface SpilledRun {
  run: TempRun;
  byteLength: number;
}

class RunSet {
  private readonly runs: SpilledRun[] = [];
  constructor(
    private readonly store: TempStore,
    private readonly maxOpenRuns: number,
  ) {}

  add(bytes: Uint8Array): void {
    if (this.runs.length >= this.maxOpenRuns) {
      // Never append to a full run set: merge first so a failure below
      // cannot leave an element duplicated across runs.
      this.mergeAll();
    }
    const run = this.store.createRun();
    try {
      run.append(bytes);
    } catch (error) {
      run.close();
      throw error;
    }
    this.runs.push({ run, byteLength: run.byteLength() });
  }

  mergeAll(): void {
    if (this.runs.length <= 1) return;
    const merged = this.store.createRun();
    try {
      for (const chunk of mergeRuns(this.runs)) merged.append(chunk);
    } catch (error) {
      merged.close();
      throw error;
    }
    for (const { run } of this.runs) run.close();
    this.runs.length = 0;
    this.runs.push({ run: merged, byteLength: merged.byteLength() });
  }

  /** Single sorted run; empty when nothing was spilled. */
  finish(): SpilledRun | undefined {
    this.mergeAll();
    return this.runs[0];
  }

  closeAll(): void {
    for (const { run } of this.runs) run.close();
    this.runs.length = 0;
  }
}

/** K-way merge of sorted runs; keeps one chunk per run in memory. */
function* mergeRuns(runs: SpilledRun[]): Generator<Uint8Array> {
  const heads = runs.map(({ run }) => run[Symbol.iterator]());
  const current: (Uint8Array | undefined)[] = heads.map((it) => {
    const next = it.next();
    return next.done ? undefined : next.value;
  });
  for (;;) {
    let pick = -1;
    for (let i = 0; i < current.length; i++) {
      const c = current[i];
      if (c === undefined) continue;
      if (pick === -1 || compareDer(c, current[pick]!) < 0) pick = i;
    }
    if (pick === -1) return;
    const out = current[pick]!;
    const next = heads[pick].next();
    current[pick] = next.done ? undefined : next.value;
    yield out;
  }
}

export function planSetOf(
  elements: Iterable<unknown>,
  options: SetOfOptions = {},
): SetOfPlan {
  const memoryThreshold =
    options.memoryThresholdBytes ?? DEFAULT_MEMORY_THRESHOLD;
  const tempBudget = options.tempBudgetBytes ?? DEFAULT_TEMP_BUDGET;
  const maxOpenRuns = options.maxOpenRuns ?? DEFAULT_MAX_OPEN_RUNS;
  if (memoryThreshold < 0 || tempBudget < 0 || maxOpenRuns < 2) {
    // A merge sorter needs at least two runs to make progress.
    throw new Asn1Error('ERR_OPTION', 'invalid SetOfOptions');
  }
  const store = options.tempStore ?? createMemoryTempStore(tempBudget);

  const inMemory: Uint8Array[] = [];
  const spilled = new RunSet(store, maxOpenRuns);
  let contentLength = 0;
  let elementCount = 0;

  // Phase 1: encode privately, sort, measure. Any throw here — cancellation,
  // temp budget, bad element — happens before the sink sees a single byte.
  try {
    for (const element of elements) {
      checkCancelled(options.signal);
      const bytes = encodeElement(element);
      if (bytes.length <= memoryThreshold) {
        inMemory.push(bytes);
      } else {
        spilled.add(bytes);
      }
      contentLength += bytes.length;
      elementCount++;
    }
    checkCancelled(options.signal);

    inMemory.sort(compareDer);
    const finalRun = spilled.finish();
    const header = encodeDerLength(contentLength);
    const totalLength = 1 + header.length + contentLength;

    let disposed = false;
    const writeTo = (sink: (chunk: Uint8Array) => void): void => {
      if (disposed) {
        throw new Asn1Error('ERR_STATE', 'plan has been disposed');
      }
      // Phase 2: pure streaming of the already-planned output.
      sink(Uint8Array.of(DER_TAG_SET_OF));
      sink(header);
      if (finalRun === undefined) {
        for (const bytes of inMemory) sink(bytes);
      } else {
        for (const bytes of mergeRuns([
          { run: toRun(inMemory), byteLength: 0 },
          finalRun,
        ])) {
          sink(bytes);
        }
      }
    };

    return {
      totalLength,
      contentLength,
      elementCount,
      writeTo,
      toBytes(): Uint8Array {
        const chunks: Uint8Array[] = [];
        writeTo((chunk) => chunks.push(chunk));
        const out = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
          out.set(chunk, offset);
          offset += chunk.length;
        }
        return out;
      },
      dispose(): void {
        if (disposed) return;
        disposed = true;
        finalRun?.run.close();
      },
    };
  } catch (error) {
    spilled.closeAll();
    throw error;
  }
}

/** Adapter so the in-memory sorted list merges through the same path. */
function toRun(sorted: Uint8Array[]): TempRun {
  return {
    append(): void {
      throw new Asn1Error('ERR_TEMP_STORE', 'run is read-only');
    },
    byteLength: () => 0,
    *[Symbol.iterator](): Iterator<Uint8Array> {
      yield* sorted;
    },
    close(): void {},
  };
}

/** Convenience one-shot: plan and encode a DER SET OF. */
export function encodeSetOf(
  elements: Iterable<unknown>,
  options: SetOfOptions = {},
): Uint8Array {
  const plan = planSetOf(elements, options);
  try {
    return plan.toBytes();
  } finally {
    plan.dispose();
  }
}
