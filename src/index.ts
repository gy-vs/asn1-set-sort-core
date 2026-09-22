/**
 * ASN.1 DER core.
 *
 * SET OF encoding (X.690 11.6): the elements of a SET OF must be ordered by
 * the lexicographic comparison of their complete DER encodings (tag octets,
 * length octets and contents), never by logical value or tag alone. Equal
 * encodings (duplicates) are all retained.
 */

export type MaybePromise<T> = T | PromiseLike<T>;

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

export class DerSetError extends Error {
  override name = 'DerSetError';
}

/** Thrown when encoding was canceled through a CancelToken / AbortSignal. */
export class CanceledError extends DerSetError {
  override name = 'CanceledError';
  constructor(message = 'SET OF encoding canceled') {
    super(message);
  }
}

/** Thrown when encoded elements cannot fit in RAM or in the temp budget. */
export class TempBudgetExceededError extends DerSetError {
  override name = 'TempBudgetExceededError';
  constructor(message: string) {
    super(message);
  }
}

/** Wraps any failure reported by the pluggable temporary storage. */
export class TempStorageFailureError extends DerSetError {
  override name = 'TempStorageFailureError';
  constructor(message: string, readonly cause?: unknown) {
    super(message);
  }
}

/* ------------------------------------------------------------------ */
/* Cancellation                                                        */
/* ------------------------------------------------------------------ */

export interface CancelToken {
  readonly canceled: boolean;
}

export type CancelSignal = CancelToken | AbortSignal;

function isAbortSignal(signal: CancelSignal): signal is AbortSignal {
  return typeof (signal as Partial<AbortSignal>).aborted === 'boolean';
}

export function isCanceled(signal?: CancelSignal): boolean {
  if (!signal) return false;
  return isAbortSignal(signal) ? signal.aborted : signal.canceled;
}

function throwIfCanceled(signal?: CancelSignal): void {
  if (isCanceled(signal)) throw new CanceledError();
}

/* ------------------------------------------------------------------ */
/* DER byte primitives                                                 */
/* ------------------------------------------------------------------ */

const EMPTY = new Uint8Array(0);

export function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Encodes a DER length (short or long form), minimally. */
export function encodeDerLength(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new DerSetError(`invalid DER length: ${length}`);
  }
  if (length < 0x80) return Uint8Array.of(length);
  const bytes: number[] = [];
  let rest = length;
  while (rest > 0) {
    bytes.push(rest & 0xff);
    rest = Math.floor(rest / 0x100);
  }
  bytes.reverse();
  if (bytes.length > 6) throw new DerSetError(`DER length too large: ${length}`);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

/** Builds a complete DER TLV. */
export function tlv(tag: number, value: Uint8Array): Uint8Array {
  return concatBytes([Uint8Array.of(tag), encodeDerLength(value.length), value]);
}

/** Builds the DER SET OF header (universal, constructed, tag 17). */
export function setOfHeader(contentLength: number): Uint8Array {
  return concatBytes([Uint8Array.of(0x31), encodeDerLength(contentLength)]);
}

/**
 * X.690 ordering: unsigned lexicographic comparison of the complete DER
 * encoding of two SET OF elements (T, L and V octets together). Shorter
 * encodings sort first when one is a prefix of the other.
 */
export function compareTlvBytes(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i++) {
    const diff = a[i] - b[i];
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

/* ------------------------------------------------------------------ */
/* Legacy decoding helpers (kept for compatibility)                    */
/* ------------------------------------------------------------------ */

export type Tlv = { tag: number; length: number; value: Uint8Array };

export function decodeTlv(data: Uint8Array): Tlv {
  if (data.length < 2) throw new Error('truncated');
  const tag = data[0];
  const length = data[1];
  if (length & 128) throw new Error('long length unsupported');
  if (data.length < 2 + length) throw new Error('truncated');
  return { tag, length, value: data.slice(2, 2 + length) };
}

export function decodeInteger(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** Structural TLV parser supporting long-form lengths and nested data. */
export function parseTlv(data: Uint8Array, offset = 0): {
  tag: number;
  valueStart: number;
  valueLength: number;
  end: number;
} {
  if (offset + 2 > data.length) throw new DerSetError('truncated TLV');
  const tag = data[offset];
  let p = offset + 1;
  const first = data[p++];
  let valueLength: number;
  if ((first & 0x80) === 0) {
    valueLength = first;
  } else {
    const count = first & 0x7f;
    if (count === 0 || count > 6 || p + count > data.length) {
      throw new DerSetError('invalid DER length');
    }
    valueLength = 0;
    for (let i = 0; i < count; i++) valueLength = valueLength * 0x100 + data[p + i];
    p += count;
  }
  const end = p + valueLength;
  if (end > data.length) throw new DerSetError('truncated TLV value');
  return { tag, valueStart: p, valueLength, end };
}

/* ------------------------------------------------------------------ */
/* Elements, sinks and temporary storage                               */
/* ------------------------------------------------------------------ */

/** A SET OF member: either a ready DER TLV or an encoder producing one. */
export type DerElement = Uint8Array | { encode(): MaybePromise<Uint8Array> };

/** Streaming output target. The encoder never buffers the whole result. */
export interface ByteSink {
  write(chunk: Uint8Array): MaybePromise<void>;
}

/** Handle to bytes held by a TempStorage backend (disk, blob store, ...). */
export interface TempHandle {
  readonly size: number;
  /**
   * Reads up to `size` bytes starting at `offset`. Implementations may
   * return a shorter buffer; the reader keeps pulling until satisfied.
   */
  read(offset: number, size: number): MaybePromise<Uint8Array>;
  release(): MaybePromise<void>;
}

/** Backend for bounded temporary storage of sort runs. */
export interface TempStorage {
  store(bytes: Uint8Array): MaybePromise<TempHandle>;
}

/** Simple in-memory TempStorage with an optional hard byte budget. */
export class MemoryTempStorage implements TempStorage {
  #used = 0;
  #live = new Set<TempHandle>();

  constructor(readonly budget: number = Number.POSITIVE_INFINITY) {}

  /** Bytes currently held by unreleased handles. */
  get usedBytes(): number {
    return this.#used;
  }

  store(bytes: Uint8Array): TempHandle {
    if (this.#used + bytes.length > this.budget) {
      throw new TempBudgetExceededError(
        `temp budget exceeded: ${this.#used}+${bytes.length} > ${this.budget}`,
      );
    }
    const data = bytes.slice();
    this.#used += data.length;
    const storage = this;
    const handle: TempHandle = {
      get size() {
        return data.length;
      },
      read(offset, size) {
        return data.subarray(offset, Math.min(offset + size, data.length));
      },
      release() {
        if (storage.#live.has(handle)) {
          storage.#live.delete(handle);
          storage.#used -= data.length;
        }
      },
    };
    this.#live.add(handle);
    return handle;
  }
}

/* ------------------------------------------------------------------ */
/* External merge interface                                            */
/* ------------------------------------------------------------------ */

/** A lexicographically ordered stream of complete TLV records. */
export interface RunInput {
  /** Returns the next TLV or null at end of run. */
  nextRecord(): MaybePromise<Uint8Array | null>;
}

/**
 * Pluggable external merge. Implementations receive one RunInput per sorted
 * run (each run is already ordered by complete TLV bytes) and must write the
 * k-way lexicographic merge to `sink`, retaining duplicate records.
 */
export interface ExternalMerge {
  mergeRuns(
    runs: readonly RunInput[],
    sink: ByteSink,
    cancel?: CancelSignal,
  ): MaybePromise<void>;
}

/**
 * Streaming k-way lexicographic merge. Only one record per run is buffered,
 * so extra RAM is bounded by the number of runs times one record; the run
 * payload itself is pulled through TempHandle.read on demand.
 */
export const kWayExternalMerge: ExternalMerge = {
  async mergeRuns(runs, sink, cancel) {
    const heads = await Promise.all(runs.map((run) => run.nextRecord()));
    for (;;) {
      throwIfCanceled(cancel);
      let best = -1;
      for (let i = 0; i < heads.length; i++) {
        const head = heads[i];
        if (head !== null && (best === -1 || compareTlvBytes(head, heads[best]!) < 0)) {
          best = i;
        }
      }
      if (best === -1) return;
      const record = heads[best]!;
      await sink.write(record);
      heads[best] = await runs[best]!.nextRecord();
    }
  },
};

/**
 * Framed run layout: records are concatenated as
 *   uint32 BE record length | record bytes
 * so a run can be streamed back without holding it entirely in memory.
 */
const RUN_READ_CHUNK = 64 * 1024;

export function buildRun(records: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const record of records) total += 4 + record.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const record of records) {
    view.setUint32(offset, record.length);
    out.set(record, offset + 4);
    offset += 4 + record.length;
  }
  return out;
}

class EofError extends DerSetError {}

/** Streams framed records out of a TempHandle, tolerating short reads. */
class TempRunReader implements RunInput {
  #chunk: Uint8Array = EMPTY;
  #pos = 0;
  #offset = 0;

  constructor(private readonly handle: TempHandle) {}

  async nextRecord(): Promise<Uint8Array | null> {
    if (this.#offset >= this.handle.size && this.#pos >= this.#chunk.length) {
      return null;
    }
    let header: Uint8Array;
    try {
      header = await this.#need(4);
    } catch (error) {
      if (error instanceof EofError) return null;
      throw error;
    }
    const length =
      ((header[0]! << 24) >>> 0) | (header[1]! << 16) | (header[2]! << 8) | header[3]!;
    const body = await this.#need(length);
    if (body.length !== length) throw new DerSetError('truncated record in sort run');
    return body;
  }

  async #need(size: number): Promise<Uint8Array> {
    const out = new Uint8Array(size);
    let filled = 0;
    while (filled < size) {
      if (this.#pos >= this.#chunk.length) {
        if (this.#offset >= this.handle.size) {
          if (filled === 0) throw new EofError('end of run');
          throw new DerSetError('truncated sort run');
        }
        const want = Math.min(RUN_READ_CHUNK, this.handle.size - this.#offset);
        const chunk = await this.handle.read(this.#offset, want);
        if (chunk.length === 0) throw new DerSetError('temp read returned no bytes');
        this.#offset += chunk.length;
        this.#chunk = chunk;
        this.#pos = 0;
      }
      const take = Math.min(size - filled, this.#chunk.length - this.#pos);
      out.set(this.#chunk.subarray(this.#pos, this.#pos + take), filled);
      this.#pos += take;
      filled += take;
    }
    return out;
  }
}

function memoryHandle(bytes: Uint8Array): TempHandle {
  return {
    get size() {
      return bytes.length;
    },
    read(offset, size) {
      return bytes.subarray(offset, Math.min(offset + size, bytes.length));
    },
    release() {},
  };
}

/* ------------------------------------------------------------------ */
/* SET OF encoder                                                      */
/* ------------------------------------------------------------------ */

export interface SetOfOptions {
  /** Elements may be raw complete TLVs or objects with an encode() method. */
  elements: Iterable<DerElement> | AsyncIterable<DerElement>;
  /** Encoded TLV bytes collectable in RAM before spilling to temp. */
  memoryBytes?: number;
  /** Hard upper bound on bytes held in temp storage during the sort. */
  tempBytes?: number;
  /** Required when encoded data exceeds memoryBytes. */
  tempStorage?: TempStorage;
  /** External merge implementation; defaults to a streaming k-way merge. */
  externalMerge?: ExternalMerge;
  cancel?: CancelSignal;
}

export interface PreparedSetOf {
  /** Total length of SET OF member TLVs, in sorted order. */
  readonly contentLength: number;
  /** Total encoded SET OF length including header. */
  readonly encodedLength: number;
  /**
   * Streams the SET OF header followed by sorted members. Determining the
   * order and length is fully finished before this is called, so nothing is
   * emitted on cancel or temp failure. A PreparedSetOf can only be written
   * once; a failed write never reaches a successful terminal state.
   */
  writeTo(sink: ByteSink, cancel?: CancelSignal): Promise<void>;
}

async function elementBytes(element: DerElement): Promise<Uint8Array> {
  return element instanceof Uint8Array ? element : Promise.resolve(element.encode());
}

function isAsyncIterable(
  elements: Iterable<DerElement> | AsyncIterable<DerElement>,
): elements is AsyncIterable<DerElement> {
  return typeof (elements as Partial<AsyncIterable<DerElement>>)[Symbol.asyncIterator] === 'function';
}

export async function prepareSetOf(options: SetOfOptions): Promise<PreparedSetOf> {
  const memoryLimit = options.memoryBytes ?? 1 << 20;
  const tempBudget = options.tempBytes ?? Number.POSITIVE_INFINITY;
  const storage = options.tempStorage;
  const merger = options.externalMerge ?? kWayExternalMerge;
  const initialCancel = options.cancel;

  if (!Number.isSafeInteger(memoryLimit) || memoryLimit < 0) {
    throw new DerSetError(`invalid memoryBytes: ${memoryLimit}`);
  }

  let memory: Uint8Array[] = [];
  let memoryUsed = 0;
  const spilled: TempHandle[] = [];
  let tempUsed = 0;
  let contentLength = 0;
  let recordCount = 0;

  async function releaseAll(): Promise<void> {
    const handles = spilled.splice(0);
    await Promise.all(
      handles.map(async (handle) => {
        try {
          await handle.release();
        } catch {
          /* best-effort cleanup */
        }
      }),
    );
  }

  async function spill(run: Uint8Array): Promise<void> {
    if (!storage) {
      throw new TempBudgetExceededError(
        `encoded SET OF data exceeds memoryBytes ${memoryLimit} but no temp storage was provided`,
      );
    }
    if (tempUsed + run.length > tempBudget) {
      throw new TempBudgetExceededError(
        `temp budget exceeded: ${tempUsed}+${run.length} > ${tempBudget}`,
      );
    }
    let handle: TempHandle;
    try {
      handle = await Promise.resolve(storage.store(run));
    } catch (error) {
      if (error instanceof TempBudgetExceededError) throw error;
      throw new TempStorageFailureError('temporary storage rejected sort run', error);
    }
    spilled.push(handle);
    tempUsed += handle.size;
  }

  try {
    const consume = async (element: DerElement): Promise<void> => {
      throwIfCanceled(initialCancel);
      const tlvBytes = await elementBytes(element);
      if (!(tlvBytes instanceof Uint8Array) || tlvBytes.length < 2) {
        throw new DerSetError('SET OF member did not encode to a DER TLV');
      }
      contentLength += tlvBytes.length;
      recordCount += 1;
      if (memoryUsed + tlvBytes.length > memoryLimit) {
        // A member that fits makes the current run full: flush a sorted run.
        if (memoryUsed > 0) {
          memory.sort(compareTlvBytes);
          await spill(buildRun(memory));
          memory = [];
          memoryUsed = 0;
        }
        // A member larger than the RAM limit gets its own run in temp, or it
        // simply starts the next run when spilling did not happen.
        if (tlvBytes.length > memoryLimit) {
          await spill(buildRun([tlvBytes]));
        } else {
          memory.push(tlvBytes);
          memoryUsed += tlvBytes.length;
        }
      } else {
        memory.push(tlvBytes);
        memoryUsed += tlvBytes.length;
      }
    };

    if (isAsyncIterable(options.elements)) {
      for await (const element of options.elements) await consume(element);
    } else {
      for (const element of options.elements) await consume(element);
    }
    throwIfCanceled(initialCancel);
  } catch (error) {
    await releaseAll();
    throw error;
  }

  // Fix the order before any output can start. The spilled path keeps its
  // order in the run headers and merges it lazily while streaming.
  if (spilled.length === 0) memory.sort(compareTlvBytes);

  const header = setOfHeader(contentLength);
  let state: 'ready' | 'writing' | 'done' | 'failed' = 'ready';

  const prepared: PreparedSetOf = {
    contentLength,
    encodedLength: header.length + contentLength,

    async writeTo(sink: ByteSink, cancelOverride?: CancelSignal): Promise<void> {
      if (state === 'done') throw new DerSetError('PreparedSetOf has already been written');
      if (state === 'failed') throw new DerSetError('PreparedSetOf previously failed');
      if (state === 'writing') throw new DerSetError('PreparedSetOf write is already in progress');
      state = 'writing';
      const cancel = cancelOverride ?? initialCancel;
      try {
        throwIfCanceled(cancel);
        // Header is the first byte that leaves the encoder, and it is only
        // emitted once length and order are fully determined.
        await sink.write(header);

        if (spilled.length === 0) {
          let written = 0;
          for (const record of memory) {
            throwIfCanceled(cancel);
            await sink.write(record);
            written += 1;
          }
          if (written !== recordCount) {
            throw new DerSetError(`record count mismatch: ${written} != ${recordCount}`);
          }
        } else {
          // Remaining RAM members become one extra sorted run that never
          // touches temp; spilled runs are merged with it lexicographically.
          const runs: RunInput[] = spilled.map((handle) => new TempRunReader(handle));
          let memoryRun: TempHandle | undefined;
          if (memory.length > 0) {
            memory.sort(compareTlvBytes);
            memoryRun = memoryHandle(buildRun(memory));
          }
          if (memoryRun) runs.push(new TempRunReader(memoryRun));

          let emitted = 0;
          const countingSink: ByteSink = {
            async write(chunk) {
              await sink.write(chunk);
              emitted += 1;
            },
          };
          try {
            await merger.mergeRuns(runs, countingSink, cancel);
          } finally {
            await releaseAll();
          }
          if (emitted !== recordCount) {
            throw new DerSetError(`merge record count mismatch: ${emitted} != ${recordCount}`);
          }
        }
        state = 'done';
      } catch (error) {
        state = 'failed';
        if (spilled.length > 0) await releaseAll();
        throw error;
      }
    },
  };

  return prepared;
}

/** One-shot convenience: prepare, then collect the streamed bytes. */
export async function encodeSetOf(options: SetOfOptions): Promise<Uint8Array> {
  const prepared = await prepareSetOf(options);
  const chunks: Uint8Array[] = [];
  const sink: ByteSink = {
    async write(chunk) {
      chunks.push(chunk);
    },
  };
  await prepared.writeTo(sink);
  return concatBytes(chunks);
}
