# ASN.1 DER core

TypeScript library for DER encoding and decoding, with DER-compliant SET OF
ordering (X.690 §11.6).

Run `npm install`, then `npm test` and `npm run build`.

## SET OF sorting

SET OF members are ordered by **unsigned lexicographic comparison of their
complete DER encodings** — tag octets, length octets and contents compared
together — never by logical value or by tag alone. When one encoding is a
prefix of another, the shorter one sorts first. Duplicate members are all
retained. The resulting bytes are identical for every input order.

```ts
import { encodeSetOf, tlv } from './src/index.js';

const a = tlv(0x04, Uint8Array.of(1, 2, 3));
const b = tlv(0x02, Uint8Array.of(7));
const encoded = await encodeSetOf({ elements: [a, b] }); // sorted for you
```

### Two-phase encoding

`prepareSetOf` first encodes all members, determines the sorted order and the
final content length, and only then allows streaming the header and members:

```ts
const prepared = await prepareSetOf({ elements, cancel: signal });
prepared.contentLength; // known before any byte is written
await prepared.writeTo(sink);
```

Nothing is emitted on cancel or temporary-storage failure, and a failed
`PreparedSetOf` never reaches a reusable/success terminal state (re-writing
throws).

### Small elements: in-memory sort

Up to `memoryBytes` of encoded TLV data is held in RAM and sorted directly.

### Large elements: bounded temp storage + external merge

When encoded data exceeds `memoryBytes`, sorted runs are spilled to a
`TempStorage` backend under a hard `tempBytes` budget. Runs use a framed
format (`uint32 BE length | TLV`) and are streamed back through a
`TempHandle.read(offset, size)` API that tolerates short reads, so only one
record per run needs to be resident during the merge.

```ts
interface TempStorage { store(bytes: Uint8Array): MaybePromise<TempHandle>; }
interface TempHandle {
  readonly size: number;
  read(offset: number, size: number): MaybePromise<Uint8Array>;
  release(): MaybePromise<void>;
}
```

`MemoryTempStorage` (with an optional byte budget) is provided; supply your
own backend (disk, blob store, ...) by implementing those two interfaces. The
default merge is a streaming k-way lexicographic merge
(`kWayExternalMerge`, one record of headroom per run); replace it via
`externalMerge`, which receives one `RunInput` per already-sorted run and a
`ByteSink`.

Cancellation accepts an `AbortSignal` or a `{ canceled: boolean }` token.
