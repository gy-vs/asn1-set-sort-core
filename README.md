# ASN.1 DER core

TypeScript library for DER encoding and decoding.

Run `npm install`, then `npm test` and `npm run build`.

## DER SET OF encoding (`src/setof.ts`)

`planSetOf` / `encodeSetOf` encode a SET OF with the canonical DER ordering of
X.690 §11.6: elements are sorted by their **complete DER encodings** (tag +
length + value) compared as octet strings — not by logical value, not by tag.
Duplicate elements are kept.

```ts
import { planSetOf, encodeSetOf } from 'asn1-set-sort-core';

const bytes = encodeSetOf([elementA, elementB]); // one-shot

const plan = planSetOf(elements, options);       // two-phase
plan.totalLength;                                // known before anything is written
plan.writeTo((chunk) => socket.write(chunk));    // streamed, in sorted order
plan.dispose();                                  // release temp runs
```

Encoding is two-phase: **planning** encodes and sorts all elements privately
and computes the exact length; only then does **writing** stream bytes to the
sink. A cancellation (`options.signal`) or temp-store failure aborts the plan
before a single byte reaches the sink, so a failed encode can never leave a
successful terminal state.

### Large elements

Elements encoded to more than `memoryThresholdBytes` (default 64 KiB) are
spilled to a bounded temp store and merged back with a k-way external merge
(`maxOpenRuns` controls the fan-in). The default store is in-memory and capped
by `tempBudgetBytes` (default 8 MiB); exceeding the budget fails the plan.
Provide `options.tempStore` to spill elsewhere (e.g. disk):

```ts
interface TempStore {
  createRun(): {
    append(chunk: Uint8Array): void;
    byteLength(): number;
    [Symbol.iterator](): Iterator<Uint8Array>;
    close(): void;
  };
}
```

Output is byte-identical regardless of input order and regardless of which
elements took the spill path.
