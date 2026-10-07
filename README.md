# asn1 DER core

A small, dependency-free **DER (X.690) encoder/decoder** for Node, driven by a
schema you declare up front. Both sides encode the same way, so the bytes
match byte-for-byte across implementations.

- Zero runtime dependencies (Node built-ins only).
- Deterministic DER output: minimal INTEGER/length encodings, `SET`/`SET OF`
  members sorted by encoded bytes (including nested ones), `DEFAULT`-equal and
  absent `OPTIONAL` fields omitted.
- Strict decoder rejects every non-unique DER form (indefinite length,
  non-minimal length/INTEGER/tag, unsorted SET, explicit DEFAULT field,
  trailing bytes, …) with byte offset and a path such as
  `$.certs[3].validity.notBefore`.
- Bounded nesting depth; oversized declared lengths fail immediately and never
  allocate proportional memory.
- `INTEGER` maps to/from JS `bigint`.

## Usage

```ts
import { asn1, encode, decode } from './dist/index.js';

// SEQUENCE { id INTEGER, name UTF8String OPTIONAL, attrs SET OF OCTET STRING }
const schema = asn1.sequence([
  ['id', asn1.integer],
  ['name', asn1.utf8String.optional()],
  ['attrs', asn1.setOf(asn1.octetString)],
]);

const der = encode(schema, {
  id: 1234n,
  attrs: [Buffer.from('02'), Buffer.from('01')], // input order is irrelevant
});
// attrs are emitted sorted: 01 then 02

const value = decode(schema, der); // { id: 1234n, attrs: [Uint8Array(01), Uint8Array(02)] }
```

### Types

| Schema factory        | ASN.1          | JS value                         |
| --------------------- | -------------- | -------------------------------- |
| `asn1.boolean`        | BOOLEAN        | `boolean`                        |
| `asn1.integer`        | INTEGER        | `bigint`                         |
| `asn1.bitString`      | BIT STRING     | `new BitString(Uint8Array, n)`   |
| `asn1.octetString`    | OCTET STRING   | `Uint8Array`                     |
| `asn1.null`           | NULL           | `null`                           |
| `asn1.objectIdentifier` | OBJECT IDENTIFIER | dotted `"1.2.840.…"` string   |
| `asn1.utf8String`     | UTF8String     | `string`                         |
| `asn1.sequenceOf(t)`  | SEQUENCE OF    | `unknown[]` (order preserved)    |
| `asn1.setOf(t)`       | SET OF         | `unknown[]` (canonically sorted) |
| `asn1.sequence([…])`  | SEQUENCE       | plain object                     |
| `asn1.set([…])`       | SET            | plain object (members sorted)    |
| `asn1.choice([…])`    | CHOICE         | `Choice` or single-key object    |

Fields are `[name, type]` tuples. Modifiers chain on a type:

```ts
asn1.integer.optional()
asn1.integer.default(0n)
asn1.integer.implicit(0)        // context tag [0] IMPLICIT
asn1.octetString.explicit(1)    // context tag [1] EXPLICIT
```

Recursive types use `asn1.lazy(() => node)`. A decoded `CHOICE` is a
`Choice { name, value }`; encoding also accepts `{ [name]: value }`.

### Options

```ts
encode(schema, value, { maxDepth: 512 })
decode(schema, bytes, { strict: true, maxDepth: 512 })
```

`strict: false` tolerates BER-ish inputs (non-minimal INTEGER/BOOLEAN/length,
unsorted SET OF, unknown fields, explicit DEFAULT) but re-encoding such a
value always produces canonical DER.

Errors are `DERError` with `.offset` (byte offset or `null`) and `.path`
(structural location).

## Scripts

- `npm install`
- `npm test` — vitest (round trips, order-independent SET bytes, strict
  rejections, error paths, 100k-element performance, depth/length attacks)
- `npm run build` — `tsc` → `dist/`
