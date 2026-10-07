/**
 * Minimal, dependency-free DER (X.690) encoder/decoder.
 *
 * Build a schema with the type factories (`sequence`, `setOf`, `choice`, ...),
 * optionally annotate fields with `.optional()`, `.default()`, `.implicit(n)`,
 * `.explicit(n)`, then `encode(schema, value)` / `decode(schema, bytes)`.
 */
export {
  // top-level driver
  encode,
  decode,
  // value types
  BitString,
  Choice,
  // schema node types (for instanceof and modifier chaining)
  AsnType,
  OptionalType,
  DefaultType,
  ImplicitType,
  ExplicitType,
  CollectionOfType,
  SequenceOrSetType,
  ChoiceType,
  LazyType,
  // options
  type EncodeOptions,
  type DecodeOptions,
  type FieldDef,
  // error type
  DERError,
} from './schema.js';

export { DERError as DERDecodeError } from './errors.js';

import {
  boolean,
  integer,
  bitString,
  octetString,
  nullType,
  objectIdentifier,
  utf8String,
  sequenceOf,
  setOf,
  sequence,
  set,
  choice,
  lazy,
} from './schema.js';

/**
 * Primitive/constructed type factories and singletons.
 *
 * ```ts
 * import { asn1 } from './index.js';
 * const schema = asn1.sequence([['id', asn1.integer], ['name', asn1.utf8String.optional()]]);
 * ```
 */
export const asn1 = {
  boolean,
  integer,
  bitString,
  octetString,
  null: nullType,
  objectIdentifier,
  utf8String,
  sequenceOf,
  setOf,
  sequence,
  set,
  choice,
  lazy,
};

export {
  boolean,
  integer,
  bitString,
  octetString,
  nullType,
  objectIdentifier,
  utf8String,
  sequenceOf,
  setOf,
  sequence,
  set,
  choice,
  lazy,
};
