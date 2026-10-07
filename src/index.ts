/**
 * A small, zero-runtime-dependency DER (X.690) encoding/decoding library.
 *
 * Describe a value with the schema builders, then `encode(schema, obj)` /
 * `decode(schema, bytes)`. Encoding always yields the unique DER form; the
 * strict decoder rejects any input that is not that form.
 *
 *     import {sequence, integer, utf8String, setOf, encode, decode, Choice}
 *       from './index.js';
 */
export {Asn1Error} from './errors.js';
export type {PathStep} from './errors.js';
export {
  TagClass,
  UniversalTag,
  type Schema,
  type SchemaKind,
  type PrimitiveSchema,
  type StructuredSchema as SequenceSchema,
  type HomogeneousSchema as CollectionSchema,
  type ChoiceSchema,
  type ExplicitTagSchema,
  type FieldDef,
} from './schema.js';
export {
  boolean,
  integer,
  bitString,
  octetString,
  /** NULL type builder. Use this in plain-JS ESM imports; `null` is a keyword. */
  nullSchema as nullType,
  /** Deprecated alias: cannot be used as a plain-JS named import (`null` keyword). */
  nullSchema as null_,
  oid,
  utf8String,
  sequence,
  set,
  sequenceOf,
  setOf,
  choice,
  implicit,
  explicit,
  optional,
  withDefault,
  type FieldsInput,
  type FieldSpec,
  type FieldEntry,
  type ChoiceInput,
} from './dsl.js';
export {Choice} from './encode.js';
export type {ChoiceValue} from './encode.js';
export type {BitStringValue} from './primitives.js';
export type {OidValue} from './primitives.js';
export type {DecodeOptions} from './decode.js';

import {Asn1Error} from './errors.js';
import {encodeValue, type ChoiceValue} from './encode.js';
import {decodeValueTop, type DecodeOptions} from './decode.js';
import type {Schema} from './schema.js';

export interface EncodeOptions {
  /** Maximum nesting depth accepted. Defaults to 256. */
  maxDepth?: number;
}

/**
 * Encode a JS value to its unique DER byte sequence.
 * INTEGER fields are bigints; OCTET STRING fields are Uint8Array;
 * BIT STRING fields are `{ unused, data }`; CHOICE fields are
 * `{ [Choice]: alternativeName, value }`.
 */
export function encode(
  schema: Schema,
  value: unknown,
  options: EncodeOptions = {},
): Uint8Array {
  const maxDepth = options.maxDepth ?? 256;
  if (!Number.isInteger(maxDepth) || maxDepth < 0) {
    throw new Asn1Error('maxDepth must be a non-negative integer');
  }
  return encodeValue(schema, value, [], 0, maxDepth, new Map());
}

/**
 * Decode DER bytes into a plain JS value according to `schema`.
 * Strict by default; see {@link DecodeOptions}.
 */
export function decode(
  schema: Schema,
  data: Uint8Array,
  options?: DecodeOptions,
): unknown {
  return decodeValueTop(schema, data, options);
}

export type {ChoiceValue as ChoiceValueType};
