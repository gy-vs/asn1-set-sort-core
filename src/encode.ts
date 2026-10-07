/**
 * DER encoder. The output is the unique X.690 DER form:
 *  - definite minimal length octets, minimal INTEGER contents,
 *  - BOOLEAN 0x00/0xFF, zeroed unused BIT STRING bits,
 *  - SET / SET OF components sorted by their complete encoded octets,
 *  - fields equal to their DEFAULT are omitted.
 *
 * Recursion depth is bounded by the caller-supplied maximum (256 by
 * default) so a self-referential or deeply nested schema reports an error
 * instead of overflowing the call stack.
 */
import {Asn1Error, type PathStep} from './errors.js';
import {
  encodeBitStringContent,
  encodeBooleanContent,
  encodeIntegerContent,
  encodeOidContent,
  encodeUtf8Content,
} from './primitives.js';
import type {Schema} from './schema.js';
import {compareTlv, concat, wrapTlv} from './tlv.js';

type BitStringInput = {unused: number; data: Uint8Array};

/** Marker used as the key of a CHOICE value: `{ [Choice]: 'name', value }`. */
export const Choice = Symbol('ASN.1 CHOICE');

export type ChoiceValue = {
  [Choice]: string;
  value: unknown;
};

export function isChoiceValue(v: unknown): v is ChoiceValue {
  return (
    v !== null &&
    typeof v === 'object' &&
    typeof (v as ChoiceValue)[Choice] === 'string' &&
    'value' in (v as object)
  );
}

/** Encode a complete TLV for `value` described by `schema`. */
export function encodeValue(
  schema: Schema,
  value: unknown,
  path: readonly PathStep[],
  depth: number,
  maxDepth: number,
  defaultCache: Map<Schema, Uint8Array>,
): Uint8Array {
  if (depth > maxDepth) {
    throw new Asn1Error(
      `nesting depth ${depth} exceeds the limit of ${maxDepth}`,
      null,
      path,
    );
  }

  switch (schema.kind) {
    case 'boolean':
    case 'integer':
    case 'bitString':
    case 'octetString':
    case 'null':
    case 'oid':
    case 'utf8String':
      return wrapTlv(
        schema.tagClass,
        schema.constructed,
        schema.tagNumber,
        encodePrimitiveContent(schema.kind, value, path),
      );

    case 'sequenceOf':
    case 'setOf': {
      if (!Array.isArray(value)) {
        throw new Asn1Error(
          `${schema.kind === 'setOf' ? 'SET OF' : 'SEQUENCE OF'} value must be an array`,
          null,
          path,
        );
      }
      const elements = new Array<Uint8Array>(value.length);
      for (let i = 0; i < value.length; i++) {
        elements[i] = encodeValue(
          schema.element,
          value[i],
          [...path, i],
          depth + 1,
          maxDepth,
          defaultCache,
        );
      }
      if (schema.kind === 'setOf') elements.sort(compareTlv);
      return wrapTlv(
        schema.tagClass,
        true,
        schema.tagNumber,
        concat(elements),
      );
    }

    case 'sequence':
    case 'set': {
      if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Asn1Error(
          `${schema.kind === 'set' ? 'SET' : 'SEQUENCE'} value must be a plain object`,
          null,
          path,
        );
      }
      const obj = value as Record<string, unknown>;
      const components: Uint8Array[] = [];
      for (const field of schema.fields) {
        const present = Object.prototype.hasOwnProperty.call(obj, field.name);
        if (!present) {
          if (field.schema.hasDefault) continue;
          if (field.optional) continue;
          throw new Asn1Error(
            `missing required field "${field.name}"`,
            null,
            path,
          );
        }
        const fieldValue = obj[field.name];
        if (fieldValue === undefined) {
          if (field.schema.hasDefault || field.optional) continue;
          throw new Asn1Error(
            `required field "${field.name}" is undefined`,
            null,
            path,
          );
        }
        const encoded = encodeValue(
          field.schema,
          fieldValue,
          [...path, field.name],
          depth + 1,
          maxDepth,
          defaultCache,
        );
        if (field.schema.hasDefault) {
          let def = defaultCache.get(field.schema);
          if (!def) {
            def = encodeValue(
              field.schema,
              field.schema.defaultValue,
              [...path, field.name],
              depth + 1,
              maxDepth,
              defaultCache,
            );
            defaultCache.set(field.schema, def);
          }
          if (bytesEqual(encoded, def)) continue; // equal to DEFAULT: absent
        }
        components.push(encoded);
      }
      if (schema.kind === 'set') components.sort(compareTlv);
      return wrapTlv(schema.tagClass, true, schema.tagNumber, concat(components));
    }

    case 'explicitTag': {
      const inner = encodeValue(
        schema.inner,
        value,
        path,
        depth + 1,
        maxDepth,
        defaultCache,
      );
      return wrapTlv(schema.tagClass, true, schema.tagNumber, inner);
    }

    case 'choice':
      return encodeChoice(schema, value, path, depth, maxDepth, defaultCache);
  }
}

function encodeChoice(
  schema: Extract<Schema, {kind: 'choice'}>,
  value: unknown,
  path: readonly PathStep[],
  depth: number,
  maxDepth: number,
  defaultCache: Map<Schema, Uint8Array>,
): Uint8Array {
  if (!isChoiceValue(value)) {
    throw new Asn1Error(
      `CHOICE value must be { [Choice]: alternativeName, value }`,
      null,
      path,
    );
  }
  const index = schema.alternatives.findIndex(
    (alt) => alt.name === value[Choice],
  );
  if (index < 0) {
    throw new Asn1Error(
      `CHOICE has no alternative named "${value[Choice]}"`,
      null,
      path,
    );
  }
  return encodeValue(
    schema.alternatives[index].schema,
    value.value,
    [...path, value[Choice]],
    depth + 1,
    maxDepth,
    defaultCache,
  );
}

function encodePrimitiveContent(
  kind: Schema['kind'],
  value: unknown,
  path: readonly PathStep[],
): Uint8Array {
  try {
    switch (kind) {
      case 'boolean':
        if (typeof value !== 'boolean') {
          throw new Asn1Error(`BOOLEAN value must be a boolean, got ${typeof value}`);
        }
        return encodeBooleanContent(value);
      case 'integer':
        return encodeIntegerContent(value as bigint);
      case 'bitString':
        return encodeBitStringContent(value as BitStringInput);
      case 'octetString':
        if (!(value instanceof Uint8Array)) {
          throw new Asn1Error(`OCTET STRING value must be a Uint8Array, got ${typeof value}`);
        }
        return value;
      case 'null':
        if (value !== null) {
          throw new Asn1Error('NULL value must be null');
        }
        return new Uint8Array(0);
      case 'oid':
        return encodeOidContent(value as string | ReadonlyArray<number | bigint>);
      case 'utf8String':
        return encodeUtf8Content(value as string);
      default:
        throw new Asn1Error(`not a primitive schema: ${kind}`);
    }
  } catch (err) {
    if (err instanceof Asn1Error && err.path.length === 0) {
      throw new Asn1Error(err.message, null, path);
    }
    throw err;
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
