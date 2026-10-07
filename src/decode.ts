/**
 * Strict DER decoder.
 *
 * In strict mode (the default) every requirement of the unique DER encoding
 * is checked: definite minimal lengths, primitive/constructed bit, minimal
 * INTEGER contents, canonical BOOLEAN/NULL/BIT STRING/OID forms, SET and
 * SET OF component ordering, absence of DEFAULT-valued components, field
 * order in SEQUENCE, and no trailing octets anywhere.
 *
 * All bounds are derived from the real buffer; a length declaring far more
 * octets than exist fails before any allocation. Recursion depth is bounded
 * by `maxDepth`, so pathological nesting reports an error instead of
 * overflowing the call stack.
 */
import {Asn1Error, type PathStep} from './errors.js';
import {Choice, encodeValue, isChoiceValue} from './encode.js';
import {
  decodeBitStringContent,
  type BitStringValue,
  decodeBooleanContent,
  decodeIntegerContent,
  decodeOidContent,
  decodeUtf8Content,
} from './primitives.js';
import type {
  ExplicitTagSchema,
  Schema,
  StructuredSchema,
} from './schema.js';
import {compareTlv, parseHeader, type TlvHeader} from './tlv.js';

export interface DecodeOptions {
  /**
   * Reject anything that is not the unique DER form. Defaults to true.
   * When false, a small set of BER relaxations (non-canonical BOOLEAN,
   * INTEGER padding, nonzero unused BIT STRING bits, and SET / SEQUENCE
   * component order) is accepted; indefinite length and constructed
   * primitives remain unsupported.
   */
  strict?: boolean;
  /** Maximum nesting depth accepted. Defaults to 256. */
  maxDepth?: number;
}

interface Ctx {
  strict: boolean;
  maxDepth: number;
  buf: Uint8Array;
}

/** Decode the whole buffer as `schema`; trailing bytes are an error. */
export function decodeValueTop(
  schema: Schema,
  buf: Uint8Array,
  options: DecodeOptions = {},
): unknown {
  const ctx: Ctx = {
    strict: options.strict !== false,
    maxDepth: options.maxDepth ?? 256,
    buf,
  };
  if (!(buf instanceof Uint8Array)) {
    throw new Asn1Error('input must be a Uint8Array');
  }
  if (!Number.isInteger(ctx.maxDepth) || ctx.maxDepth < 0) {
    throw new Asn1Error('maxDepth must be a non-negative integer');
  }
  const path: PathStep[] = [];
  const header = parseHeader(buf, 0, buf.length, ctx.strict, path);
  const value = decodeBySchema(ctx, schema, 0, header, path, 0);
  if (header.contentEnd !== buf.length) {
    throw new Asn1Error(
      `trailing octets after the outer value: ${buf.length - header.contentEnd} byte(s)`,
      header.contentEnd,
      path,
    );
  }
  return value;
}

function tagMatches(header: TlvHeader, schema: Schema): boolean {
  if (schema.kind === 'choice') {
    return schema.alternatives.some((alt) => tagMatches(header, alt.schema));
  }
  return (
    header.tagClass === schema.tagClass &&
    header.tagNumber === schema.tagNumber &&
    header.constructed === schema.constructed
  );
}

const CLASS_NAMES = ['universal', 'application', 'context', 'private'] as const;

function describe(header: TlvHeader): string {
  return `tag [${CLASS_NAMES[header.tagClass]} ${header.tagNumber}]`;
}

function expectedTag(schema: Schema): string {
  if (schema.kind === 'choice') return 'one of its alternatives';
  return `[${CLASS_NAMES[schema.tagClass]} ${schema.tagNumber}]`;
}

function checkConstructed(
  header: TlvHeader,
  schema: Schema,
  path: PathStep[],
) {
  if (schema.kind === 'choice') return;
  if (header.constructed !== schema.constructed) {
    throw new Asn1Error(
      `non-DER: ${describe(header)} is ${header.constructed ? 'constructed' : 'primitive'} but the schema requires ${schema.constructed ? 'constructed' : 'primitive'}`,
      header.contentStart,
      path,
    );
  }
}

function decodeBySchema(
  ctx: Ctx,
  schema: Schema,
  tagOffset: number,
  header: TlvHeader,
  path: PathStep[],
  depth: number,
): unknown {
  if (depth > ctx.maxDepth) {
    throw new Asn1Error(
      `nesting depth ${depth} exceeds the limit of ${ctx.maxDepth}`,
      tagOffset,
      path,
    );
  }
  if (!tagMatches(header, schema)) {
    throw new Asn1Error(
      `unexpected ${describe(header)} (expected ${expectedTag(schema)})`,
      tagOffset,
      path,
    );
  }

  if (schema.kind === 'choice') {
    const index = schema.alternatives.findIndex((alt) =>
      tagMatches(header, alt.schema),
    );
    const alt = schema.alternatives[index];
    checkConstructed(header, alt.schema, path);
    const name = alt.name ?? `alt${index}`;
    const value = decodeBySchema(
      ctx,
      alt.schema,
      tagOffset,
      header,
      [...path, name],
      depth,
    );
    return {[Choice]: name, value};
  }

  checkConstructed(header, schema, path);

  switch (schema.kind) {
    case 'explicitTag':
      return decodeExplicit(ctx, schema, header, path, depth);
    case 'sequence':
    case 'set':
      return decodeStructured(ctx, schema, header, path, depth);
    case 'sequenceOf':
    case 'setOf':
      return decodeHomogeneous(ctx, schema, header, path, depth);
    default:
      return decodePrimitive(ctx, schema.kind, header, path);
  }
}

function decodeExplicit(
  ctx: Ctx,
  schema: ExplicitTagSchema,
  header: TlvHeader,
  path: PathStep[],
  depth: number,
): unknown {
  if (header.contentStart === header.contentEnd) {
    throw new Asn1Error('explicit tag wraps no inner value', header.contentStart, path);
  }
  const innerHeader = parseHeader(
    ctx.buf,
    header.contentStart,
    header.contentEnd,
    ctx.strict,
    path,
  );
  const value = decodeBySchema(
    ctx,
    schema.inner,
    header.contentStart,
    innerHeader,
    path,
    depth + 1,
  );
  if (innerHeader.contentEnd !== header.contentEnd) {
    throw new Asn1Error(
      `trailing octets inside explicitly tagged value: ${header.contentEnd - innerHeader.contentEnd} byte(s)`,
      innerHeader.contentEnd,
      path,
    );
  }
  return value;
}

interface ParsedComponent {
  header: TlvHeader;
  tagOffset: number;
  raw: Uint8Array;
}

function parseComponents(
  ctx: Ctx,
  header: TlvHeader,
  path: PathStep[],
): ParsedComponent[] {
  const components: ParsedComponent[] = [];
  let offset = header.contentStart;
  while (offset < header.contentEnd) {
    const componentStart = offset;
    const componentHeader = parseHeader(
      ctx.buf,
      offset,
      header.contentEnd,
      ctx.strict,
      path,
    );
    components.push({
      header: componentHeader,
      tagOffset: componentStart,
      raw: ctx.buf.subarray(componentStart, componentHeader.contentEnd),
    });
    offset = componentHeader.contentEnd;
  }
  return components;
}

function decodeStructured(
  ctx: Ctx,
  schema: StructuredSchema,
  header: TlvHeader,
  path: PathStep[],
  depth: number,
): Record<string, unknown> {
  const components = parseComponents(ctx, header, path);

  // SET: components must already appear in ascending DER order.
  if (schema.kind === 'set' && ctx.strict) assertSorted(components, path);

  const result: Record<string, unknown> = {};
  const usedFields = new Set<number>();
  let lastFieldIndex = -1;

  for (const component of components) {
    // SEQUENCE: search from after the cursor (fields are positional; several
    // may share a universal tag, e.g. validity has two times).
    // SET: search from the start but skip fields already consumed (a SET may
    // repeat the same universal type under different context tags).
    let fieldIndex = -1;
    const lower = schema.kind === 'sequence' ? lastFieldIndex + 1 : 0;
    for (let i = lower; i < schema.fields.length; i++) {
      if (!usedFields.has(i) && tagMatches(component.header, schema.fields[i].schema)) {
        fieldIndex = i;
        break;
      }
    }
    if (fieldIndex < 0) {
      throw new Asn1Error(
        `unexpected ${describe(component.header)} in ${schema.kind === 'set' ? 'SET' : 'SEQUENCE'}`,
        component.tagOffset,
        path,
      );
    }
    if (schema.kind === 'sequence') lastFieldIndex = fieldIndex;
    const field = schema.fields[fieldIndex];
    const fieldPath = [...path, field.name];

    const value = decodeBySchema(
      ctx,
      field.schema,
      component.tagOffset,
      component.header,
      fieldPath,
      depth + 1,
    );

    if (ctx.strict && field.schema.hasDefault) {
      const defaultTlv = encodeValue(
        field.schema,
        field.schema.defaultValue,
        fieldPath,
        depth + 2,
        ctx.maxDepth,
        new Map(),
      );
      if (bytesEqual(component.raw, defaultTlv)) {
        throw new Asn1Error(
          'non-DER: component equal to its DEFAULT must be omitted',
          component.tagOffset,
          fieldPath,
        );
      }
    }

    usedFields.add(fieldIndex);
    result[field.name] = value;
  }

  for (let i = 0; i < schema.fields.length; i++) {
    const field = schema.fields[i];
    if (!usedFields.has(i)) {
      if (field.schema.hasDefault) {
        result[field.name] = cloneDefault(field.schema.defaultValue);
      } else if (!field.optional) {
        throw new Asn1Error(
          `missing required field "${field.name}"`,
          header.contentEnd,
          path,
        );
      }
    }
  }
  return result;
}

function decodeHomogeneous(
  ctx: Ctx,
  schema: Extract<Schema, {kind: 'sequenceOf' | 'setOf'}>,
  header: TlvHeader,
  path: PathStep[],
  depth: number,
): unknown[] {
  const components = parseComponents(ctx, header, path);
  if (schema.kind === 'setOf' && ctx.strict) assertSorted(components, path);

  const result: unknown[] = new Array(components.length);
  for (let i = 0; i < components.length; i++) {
    const {header: componentHeader, tagOffset} = components[i];
    if (!tagMatches(componentHeader, schema.element)) {
      throw new Asn1Error(
        `unexpected ${describe(componentHeader)} in ${schema.kind === 'setOf' ? 'SET OF' : 'SEQUENCE OF'}`,
        tagOffset,
        [...path, i],
      );
    }
    result[i] = decodeBySchema(
      ctx,
      schema.element,
      tagOffset,
      componentHeader,
      [...path, i],
      depth + 1,
    );
  }
  return result;
}

function assertSorted(
  components: ParsedComponent[],
  path: PathStep[],
): void {
  for (let i = 1; i < components.length; i++) {
    if (compareTlv(components[i - 1].raw, components[i].raw) > 0) {
      throw new Asn1Error(
        'non-DER: SET/SET OF components are not in ascending encoded order',
        components[i].tagOffset,
        path,
      );
    }
  }
}

function decodePrimitive(
  ctx: Ctx,
  kind: Schema['kind'],
  header: TlvHeader,
  path: PathStep[],
): unknown {
  if (header.constructed) {
    throw new Asn1Error(
      `non-DER: ${kind} must use the primitive form`,
      header.contentStart,
      path,
    );
  }
  const content = ctx.buf.subarray(header.contentStart, header.contentEnd);
  const offset = header.contentStart;
  switch (kind) {
    case 'boolean':
      return decodeBooleanContent(content, ctx.strict, offset, path);
    case 'integer':
      return decodeIntegerContent(content, ctx.strict, offset, path);
    case 'bitString': {
      const v: BitStringValue = decodeBitStringContent(
        content,
        ctx.strict,
        offset,
        path,
      );
      return v;
    }
    case 'octetString':
      // Copy so callers cannot mutate (and alias) decoder input.
      return content.slice();
    case 'null':
      if (content.length !== 0) {
        throw new Asn1Error(
          `non-DER: NULL must have zero content octets, got ${content.length}`,
          offset,
          path,
        );
      }
      return null;
    case 'oid':
      return decodeOidContent(content, ctx.strict, offset, path);
    case 'utf8String':
      return decodeUtf8Content(content, offset, path);
    default:
      throw new Asn1Error(`not a primitive schema: ${kind}`);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function cloneDefault(value: unknown): unknown {
  if (value instanceof Uint8Array) return value.slice();
  if (Array.isArray(value)) return value.map(cloneDefault);
  if (value !== null && typeof value === 'object') {
    if (isChoiceValue(value)) {
      return {[Choice]: value[Choice], value: cloneDefault(value.value)};
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = cloneDefault(v);
    }
    return out;
  }
  return value;
}
