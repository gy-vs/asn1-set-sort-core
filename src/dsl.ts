/**
 * Builder API for declaring schemas:
 *
 *   const schema = sequence([
 *     ['version', withDefault(integer(), 0n)],
 *     ['name',    utf8String()],
 *     ['flags',   setOf(oid())],
 *     ['mode',    implicit(integer(), 0)],
 *   ]);
 */
import {
  type ChoiceAlternative,
  type FieldDef,
  type HomogeneousSchema,
  type PrimitiveKind,
  type PrimitiveSchema,
  type Schema,
  type StructuredSchema,
  TagClass,
  UniversalTag,
} from './schema.js';
import {Asn1Error} from './errors.js';

function primitive(kind: PrimitiveKind): PrimitiveSchema {
  switch (kind) {
    case 'boolean':
      return {kind, tagClass: TagClass.Universal, tagNumber: UniversalTag.Boolean, constructed: false};
    case 'integer':
      return {kind, tagClass: TagClass.Universal, tagNumber: UniversalTag.Integer, constructed: false};
    case 'bitString':
      return {kind, tagClass: TagClass.Universal, tagNumber: UniversalTag.BitString, constructed: false};
    case 'octetString':
      return {kind, tagClass: TagClass.Universal, tagNumber: UniversalTag.OctetString, constructed: false};
    case 'null':
      return {kind, tagClass: TagClass.Universal, tagNumber: UniversalTag.Null, constructed: false};
    case 'oid':
      return {kind, tagClass: TagClass.Universal, tagNumber: UniversalTag.ObjectIdentifier, constructed: false};
    case 'utf8String':
      return {kind, tagClass: TagClass.Universal, tagNumber: UniversalTag.Utf8String, constructed: false};
  }
}

export const boolean = () => primitive('boolean');
export const integer = () => primitive('integer');
export const bitString = () => primitive('bitString');
export const octetString = () => primitive('octetString');
export const nullSchema = () => primitive('null');
export const oid = () => primitive('oid');
export const utf8String = () => primitive('utf8String');

/** Tag a schema IMPLICITLY: the underlying tag is replaced in place. */
export function implicit(
  schema: Schema,
  tagNumber: number,
  tagClass: Exclude<TagClass, typeof TagClass.Universal> = TagClass.Context,
): Schema {
  if (schema.kind === 'choice') {
    throw new Asn1Error(
      'IMPLICIT tagging cannot be applied to CHOICE; tag the alternatives or use EXPLICIT',
    );
  }
  if (!Number.isInteger(tagNumber) || tagNumber < 0) {
    throw new Asn1Error(`invalid implicit tag number ${String(tagNumber)}`);
  }
  return {...schema, tagClass, tagNumber};
}

/** Tag a schema EXPLICITLY: a constructed wrapper keeps the original TLV. */
export function explicit(
  inner: Schema,
  tagNumber: number,
  tagClass: Exclude<TagClass, typeof TagClass.Universal> = TagClass.Context,
): Schema {
  if (!Number.isInteger(tagNumber) || tagNumber < 0) {
    throw new Asn1Error(`invalid explicit tag number ${String(tagNumber)}`);
  }
  return {
    kind: 'explicitTag',
    inner,
    tagClass,
    tagNumber,
    constructed: true,
  };
}

/** Mark a schema OPTIONAL (as an alternative or a SET/SEQUENCE field). */
export function optional<T extends Schema>(schema: T): T {
  return {...schema, optional: true};
}

/** Attach a DEFAULT. The field becomes implicitly OPTIONAL. */
export function withDefault<T extends Schema>(schema: T, value: unknown): T {
  return {...schema, hasDefault: true, defaultValue: value, optional: true};
}

/* ---------------------- SEQUENCE / SET field lists ---------------------- */

export interface FieldSpec {
  schema: Schema;
  optional?: boolean;
}

export type FieldEntry =
  | readonly [name: string, schema: Schema]
  | readonly [name: string, schema: Schema, spec: {optional?: boolean}];

export type FieldsInput =
  | Record<string, Schema | FieldSpec>
  | readonly FieldEntry[];

function resolveFields(input: FieldsInput): FieldDef[] {
  const entries: Array<[string, Schema | FieldSpec]> = Array.isArray(input)
    ? input.map(([name, schema, spec]) => [
        name,
        spec ? {schema, ...spec} : schema,
      ])
    : Object.entries(input);

  return entries.map(([name, raw]) => {
    const spec: FieldSpec =
      'kind' in raw ? {schema: raw} : (raw as FieldSpec);
    return {
      name,
      schema: spec.schema,
      optional: spec.optional === true || spec.schema.optional === true,
    };
  });
}

/** All tags a value matching this schema might appear under on the wire. */
function wireTags(
  schema: Schema,
): Array<[TagClass, number, boolean]> {
  if (schema.kind === 'choice') {
    return schema.alternatives.flatMap((a) => wireTags(a.schema));
  }
  return [[schema.tagClass, schema.tagNumber, schema.constructed]];
}

function tagKey(t: [TagClass, number, boolean]): string {
  return `${t[0]}/${t[1]}/${t[2] ? 1 : 0}`;
}

function assertDistinctTags(
  tags: Map<string, string>,
  schema: Schema,
  label: string,
) {
  for (const t of wireTags(schema)) {
    const key = tagKey(t);
    const previous = tags.get(key);
    if (previous !== undefined) {
      throw new Asn1Error(
        `schema is ambiguous: ${previous} and ${label} both encode as tag ${t[0]}/${t[1]}`,
      );
    }
    tags.set(key, label);
  }
}

export function sequence(fields: FieldsInput): StructuredSchema {
  const defs = resolveFields(fields);
  assertSequenceTagDisambiguation(defs);
  return {
    kind: 'sequence',
    fields: defs,
    tagClass: TagClass.Universal,
    tagNumber: UniversalTag.Sequence,
    constructed: true,
  };
}

/**
 * X.680 (25.7): two fields with overlapping tag sets may only appear in a
 * SEQUENCE when every field up to and including the earlier one is always
 * present. Otherwise the decoder could not tell them apart once an optional
 * component is skipped. SET has no order, so its tags must be distinct.
 */
function assertSequenceTagDisambiguation(defs: FieldDef[]): void {
  for (let j = 0; j < defs.length; j++) {
    if (!defs[j].optional) continue; // required components anchor the cursor
    for (let i = j + 1; i < defs.length; i++) {
      if (tagsOverlap(defs[j].schema, defs[i].schema)) {
        throw new Asn1Error(
          `schema is ambiguous: field "${defs[i].name}" could be mistaken for optional/defaulted field "${defs[j].name}" (overlapping tags); give one an IMPLICIT tag`,
        );
      }
    }
  }
}

function tagsOverlap(a: Schema, b: Schema): boolean {
  const ta = new Set(wireTags(a).map(tagKey));
  return wireTags(b).some((t) => ta.has(tagKey(t)));
}

export function set(fields: FieldsInput): StructuredSchema {
  const defs = resolveFields(fields);
  const tags = new Map<string, string>();
  for (const f of defs) assertDistinctTags(tags, f.schema, `field "${f.name}"`);
  return {
    kind: 'set',
    fields: defs,
    tagClass: TagClass.Universal,
    tagNumber: UniversalTag.Set,
    constructed: true,
  };
}

export function sequenceOf(element: Schema): HomogeneousSchema {
  return {
    kind: 'sequenceOf',
    element,
    tagClass: TagClass.Universal,
    tagNumber: UniversalTag.Sequence,
    constructed: true,
  };
}

export function setOf(element: Schema): HomogeneousSchema {
  return {
    kind: 'setOf',
    element,
    tagClass: TagClass.Universal,
    tagNumber: UniversalTag.Set,
    constructed: true,
  };
}

export type ChoiceInput =
  | Record<string, Schema>
  | ReadonlyArray<Schema | ChoiceAlternative>;

export function choice(input: ChoiceInput): Schema {
  const alternatives: ChoiceAlternative[] = Array.isArray(input)
    ? input.map((entry) =>
        'kind' in entry ? {schema: entry} : entry,
      )
    : Object.entries(input).map(([name, schema]) => ({name, schema}));

  if (alternatives.length === 0) {
    throw new Asn1Error('CHOICE needs at least one alternative');
  }
  const tags = new Map<string, string>();
  alternatives.forEach((alt, i) =>
    assertDistinctTags(
      tags,
      alt.schema,
      `choice alternative "${alt.name ?? `#${i}`}"`,
    ),
  );
  return {
    kind: 'choice',
    alternatives,
    tagClass: TagClass.Universal,
    tagNumber: -1,
    constructed: false,
  };
}
