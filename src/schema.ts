/**
 * Declarative description of an ASN.1 value. Schemas are plain serializable
 * objects built with the helpers exported from the package entry point
 * (`integer`, `sequence`, `implicit`, ...) and never hold value data.
 */

/** ASN.1 tag classes (X.690 8.1.2). */
export const TagClass = {
  Universal: 0,
  Application: 1,
  Context: 2,
  Private: 3,
} as const;
export type TagClass = (typeof TagClass)[keyof typeof TagClass];

/** Well-known universal tag numbers (X.690 8.1.2, table 1). */
export const UniversalTag = {
  Boolean: 0x01,
  Integer: 0x02,
  BitString: 0x03,
  OctetString: 0x04,
  Null: 0x05,
  ObjectIdentifier: 0x06,
  Utf8String: 0x0c,
  Sequence: 0x10,
  Set: 0x11,
} as const;

/** Kind discriminator for the schema union. */
export type SchemaKind =
  | 'boolean'
  | 'integer'
  | 'bitString'
  | 'octetString'
  | 'null'
  | 'oid'
  | 'utf8String'
  | 'sequence'
  | 'set'
  | 'sequenceOf'
  | 'setOf'
  | 'choice'
  | 'explicitTag';

interface SchemaBase {
  kind: SchemaKind;
  /**
   * Effective tag used on the wire. Implicit tagging replaces the tag of the
   * underlying schema in place; explicit tagging wraps it and keeps it here.
   */
  tagClass: TagClass;
  tagNumber: number;
  /** Constructed bit of the effective tag. */
  constructed: boolean;
  /** Marks OPTIONAL fields (SEQUENCE/SET members and CHOICE members). */
  optional?: boolean;
  /** True for a field carrying a DEFAULT. */
  hasDefault?: boolean;
  /** DEFAULT in JS-value form, inserted when the field is absent. */
  defaultValue?: unknown;
}

export type PrimitiveKind =
  | 'boolean'
  | 'integer'
  | 'bitString'
  | 'octetString'
  | 'null'
  | 'oid'
  | 'utf8String';

export interface PrimitiveSchema extends SchemaBase {
  kind: PrimitiveKind;
}

export interface FieldDef {
  name: string;
  schema: Schema;
  optional: boolean;
}

/** SEQUENCE / SET: a fixed list of named fields. */
export interface StructuredSchema extends SchemaBase {
  kind: 'sequence' | 'set';
  fields: FieldDef[];
}

/** SEQUENCE OF / SET OF: every element follows the same schema. */
export interface HomogeneousSchema extends SchemaBase {
  kind: 'sequenceOf' | 'setOf';
  element: Schema;
}

export interface ChoiceAlternative {
  /** Optional name for diagnostics. */
  name?: string;
  schema: Schema;
}

export interface ChoiceSchema extends SchemaBase {
  kind: 'choice';
  alternatives: ChoiceAlternative[];
}

/** A schema wrapped in an explicit context/application/private tag. */
export interface ExplicitTagSchema extends SchemaBase {
  kind: 'explicitTag';
  inner: Schema;
}

export type Schema =
  | PrimitiveSchema
  | StructuredSchema
  | HomogeneousSchema
  | ChoiceSchema
  | ExplicitTagSchema;
