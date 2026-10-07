import { CodingContext, DEFAULT_MAX_DEPTH } from './context.js';
import { DERError } from './errors.js';
export { DERError } from './errors.js';
import {
  ByteReader,
  ByteWriter,
  CLASS_CONTEXT,
  CLASS_UNIVERSAL,
  TAG_BIT_STRING,
  TAG_BOOLEAN,
  TAG_INTEGER,
  TAG_NULL,
  TAG_OCTET_STRING,
  TAG_OID,
  TAG_SEQUENCE,
  TAG_SET,
  TAG_UTF8_STRING,
  Tag,
  TlvHeader,
  compareBytes,
  integerBytes,
  oidBytes,
  readIntegerContent,
  readOidContent,
  sameTag,
  sortByteArrays,
  tagText,
} from './bytes.js';

// ===========================================================================
// Public value types
// ===========================================================================

/** BIT STRING: content octets plus the count of trailing unused bits (0..7). */
export class BitString {
  readonly bytes: Uint8Array;
  readonly unusedBits: number;

  constructor(bytes: Uint8Array, unusedBits = 0) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError('BitString bytes must be Uint8Array');
    if (!Number.isInteger(unusedBits) || unusedBits < 0 || unusedBits > 7) {
      throw new RangeError('BitString unusedBits must be an integer 0..7');
    }
    if (bytes.length === 0 && unusedBits !== 0) {
      throw new RangeError('an empty BIT STRING must have zero unused bits');
    }
    this.bytes = bytes;
    this.unusedBits = unusedBits;
  }
}

/**
 * Runtime value of a decoded CHOICE (and an accepted shape for encoding).
 * `name` is the selected alternative's name in the schema. Encoding also
 * accepts a single-key object `{ [name]: value }`.
 */
export class Choice {
  readonly name: string;
  readonly value: unknown;

  constructor(name: string, value: unknown) {
    this.name = name;
    this.value = value;
  }
}

// ===========================================================================
// Options
// ===========================================================================

export interface EncodeOptions {
  /** Reject structures nested deeper than this many TLVs (default 512). */
  maxDepth?: number;
}

export interface DecodeOptions {
  /**
   * Enforce the unique DER encoding: definite minimal lengths, minimal
   * INTEGERs/tags, sorted SET/SET OF, no explicit DEFAULT fields, no trailing
   * bytes, etc. Defaults to `true`.
   */
  strict?: boolean;
  /** Reject structures nested deeper than this many TLVs (default 512). */
  maxDepth?: number;
}

// ===========================================================================
// Schema type hierarchy
// ===========================================================================

/** A named field as given to `sequence` / `set` / `choice`. */
export type FieldDef = readonly [name: string, type: AsnType];

export abstract class AsnType {
  /** False for the fixed-primitive types; true for everything constructed. */
  abstract readonly primitive: boolean;
  /** Universal tag number, or undefined for tag-indeterminate wrappers. */
  abstract readonly universal: number | undefined;

  /** Tag carried by a complete top-level TLV of this type. */
  abstract outerTag(): Tag;

  /** Write the content octets (head is emitted by the caller). */
  abstract writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void;

  /** Read content octets `[start, end)` of an already tag-matched TLV. */
  abstract readContent(
    r: ByteReader,
    start: number,
    end: number,
    ctx: CodingContext,
    observed?: Tag,
  ): unknown;

  /** Encode a complete TLV. One physical TLV ⇒ one depth level. */
  writeTo(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    ctx.enter();
    try {
      const cw = new ByteWriter();
      this.writeContent(cw, value, ctx);
      w.writeHead(this.outerTag(), cw.length);
      w.writer(cw);
    } finally {
      ctx.leave();
    }
  }

  optional(): OptionalType {
    return new OptionalType(this);
  }

  default(value: unknown): DefaultType {
    return new DefaultType(this, value);
  }

  /** Context-specific IMPLICIT tag (X.680 clause 31). */
  implicit(tagNumber: number): ImplicitType {
    return new ImplicitType(this, tagNumber);
  }

  /** Context-specific EXPLICIT tag (X.680 clause 31). */
  explicit(tagNumber: number): ExplicitType {
    return new ExplicitType(this, tagNumber);
  }
}

// ---------------------------------------------------------------------------
// Transparent modifiers (add no TLV of their own)
// ---------------------------------------------------------------------------

export class OptionalType extends AsnType {
  readonly inner: AsnType;

  constructor(inner: AsnType) {
    super();
    this.inner = inner;
  }

  get primitive(): boolean {
    return this.inner.primitive;
  }

  get universal(): number | undefined {
    return this.inner.universal;
  }

  outerTag(): Tag {
    return this.inner.outerTag();
  }

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    this.inner.writeContent(w, value, ctx);
  }

  writeTo(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    this.inner.writeTo(w, value, ctx);
  }

  readContent(r: ByteReader, start: number, end: number, ctx: CodingContext, observed?: Tag): unknown {
    return this.inner.readContent(r, start, end, ctx, observed);
  }
}

export class DefaultType extends AsnType {
  readonly inner: AsnType;
  readonly def: unknown;

  constructor(inner: AsnType, def: unknown) {
    super();
    this.inner = inner;
    this.def = def;
  }

  get primitive(): boolean {
    return this.inner.primitive;
  }

  get universal(): number | undefined {
    return this.inner.universal;
  }

  outerTag(): Tag {
    return this.inner.outerTag();
  }

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    this.inner.writeContent(w, value, ctx);
  }

  writeTo(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    this.inner.writeTo(w, value, ctx);
  }

  readContent(r: ByteReader, start: number, end: number, ctx: CodingContext, observed?: Tag): unknown {
    return this.inner.readContent(r, start, end, ctx, observed);
  }
}

/** Strip OPTIONAL / DEFAULT / LAZY wrappers; they carry no encoding of their own. */
function transparentBase(t: AsnType): AsnType {
  let x = t;
  while (x instanceof OptionalType || x instanceof DefaultType || x instanceof LazyType) {
    x = x instanceof LazyType ? x.resolve() : x.inner;
  }
  return x;
}

// ---------------------------------------------------------------------------
// Explicit tagging: a constructed context TLV wrapping the original encoding
// ---------------------------------------------------------------------------

export class ExplicitType extends AsnType {
  readonly inner: AsnType;
  readonly tagNumber: number;
  readonly primitive = false;

  constructor(inner: AsnType, tagNumber: number) {
    super();
    this.inner = inner;
    this.tagNumber = tagNumber;
  }

  get universal(): number | undefined {
    return undefined;
  }

  outerTag(): Tag {
    return { cls: CLASS_CONTEXT, constructed: true, number: this.tagNumber };
  }

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    // The wrapped value is one nested physical TLV (possibly CHOICE → one TLV).
    this.inner.writeTo(w, value, ctx);
  }

  readContent(r: ByteReader, start: number, end: number, ctx: CodingContext): unknown {
    const inner = new ByteReader(r.data, r.strict, r.path, start, end);
    const value = readAny(this.inner, inner, ctx);
    if (inner.pos !== end) {
      r.fail('trailing bytes inside explicitly tagged value', inner.pos);
    }
    return value;
  }
}

// ---------------------------------------------------------------------------
// Implicit tagging: replaces the tag of the underlying TLV
// ---------------------------------------------------------------------------

export class ImplicitType extends AsnType {
  readonly inner: AsnType;
  readonly tagNumber: number;

  constructor(inner: AsnType, tagNumber: number) {
    super();
    this.inner = inner;
    this.tagNumber = tagNumber;
  }

  get primitive(): boolean {
    return this.inner.primitive;
  }

  get universal(): number | undefined {
    return undefined;
  }

  outerTag(): Tag {
    const base = transparentBase(this.inner);
    if (base instanceof ChoiceType) {
      // Tag-indeterminate: the context tag propagates to whichever
      // alternative is selected; handled specially in read/write.
      throw new DERError('IMPLICIT tag on a CHOICE has no fixed outer tag', null, '$');
    }
    return {
      cls: CLASS_CONTEXT,
      constructed: base instanceof ExplicitType || !base.primitive,
      number: this.tagNumber,
    };
  }

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    // Content octets of the implicit TLV: the inner type's content.
    emitImplicitContent(transparentBase(this.inner), this.tagNumber, w, value, ctx);
  }

  writeTo(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    ctx.enter();
    try {
      const base = transparentBase(this.inner);
      if (base instanceof ChoiceType) {
        // Tag-indeterminate: the propagated tag wraps the selected alternative's
        // complete TLV; it is emitted by the helper directly.
        emitImplicitContent(base, this.tagNumber, w, value, ctx);
        return;
      }
      const cw = new ByteWriter();
      emitImplicitContent(base, this.tagNumber, cw, value, ctx);
      w.writeHead(this.outerTag(), cw.length);
      w.writer(cw);
    } finally {
      ctx.leave();
    }
  }

  readContent(r: ByteReader, start: number, end: number, ctx: CodingContext, observed?: Tag): unknown {
    return readRetaggedContent(transparentBase(this.inner), this.tagNumber, r, start, end, ctx, observed);
  }
}

/**
 * Write the content octets of an implicit-context tag. For ordinary types
 * this is just their normal content; for a CHOICE (tag-indeterminate) the
 * "content" is in fact the selected alternative's fully retagged TLV.
 */
function emitImplicitContent(
  type: AsnType,
  tagNumber: number,
  w: ByteWriter,
  value: unknown,
  ctx: CodingContext,
): void {
  if (type instanceof ChoiceType) {
    writeRetaggedContent(type, tagNumber, w, value, ctx);
    return;
  }
  if (type instanceof ExplicitType) {
    // IMPLICIT outside EXPLICIT: the wrapper is replaced, so the inner TLV is
    // what becomes this TLV's content.
    type.inner.writeTo(w, value, ctx);
    return;
  }
  type.writeContent(w, value, ctx);
}

/**
 * Write content for a single physical TLV whose universal tag is replaced by
 * context tag `tagNumber`. Works through CHOICE and chained tagging. The
 * physical TLV depth is counted by the caller.
 */
function writeRetaggedContent(
  type: AsnType,
  tagNumber: number,
  w: ByteWriter,
  value: unknown,
  ctx: CodingContext,
): void {
  if (type instanceof ChoiceType) {
    const { name, inner, v } = selectChoice(type, value, ctx);
    ctx.path.field(name);
    writeRetaggedContent(transparentBase(inner), tagNumber, w, v, ctx);
    ctx.path.pop();
    return;
  }
  if (type instanceof ImplicitType) {
    // Propagated IMPLICIT keeps one physical TLV; reuse the same context tag.
    writeRetaggedContent(transparentBase(type.inner), tagNumber, w, value, ctx);
    return;
  }
  const cw = new ByteWriter();
  let constructed: boolean;
  if (type instanceof ExplicitType) {
    // IMPLICIT outside EXPLICIT replaces the wrapper tag; inner TLV is content.
    type.inner.writeTo(cw, value, ctx);
    constructed = true;
  } else {
    type.writeContent(cw, value, ctx);
    constructed = !type.primitive;
  }
  w.writeHead({ cls: CLASS_CONTEXT, constructed, number: tagNumber }, cw.length);
  w.writer(cw);
}

function readRetaggedContent(
  type: AsnType,
  tagNumber: number,
  r: ByteReader,
  start: number,
  end: number,
  ctx: CodingContext,
  observed?: Tag,
): unknown {
  if (type instanceof ChoiceType) {
    if (!observed) {
      throw new DERError('internal: implicit CHOICE needs observed tag', null, ctx.path.text);
    }
    return readRetaggedChoice(type, tagNumber, r, start, end, ctx, observed);
  }
  if (type instanceof ImplicitType) {
    return readRetaggedContent(transparentBase(type.inner), tagNumber, r, start, end, ctx, observed);
  }
  if (type instanceof ExplicitType) {
    const inner = new ByteReader(r.data, r.strict, r.path, start, end);
    return readAny(type.inner, inner, ctx);
  }
  return type.readContent(r, start, end, ctx, observed);
}

function readRetaggedChoice(
  choice: ChoiceType,
  tagNumber: number,
  r: ByteReader,
  start: number,
  end: number,
  ctx: CodingContext,
  observed: Tag,
): unknown {
  // The single outer TLV carries the propagated context tag. Collect
  // alternatives compatible with its constructed bit; a well-formed schema
  // keeps exactly one such alternative.
  if (observed.cls !== CLASS_CONTEXT || observed.number !== tagNumber) {
    r.fail(
      `expected context tag [${tagNumber}] on implicit CHOICE but found ${tagText(observed)}`,
      start,
    );
  }

  const candidates: { name: string; base: AsnType }[] = [];
  for (const alt of choice.alternatives) {
    const base = transparentBase(alt.type);
    if (base instanceof ChoiceType || base instanceof ImplicitType) continue;
    if (base instanceof ExplicitType) {
      if (observed.constructed) candidates.push({ name: alt.name, base });
    } else if (observed.constructed !== base.primitive) {
      candidates.push({ name: alt.name, base });
    }
  }

  if (candidates.length === 0) {
    r.fail('no CHOICE alternative matches the implicitly tagged element', start);
  }

  let lastError: unknown;
  const successes: { name: string; value: unknown }[] = [];
  for (const { name: altName, base } of candidates) {
    ctx.path.field(altName);
    try {
      let val: unknown;
      if (base instanceof ExplicitType) {
        const inner = new ByteReader(r.data, r.strict, r.path, start, end);
        val = readAny(base.inner, inner, ctx);
      } else {
        val = base.readContent(r, start, end, ctx);
      }
      ctx.path.pop();
      successes.push({ name: altName, value: val });
    } catch (e) {
      ctx.path.pop();
      lastError = e;
      if (!(e instanceof DERError)) throw e;
    }
  }
  if (successes.length === 1) {
    return new Choice(successes[0].name, successes[0].value);
  }
  if (successes.length > 1) {
    r.fail(
      `ambiguous implicit CHOICE: alternatives ${successes
        .map((s) => `"${s.name}"`)
        .join(', ')} all match tag [${tagNumber}]`,
      start,
    );
  }
  if (lastError) throw lastError;
  r.fail('no CHOICE alternative matches the implicitly tagged element', start);
}

// ---------------------------------------------------------------------------
// Primitive types
// ---------------------------------------------------------------------------

abstract class PrimitiveType extends AsnType {
  abstract readonly tagNumber: number;
  readonly primitive = true;

  get universal(): number {
    return this.tagNumber;
  }

  outerTag(): Tag {
    return { cls: CLASS_UNIVERSAL, constructed: false, number: this.tagNumber };
  }
}

class BooleanType extends PrimitiveType {
  readonly tagNumber = TAG_BOOLEAN;

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    if (typeof value !== 'boolean') throw typeError('BOOLEAN', value, ctx);
    w.byte(value ? 0xff : 0x00);
  }

  readContent(r: ByteReader, start: number, end: number): boolean {
    if (end - start !== 1) r.fail('BOOLEAN content must be exactly one octet', start);
    const b = r.data[start];
    if (r.strict && b !== 0x00 && b !== 0xff) {
      r.fail('non-DER BOOLEAN: value octet must be 0x00 or 0xff', start);
    }
    return b !== 0x00;
  }
}

class IntegerType extends PrimitiveType {
  readonly tagNumber = TAG_INTEGER;

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    if (typeof value !== 'bigint') throw typeError('INTEGER', value, ctx);
    w.bytes(integerBytes(value, ctx.path));
  }

  readContent(r: ByteReader, start: number, end: number): bigint {
    return readIntegerContent(r, start, end);
  }
}

class NullType extends PrimitiveType {
  readonly tagNumber = TAG_NULL;

  writeContent(w: ByteWriter): void {
    void w;
  }

  readContent(r: ByteReader, start: number, end: number): null {
    if (end - start !== 0) r.fail('NULL content must be empty', start);
    return null;
  }
}

class OctetStringType extends PrimitiveType {
  readonly tagNumber = TAG_OCTET_STRING;

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    w.bytes(asBytes('OCTET STRING', value, ctx));
  }

  readContent(r: ByteReader, start: number, end: number): Uint8Array {
    return r.data.slice(start, end);
  }
}

class BitStringType extends PrimitiveType {
  readonly tagNumber = TAG_BIT_STRING;

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    if (!(value instanceof BitString)) throw typeError('BIT STRING', value, ctx);
    if (value.bytes.length && value.unusedBits !== 0) {
      const last = value.bytes[value.bytes.length - 1];
      if (last & ((1 << value.unusedBits) - 1)) {
        throw new DERError('BIT STRING: unused bits must be zero', null, ctx.path.text);
      }
    }
    w.byte(value.unusedBits);
    w.bytes(value.bytes);
  }

  readContent(r: ByteReader, start: number, end: number): BitString {
    if (end - start < 1) {
      r.fail('BIT STRING content must start with an unused-bits octet', start);
    }
    const unused = r.data[start];
    if (unused > 7) r.fail(`BIT STRING invalid unused bits count ${unused}`, start);
    const dataLen = end - start - 1;
    if (dataLen === 0 && unused !== 0) {
      r.fail('BIT STRING with zero content octets must have zero unused bits', start);
    }
    if (r.strict && dataLen > 0 && unused !== 0) {
      const last = r.data[end - 1];
      if (last & ((1 << unused) - 1)) {
        r.fail('non-DER BIT STRING: unused bits are not all zero', end - 1);
      }
    }
    return new BitString(r.data.slice(start + 1, end), unused);
  }
}

class OidType extends PrimitiveType {
  readonly tagNumber = TAG_OID;

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    if (typeof value !== 'string') throw typeError('OBJECT IDENTIFIER', value, ctx);
    w.bytes(oidBytes(value, ctx.path));
  }

  readContent(r: ByteReader, start: number, end: number): string {
    return readOidContent(r, start, end);
  }
}

const strictUtf8Decoder = new TextDecoder('utf-8', { fatal: true });
const utf8Encoder = new TextEncoder();

class Utf8StringType extends PrimitiveType {
  readonly tagNumber = TAG_UTF8_STRING;

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    if (typeof value !== 'string') throw typeError('UTF8String', value, ctx);
    w.bytes(utf8Encoder.encode(value));
  }

  readContent(r: ByteReader, start: number, end: number): string {
    const bytes = r.data.subarray(start, end);
    if (r.strict) {
      let decoded: string;
      try {
        decoded = strictUtf8Decoder.decode(bytes);
      } catch {
        r.fail('invalid UTF-8 in UTF8String', start);
      }
      // Re-encode and compare: rejects overlong/non-shortest encodings.
      const round = utf8Encoder.encode(decoded);
      if (round.length !== bytes.length) r.fail('non-DER UTF8String: not minimal UTF-8', start);
      for (let i = 0; i < round.length; i++) {
        if (round[i] !== bytes[i]) r.fail('non-DER UTF8String: not minimal UTF-8', start);
      }
      return decoded;
    }
    return new TextDecoder('utf-8').decode(bytes);
  }
}

// ---------------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------------

export class CollectionOfType extends AsnType {
  readonly element: AsnType;
  readonly tagNumber: number;
  readonly ordered: boolean;
  readonly primitive = false;

  constructor(element: AsnType, tagNumber: number, ordered: boolean) {
    super();
    this.element = element;
    this.tagNumber = tagNumber;
    this.ordered = ordered;
  }

  get universal(): number {
    return this.tagNumber;
  }

  outerTag(): Tag {
    return { cls: CLASS_UNIVERSAL, constructed: true, number: this.tagNumber };
  }

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    if (!Array.isArray(value)) {
      throw typeError(this.ordered ? 'SET OF' : 'SEQUENCE OF', value, ctx);
    }
    const encoded: Uint8Array[] = new Array(value.length);
    for (let i = 0; i < value.length; i++) {
      ctx.path.index(i);
      const cw = new ByteWriter();
      this.element.writeTo(cw, value[i], ctx); // child TLV: +1 depth
      encoded[i] = cw.toUint8Array();
      ctx.path.pop();
    }
    if (this.ordered) sortByteArrays(encoded);
    for (const b of encoded) w.bytes(b);
  }

  readContent(r: ByteReader, start: number, end: number, ctx: CodingContext): unknown[] {
    const children = parseChildren(r, start, end);
    if (r.strict && this.ordered) checkSorted(r, children, 'SET OF', ctx);
    const out: unknown[] = new Array(children.length);
    for (let i = 0; i < children.length; i++) {
      const h = children[i];
      ctx.path.index(i);
      const cr = new ByteReader(r.data, r.strict, r.path, h.tlvStart, h.contentEnd);
      out[i] = readAny(this.element, cr, ctx); // child TLV: +1 depth
      if (cr.pos !== h.contentEnd) r.fail('trailing bytes inside collection element', cr.pos);
      ctx.path.pop();
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// SEQUENCE / SET of named fields
// ---------------------------------------------------------------------------

interface FieldEntry {
  name: string;
  type: AsnType;
}

export class SequenceOrSetType extends AsnType {
  readonly fields: FieldEntry[];
  readonly tagNumber: number;
  readonly isSet: boolean;
  readonly primitive = false;

  constructor(fields: FieldDef[], tagNumber: number, isSet: boolean) {
    super();
    const seen = new Set<string>();
    this.fields = fields.map(([name, type]) => {
      if (seen.has(name)) throw new Error(`duplicate field name "${name}" in schema`);
      seen.add(name);
      return { name, type };
    });
    this.tagNumber = tagNumber;
    this.isSet = isSet;
  }

  get universal(): number {
    return this.tagNumber;
  }

  outerTag(): Tag {
    return { cls: CLASS_UNIVERSAL, constructed: true, number: this.tagNumber };
  }

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    if (typeof value !== 'object' || value === null || Array.isArray(value) || value instanceof Choice) {
      throw typeError(this.isSet ? 'SET' : 'SEQUENCE', value, ctx);
    }
    const obj = value as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      if (!this.fields.some((f) => f.name === key)) {
        throw new DERError(
          `unknown field "${key}" for ${this.isSet ? 'SET' : 'SEQUENCE'}`,
          null,
          ctx.path.text,
        );
      }
    }

    const encoded: { name: string; bytes: Uint8Array }[] = [];
    for (const f of this.fields) {
      let type = f.type;
      let omitted = false;

      if (type instanceof DefaultType) {
        const def = type.def;
        type = type.inner;
        if (!(f.name in obj) || obj[f.name] === undefined || deepEqual(obj[f.name], def)) {
          omitted = true;
        }
      }
      if (!omitted && type instanceof OptionalType) {
        type = type.inner;
        if (!(f.name in obj) || obj[f.name] === undefined) omitted = true;
      }
      if (omitted) continue;

      if (!(f.name in obj) || obj[f.name] === undefined) {
        throw new DERError(`missing required field "${f.name}"`, null, ctx.path.text);
      }

      ctx.path.field(f.name);
      const cw = new ByteWriter();
      type.writeTo(cw, obj[f.name], ctx); // field TLV: +1 depth
      ctx.path.pop();
      encoded.push({ name: f.name, bytes: cw.toUint8Array() });
    }

    if (this.isSet) encoded.sort((a, b) => compareBytes(a.bytes, b.bytes));
    for (const e of encoded) w.bytes(e.bytes);
  }

  readContent(
    r: ByteReader,
    start: number,
    end: number,
    ctx: CodingContext,
  ): Record<string, unknown> {
    const children = parseChildren(r, start, end);
    if (r.strict && this.isSet) checkSorted(r, children, 'SET', ctx);

    const used = new Set<number>();
    const result: Record<string, unknown> = {};
    let seqOrdinal = -1;

    for (const ch of children) {
      let found = -1;
      for (let fi = 0; fi < this.fields.length; fi++) {
        if (used.has(fi)) continue;
        if (!this.isSet && r.strict && fi <= seqOrdinal) continue;
        if (matchesField(this.fields[fi].type, ch.tag)) {
          found = fi;
          break;
        }
      }

      if (found < 0) {
        if (r.strict) {
          // In SEQUENCE (strict) the wire order follows the declaration, so
          // report the mismatch against the next expected field with its path.
          if (!this.isSet) {
            let expectFi = seqOrdinal + 1;
            while (expectFi < this.fields.length && used.has(expectFi)) expectFi++;
            if (expectFi < this.fields.length) {
              const ef = this.fields[expectFi];
              ctx.path.field(ef.name);
              r.fail(
                `expected ${describeExpected(transparentBase(ef.type))} for field "${
                  ef.name
                }" but found ${tagText(ch.tag)}`,
                ch.tlvStart,
              );
            }
          }
          r.fail(
            `unexpected ${tagText(ch.tag)} in ${this.isSet ? 'SET' : 'SEQUENCE'}: no matching field`,
            ch.tlvStart,
          );
        }
        continue; // lenient mode: skip unknown elements
      }

      used.add(found);
      if (!this.isSet) seqOrdinal = found;
      const f = this.fields[found];

      ctx.path.field(f.name);
      const cr = new ByteReader(r.data, r.strict, r.path, ch.tlvStart, ch.contentEnd);
      const val = readAny(transparentBase(f.type), cr, ctx); // field TLV: +1 depth
      if (cr.pos !== ch.contentEnd) r.fail('trailing bytes after field value', cr.pos);
      ctx.path.pop();

      if (r.strict && f.type instanceof DefaultType && deepEqual(val, f.type.def)) {
        r.fail('non-DER encoding: field equal to its DEFAULT was written explicitly', ch.tlvStart);
      }
      result[f.name] = val;
    }

    for (let fi = 0; fi < this.fields.length; fi++) {
      if (used.has(fi)) continue;
      const f = this.fields[fi];
      if (f.type instanceof DefaultType) {
        result[f.name] = f.type.def;
      } else if (f.type instanceof OptionalType) {
        // absent OPTIONAL: key omitted from result
      } else {
        r.fail(`missing required field "${f.name}"`, end);
      }
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------------

/**
 * Deferred schema reference for recursive types. The supplier is called on
 * first use, so the referenced node may be declared afterwards.
 *
 * ```ts
 * type Node = ...;
 * const node = choice([['leaf', integer], ['children', sequenceOf(lazy(() => node))]]);
 * ```
 */
export class LazyType extends AsnType {
  private supplier: () => AsnType;
  private cached: AsnType | undefined;

  constructor(supplier: () => AsnType) {
    super();
    this.supplier = supplier;
  }

  private get target(): AsnType {
    if (!this.cached) this.cached = this.supplier();
    return this.cached;
  }

  /** Resolve the deferred node (used by the codec's transparentBase). */
  resolve(): AsnType {
    return this.target;
  }

  get primitive(): boolean {
    return this.target.primitive;
  }

  get universal(): number | undefined {
    return this.target.universal;
  }

  outerTag(): Tag {
    return this.target.outerTag();
  }

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    this.target.writeContent(w, value, ctx);
  }

  writeTo(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    this.target.writeTo(w, value, ctx);
  }

  readContent(r: ByteReader, start: number, end: number, ctx: CodingContext, observed?: Tag): unknown {
    return this.target.readContent(r, start, end, ctx, observed);
  }
}

export class ChoiceType extends AsnType {
  readonly alternatives: FieldEntry[];

  constructor(alts: FieldDef[]) {
    super();
    const seen = new Set<string>();
    this.alternatives = alts.map(([name, type]) => {
      if (seen.has(name)) throw new Error(`duplicate CHOICE alternative "${name}"`);
      seen.add(name);
      return { name, type };
    });
  }

  get primitive(): boolean {
    return false;
  }

  get universal(): number | undefined {
    return undefined;
  }

  outerTag(): Tag {
    throw new DERError('CHOICE has no fixed outer tag', null, '$');
  }

  /** CHOICE is tag-indeterminate: it emits exactly the selected TLV, no more. */
  writeTo(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    this.writeContent(w, value, ctx);
  }

  writeContent(w: ByteWriter, value: unknown, ctx: CodingContext): void {
    const { name, inner, v } = selectChoice(this, value, ctx);
    ctx.path.field(name);
    inner.writeTo(w, v, ctx); // selected TLV carries the depth count
    ctx.path.pop();
  }

  readContent(): unknown {
    throw new DERError('internal: CHOICE is resolved in readAny', null);
  }
}

function selectChoice(
  choice: ChoiceType,
  value: unknown,
  ctx: CodingContext,
): { name: string; inner: AsnType; v: unknown } {
  let name: string;
  let v: unknown;
  if (value instanceof Choice) {
    name = value.name;
    v = value.value;
  } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const keys = Object.keys(value as object);
    if (keys.length !== 1) {
      throw new DERError('CHOICE value must be a Choice or a single-key object', null, ctx.path.text);
    }
    name = keys[0];
    v = (value as Record<string, unknown>)[name];
  } else {
    throw typeError('CHOICE', value, ctx);
  }
  const alt = choice.alternatives.find((a) => a.name === name);
  if (!alt) throw new DERError(`unknown CHOICE alternative "${name}"`, null, ctx.path.text);
  return { name, inner: alt.type, v };
}

// ===========================================================================
// Decoding driver
// ===========================================================================

function parseChildren(r: ByteReader, start: number, end: number): TlvHeader[] {
  const out: TlvHeader[] = [];
  const cr = new ByteReader(r.data, r.strict, r.path, start, end);
  while (cr.pos < end) {
    const h = cr.peek(cr.pos);
    out.push(h);
    cr.consume(h);
  }
  return out;
}

function checkSorted(r: ByteReader, children: TlvHeader[], what: string, ctx: CodingContext): void {
  for (let i = 1; i < children.length; i++) {
    const prev = children[i - 1];
    const cur = children[i];
    if (
      compareBytes(
        r.data.subarray(prev.tlvStart, prev.contentEnd),
        r.data.subarray(cur.tlvStart, cur.contentEnd),
      ) > 0
    ) {
      ctx.path.index(i);
      r.fail(`non-DER ${what}: elements are not in ascending encoded order`, cur.tlvStart);
    }
  }
}

/** Tags a field type can present as its outermost TLV (several for CHOICE). */
function candidateTags(type: AsnType): Tag[] {
  const base = transparentBase(type);
  if (base instanceof ChoiceType) {
    const tags: Tag[] = [];
    for (const alt of base.alternatives) tags.push(...candidateTags(alt.type));
    return tags;
  }
  if (base instanceof ImplicitType && transparentBase(base.inner) instanceof ChoiceType) {
    // Constructed bit depends on the selected alternative.
    return [
      { cls: CLASS_CONTEXT, constructed: false, number: base.tagNumber },
      { cls: CLASS_CONTEXT, constructed: true, number: base.tagNumber },
    ];
  }
  return [base.outerTag()];
}

function matchesField(type: AsnType, tag: Tag): boolean {
  return candidateTags(type).some((t) => sameTag(t, tag));
}

function describeExpected(type: AsnType): string {
  const base = transparentBase(type);
  if (base instanceof ChoiceType) return 'a CHOICE alternative';
  if (base instanceof ImplicitType && transparentBase(base.inner) instanceof ChoiceType) {
    return `context tag [${base.tagNumber}]`;
  }
  try {
    return tagText(base.outerTag());
  } catch {
    return 'another tag';
  }
}

/** Decode exactly one complete TLV for `type` from `r` (cursor at TLV start). */
function readAny(type0: AsnType, r: ByteReader, ctx: CodingContext): unknown {
  const type = transparentBase(type0);
  const h = r.peek(r.pos);

  if (type instanceof ChoiceType) {
    // CHOICE is tag-indeterminate: it adds no physical TLV of its own.
    const alt = type.alternatives.find((a) => matchesField(a.type, h.tag));
    if (!alt) r.fail(`no CHOICE alternative matches ${tagText(h.tag)}`, h.tlvStart);
    ctx.path.field(alt.name);
    let val: unknown;
    try {
      val = readAny(alt.type, r, ctx);
    } finally {
      ctx.path.pop();
    }
    return new Choice(alt.name, val);
  }

  if (!matchesField(type, h.tag)) {
    r.fail(`expected ${describeExpected(type)} but found ${tagText(h.tag)}`, h.tlvStart);
  }

  const cr = new ByteReader(r.data, r.strict, r.path, h.contentStart, h.contentEnd);
  let val: unknown;
  ctx.enter();
  try {
    val = type.readContent(cr, h.contentStart, h.contentEnd, ctx, h.tag);
  } finally {
    ctx.leave();
  }
  r.consume(h);
  return val;
}

// ===========================================================================
// Helpers
// ===========================================================================

function typeError(expected: string, value: unknown, ctx: CodingContext): never {
  throw new DERError(`expected ${expected} but got ${describeValue(value)}`, null, ctx.path.text);
}

function describeValue(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function asBytes(expected: string, value: unknown, ctx: CodingContext): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw typeError(expected, value, ctx);
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (typeof a === 'bigint' || typeof b === 'bigint') return false;
  if (a instanceof BitString && b instanceof BitString) {
    return a.unusedBits === b.unusedBits && bytesEqual(a.bytes, b.bytes);
  }
  if (a instanceof Uint8Array && b instanceof Uint8Array) return bytesEqual(a, b);
  if (a instanceof Choice || b instanceof Choice) {
    if (!(a instanceof Choice) || !(b instanceof Choice)) return false;
    return a.name === b.name && deepEqual(a.value, b.value);
  }
  if (typeof a !== 'object' || a === null || typeof b !== 'object' || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  if (ka.length !== kb.length) return false;
  return ka.every(
    (k) =>
      Object.prototype.hasOwnProperty.call(b, k) &&
      deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
  );
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ===========================================================================
// Top-level API
// ===========================================================================

export function encode(type: AsnType, value: unknown, options?: EncodeOptions): Uint8Array {
  const ctx = new CodingContext(false, options?.maxDepth ?? DEFAULT_MAX_DEPTH);
  const w = new ByteWriter();
  type.writeTo(w, value, ctx); // root TLV: +1 depth
  return w.toUint8Array();
}

export function decode(type: AsnType, data: Uint8Array, options?: DecodeOptions): unknown {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('decode expects a Uint8Array');
  }
  const strict = options?.strict ?? true;
  const ctx = new CodingContext(strict, options?.maxDepth ?? DEFAULT_MAX_DEPTH);
  const r = new ByteReader(data, strict, ctx.path);
  const value = readAny(type, r, ctx); // root TLV: +1 depth
  if (r.pos !== data.length) {
    r.fail(`trailing ${data.length - r.pos} byte(s) after the complete value`, r.pos);
  }
  return value;
}

// ===========================================================================
// Schema factories
// ===========================================================================

export const boolean: BooleanType = new BooleanType();
export const integer: IntegerType = new IntegerType();
export const bitString: BitStringType = new BitStringType();
export const octetString: OctetStringType = new OctetStringType();
export const nullType: NullType = new NullType();
export const objectIdentifier: OidType = new OidType();
export const utf8String: Utf8StringType = new Utf8StringType();

export function sequenceOf(element: AsnType): CollectionOfType {
  return new CollectionOfType(element, TAG_SEQUENCE, false);
}

export function setOf(inElement: AsnType): CollectionOfType {
  return new CollectionOfType(inElement, TAG_SET, true);
}

export function sequence(fields: FieldDef[]): SequenceOrSetType {
  return new SequenceOrSetType(fields, TAG_SEQUENCE, false);
}

export function set(fields: FieldDef[]): SequenceOrSetType {
  return new SequenceOrSetType(fields, TAG_SET, true);
}

export function choice(alternatives: FieldDef[]): ChoiceType {
  return new ChoiceType(alternatives);
}

export function lazy(supplier: () => AsnType): LazyType {
  return new LazyType(supplier);
}
