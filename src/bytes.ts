import { DERError } from './errors.js';
import { PathStack } from './context.js';

// ---------------------------------------------------------------------------
// Universal tags (X.690 8.1.2)
// ---------------------------------------------------------------------------

export const TAG_BOOLEAN = 0x01;
export const TAG_INTEGER = 0x02;
export const TAG_BIT_STRING = 0x03;
export const TAG_OCTET_STRING = 0x04;
export const TAG_NULL = 0x05;
export const TAG_OID = 0x06;
export const TAG_UTF8_STRING = 0x0c;
export const TAG_SEQUENCE = 0x10;
export const TAG_SET = 0x11;

/** Class bits as stored in the identifier octet (X.690 8.1.2.1). */
export const CLASS_UNIVERSAL = 0x00;
export const CLASS_CONTEXT = 0x02;

export interface Tag {
  cls: number;
  constructed: boolean;
  number: number;
}

function tagFirstOctet(t: Tag): number {
  return (t.cls << 6) | (t.constructed ? 0x20 : 0) | (t.number < 0x1f ? t.number : 0x1f);
}

export function writeTag(w: ByteWriter, t: Tag): void {
  w.byte(tagFirstOctet(t));
  if (t.number >= 0x1f) {
    const groups: number[] = [t.number & 0x7f];
    let v = t.number;
    while (v >= 0x80) {
      v = Math.floor(v / 0x80);
      groups.push(v & 0x7f);
    }
    for (let i = groups.length - 1; i > 0; i--) w.byte(groups[i] | 0x80);
    w.byte(groups[0]);
  }
}

export function sameTag(a: Tag, b: Tag): boolean {
  return a.cls === b.cls && a.constructed === b.constructed && a.number === b.number;
}

export function tagText(t: Tag): string {
  if (t.cls === CLASS_CONTEXT) return `[${t.number}]${t.constructed ? ' (constructed)' : ''}`;
  const clsName = ['universal', 'application', 'context', 'private'][t.cls] ?? '?';
  return `${clsName} ${t.number}${t.constructed ? ' (constructed)' : ''}`;
}

// ---------------------------------------------------------------------------
// Length octets (X.690 8.1.3) — DER: definite form, minimum number of octets
// ---------------------------------------------------------------------------

export function writeLength(w: ByteWriter, len: number): void {
  if (len < 0x80) {
    w.byte(len);
    return;
  }
  const bytes: number[] = [];
  for (let v = len; v > 0; v >>>= 8) bytes.push(v & 0xff);
  w.byte(0x80 | bytes.length);
  for (let i = bytes.length - 1; i >= 0; i--) w.byte(bytes[i]);
}

// ---------------------------------------------------------------------------
// Chunked writer — amortized linear, never O(n^2), no runtime dependencies
// ---------------------------------------------------------------------------

export class ByteWriter {
  private chunks: Uint8Array[] = [];
  private len = 0;

  byte(v: number): void {
    this.chunks.push(new Uint8Array([v & 0xff]));
    this.len++;
  }

  bytes(b: Uint8Array): void {
    if (b.length === 0) return;
    this.chunks.push(b);
    this.len += b.length;
  }

  /** Concatenate another (fully built) writer without extra per-byte copies. */
  writer(other: ByteWriter): void {
    for (const c of other.chunks) {
      this.chunks.push(c);
      this.len += c.length;
    }
  }

  get length(): number {
    return this.len;
  }

  /** Emit an identifier/length head for content of `contentLength` octets. */
  writeHead(tag: Tag, contentLength: number): void {
    writeTag(this, tag);
    writeLength(this, contentLength);
  }

  toUint8Array(): Uint8Array {
    const out = new Uint8Array(this.len);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Zero-copy cursor over one buffer
// ---------------------------------------------------------------------------

export interface TlvHeader {
  tag: Tag;
  /** Offset of the first content octet. */
  contentStart: number;
  /** Offset just past the last content octet. */
  contentEnd: number;
  /** Offset of the identifier octet. */
  tlvStart: number;
}

export class ByteReader {
  readonly data: Uint8Array;
  /** Inclusive start of this reader's window. */
  readonly start: number;
  /** Exclusive end of this reader's window. */
  readonly end: number;
  pos: number;
  readonly strict: boolean;
  readonly path: PathStack;

  constructor(data: Uint8Array, strict: boolean, path: PathStack, start = 0, end?: number) {
    this.data = data;
    this.start = start;
    this.pos = start;
    this.end = end ?? data.length;
    this.strict = strict;
    this.path = path;
  }

  fail(message: string, offset = this.pos): never {
    throw new DERError(message, offset, this.path.text);
  }

  private need(n: number, offset: number): void {
    if (offset + n > this.end || offset + n < offset) {
      this.fail('truncated DER: expected more bytes', Math.min(offset, this.end));
    }
  }

  /** Parse one TLV header at `at` without consuming anything. */
  peek(at: number): TlvHeader {
    this.need(2, at);
    const first = this.data[at];
    const numberInOctet = first & 0x1f;
    let number: number;
    let p = at + 1;
    if (numberInOctet < 0x1f) {
      number = numberInOctet;
    } else {
      // High-tag-number form: base-128 groups, each except last has bit 8 set.
      number = 0;
      let b = 0;
      let groups = 0;
      do {
        this.need(1, p);
        b = this.data[p++];
        groups++;
        if (groups > 8) this.fail('tag number too large', at);
        number = number * 128 + (b & 0x7f);
        if (number > 0xffffffff) this.fail('tag number too large', at);
      } while (b & 0x80);
      if (this.strict) {
        // Minimum encoding: with at least two groups the leading group is 1..127,
        // so its continuation octet is 0x81..0xff (never 0x80).
        if (groups >= 2 && this.data[at + 1] === 0x80) {
          this.fail('non-DER tag: high-tag-number form is not minimal', at);
        }
        if (number < 0x1f) {
          this.fail('non-DER tag: high-tag-number form used for a number below 31', at);
        }
      }
    }

    this.need(1, p);
    const firstLength = this.data[p++];
    let length: number;
    if (firstLength < 0x80) {
      length = firstLength;
    } else if (firstLength === 0x80) {
      this.fail('indefinite length is forbidden in DER', p - 1);
    } else if (firstLength === 0xff) {
      this.fail('reserved length octet 0xff', p - 1);
    } else {
      const numBytes = firstLength & 0x7f;
      this.need(numBytes, p);
      // Exact 32-bit math is enough for any real buffer; anything bigger is
      // rejected here, before content is allocated or recursed into.
      if (numBytes > 4) this.fail('declared length exceeds supported maximum', p - 1);
      length = 0;
      for (let i = 0; i < numBytes; i++) length = length * 256 + this.data[p + i];
      // Minimal long form: the value must not fit in (numBytes-1) bytes, i.e.
      // it is >= 256^(numBytes-1). This also rejects 0x81 0x00..0x7f which
      // belong in the short form.
      const minimum = numBytes === 1 ? 0x80 : 1 << ((numBytes - 1) * 8);
      if (this.strict && length < minimum) {
        this.fail('non-DER length: encoding is not minimal', p - 1);
      }
      p += numBytes;
    }

    const contentStart = p;
    const contentEnd = contentStart + length;
    // Bounds-check the declared content against the *actual* bytes right away.
    if (length > this.end - contentStart) {
      this.fail(
        `truncated DER: declared length ${length} but only ${Math.max(
          0,
          this.end - contentStart,
        )} content byte(s) follow`,
        at,
      );
    }
    return {
      tag: { cls: (first & 0xc0) >> 6, constructed: (first & 0x20) !== 0, number },
      contentStart,
      contentEnd,
      tlvStart: at,
    };
  }

  consume(h: TlvHeader): void {
    this.pos = h.contentEnd;
  }

  /** Reader scoped to a TLV's content octets (shares one backing buffer). */
  scope(h: TlvHeader): ByteReader {
    return new ByteReader(this.data, this.strict, this.path, h.contentStart, h.contentEnd);
  }
}

// ---------------------------------------------------------------------------
// INTEGER content (X.690 8.3): two's complement, minimum number of octets
// ---------------------------------------------------------------------------

export function integerBytes(value: bigint, path: PathStack): Uint8Array {
  if (value === 0n) return new Uint8Array([0]);
  const negative = value < 0n;

  // Little-endian magnitude bytes.
  const magBytes: number[] = [];
  let mag = negative ? -value : value;
  while (mag > 0n) {
    magBytes.push(Number(mag & 0xffn));
    mag >>= 8n;
  }

  let out: Uint8Array;
  if (!negative) {
    // Prefix 0x00 when the top magnitude byte already uses bit 7.
    const pad = magBytes[magBytes.length - 1] >= 0x80 ? 1 : 0;
    out = new Uint8Array(magBytes.length + pad);
    if (pad) out[0] = 0x00;
    for (let i = 0; i < magBytes.length; i++) out[out.length - 1 - i] = magBytes[i];
  } else {
    // Two's complement within the magnitude width; magBytes are little-endian,
    // so twos is big-endian afterwards.
    let twos = new Uint8Array(magBytes.length);
    let carry = 1;
    for (let i = 0; i < magBytes.length; i++) {
      const sum = (magBytes[i] ^ 0xff) + carry;
      twos[twos.length - 1 - i] = sum & 0xff;
      carry = sum >> 8;
    }
    // The minimal negative representation is known; prepend 0xff when either:
    //  - the top twos byte has a clear sign bit (value would read positive), or
    //  - it is 0xff followed by another byte whose high bit is set (would be a
    //    redundant leading 0xff).
    let pad = 0;
    if ((twos[0] & 0x80) === 0) pad = 1;
    if (twos.length > 1 && twos[0] === 0xff && (twos[1] & 0x80) !== 0) pad = 1;
    out = new Uint8Array(twos.length + pad);
    if (pad) out[0] = 0xff;
    out.set(twos, pad);
  }

  const leading = out[0];
  if (((leading & 0x80) !== 0) !== negative) {
    throw new DERError('internal integer encoding error', null, path.text);
  }
  if (out.length > 1) {
    // X.690: a leading 0x00 with a clear next sign bit, or a leading 0xff with
    // a set next sign bit, is redundant padding.
    if (out[0] === 0x00 && (out[1] & 0x80) === 0) {
      throw new DERError('internal integer encoding error: non-minimal', null, path.text);
    }
    if (out[0] === 0xff && (out[1] & 0x80) !== 0) {
      throw new DERError('internal integer encoding error: non-minimal', null, path.text);
    }
  }
  return out;
}

/** Read signed INTEGER content, rejecting anything non-minimal in strict mode. */
export function readIntegerContent(r: ByteReader, start: number, end: number): bigint {
  if (end - start === 0) r.fail('INTEGER content is empty', start);
  const first = r.data[start];
  if (r.strict && end - start >= 2) {
    const second = r.data[start + 1];
    if (first === 0x00 && (second & 0x80) === 0) {
      r.fail('non-DER INTEGER: redundant leading 0x00', start);
    }
    if (first === 0xff && (second & 0x80) !== 0) {
      r.fail('non-DER INTEGER: redundant leading 0xff', start);
    }
  }  let v = 0n;
  for (let i = start; i < end; i++) v = (v << 8n) | BigInt(r.data[i]);
  if (first & 0x80) v -= 1n << BigInt((end - start) * 8);
  return v;
}

// ---------------------------------------------------------------------------
// OBJECT IDENTIFIER content (X.690 8.19)
// ---------------------------------------------------------------------------

function encodeBase128(w: ByteWriter, value: number): void {
  const groups = [value & 0x7f];
  let v = value;
  while (v >= 0x80) {
    v = Math.floor(v / 0x80);
    groups.push(v & 0x7f);
  }
  for (let i = groups.length - 1; i > 0; i--) w.byte(groups[i] | 0x80);
  w.byte(groups[0]);
}

export function oidBytes(oid: string, path: PathStack): Uint8Array {
  const parts = oid.split('.');
  if (parts.length < 2 || parts.some((s) => !/^(?:0|[1-9][0-9]*)$/.test(s))) {
    throw new DERError(`invalid OID "${oid}"`, null, path.text);
  }
  const arcs = parts.map(Number);
  if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39)) {
    throw new DERError(`invalid OID "${oid}": first two arcs out of range`, null, path.text);
  }
  const w = new ByteWriter();
  encodeBase128(w, arcs[0] * 40 + arcs[1]);
  for (let i = 2; i < arcs.length; i++) encodeBase128(w, arcs[i]);
  return w.toUint8Array();
}

export function readOidContent(r: ByteReader, start: number, end: number): string {
  if (end - start === 0) r.fail('OBJECT IDENTIFIER content is empty', start);
  const arcs: bigint[] = [];
  let value = 0n;
  let groups = 0;
  let groupStart = start;
  let firstSub = true;
  for (let i = start; i < end; i++) {
    const b = r.data[i];
    if (groups === 0) groupStart = i;
    value = value * 128n + BigInt(b & 0x7f);
    groups++;
    if (value > 0xffffffffn) r.fail('OID subidentifier too large', groupStart);
    if (b & 0x80) continue;
    if (r.strict && groups >= 2 && r.data[groupStart] === 0x80) {
      r.fail('non-DER OID: subidentifier encoding is not minimal', groupStart);
    }
    if (firstSub) {
      // X.690 8.19.4: 0..39→0.x, 40..79→1.(x-40), 80..→2.(x-80).
      if (value < 40n) arcs.push(0n, value);
      else if (value < 80n) arcs.push(1n, value - 40n);
      else arcs.push(2n, value - 80n);
      firstSub = false;
    } else {
      arcs.push(value);
    }
    value = 0n;
    groups = 0;
  }
  if (groups !== 0) r.fail('truncated OID: subidentifier missing final octet', end);
  return arcs.map((a) => a.toString()).join('.');
}

// ---------------------------------------------------------------------------
// SET/SET OF ordering (X.690 11.6): encoded elements sorted ascending
// ---------------------------------------------------------------------------

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export function sortByteArrays(items: Uint8Array[]): Uint8Array[] {
  return items.sort(compareBytes);
}
