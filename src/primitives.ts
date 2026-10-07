/**
 * Content-octet coding for universal primitive types.
 * Every encoder produces the unique DER form; every decoder additionally
 * verifies that the form is canonical when `strict` is set.
 */
import {Asn1Error, type PathStep} from './errors.js';

/* ------------------------------ INTEGER ------------------------------ */

/** Minimal two's-complement big-endian content for a signed INTEGER. */
export function encodeIntegerContent(value: bigint): Uint8Array {
  if (typeof value !== 'bigint') {
    throw new Asn1Error(
      `INTEGER value must be a bigint, got ${typeof value}`,
    );
  }
  if (value === 0n) return Uint8Array.from([0]);

  if (value > 0n) {
    const bytes = magnitudeBytes(value);
    if (bytes[0] & 0x80) bytes.unshift(0);
    return Uint8Array.from(bytes);
  }
  // Smallest byte count in which the negative value fits as signed.
  // -m fits in k bits iff m <= 2^(k-1), i.e. k = bitLength(m-1)+1.
  const magnitude = -value;
  const k = bitLength(magnitude - 1n) + 1;
  const width = Math.max(1, Math.ceil(k / 8));
  const unsigned = (1n << BigInt(8 * width)) + value;
  const bytes = magnitudeBytes(unsigned);
  while (bytes.length < width) bytes.unshift(0);
  return Uint8Array.from(bytes);
}

function magnitudeBytes(value: bigint): number[] {
  const bytes: number[] = [];
  let v = value;
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  bytes.reverse();
  return bytes;
}

function bitLength(value: bigint): number {
  let n = 0;
  let v = value;
  while (v > 0n) {
    n++;
    v >>= 1n;
  }
  return n;
}

/** Parse a two's-complement INTEGER content, rejecting redundant padding. */
export function decodeIntegerContent(
  content: Uint8Array,
  strict: boolean,
  offset: number,
  path: readonly PathStep[],
): bigint {
  if (content.length === 0) {
    throw new Asn1Error('non-DER: INTEGER content is empty', offset, path);
  }
  if (strict && content.length > 1) {
    const first = content[0];
    const second = content[1];
    if (first === 0x00 && (second & 0x80) === 0) {
      throw new Asn1Error(
        'non-DER: INTEGER has a redundant leading 0x00 octet',
        offset,
        path,
      );
    }
    if (first === 0xff && (second & 0x80) !== 0) {
      throw new Asn1Error(
        'non-DER: INTEGER has a redundant leading 0xFF octet',
        offset,
        path,
      );
    }
  }
  let unsigned = 0n;
  for (const b of content) unsigned = (unsigned << 8n) | BigInt(b);
  if (content[0] & 0x80) unsigned -= 1n << BigInt(8 * content.length);
  return unsigned;
}

/* ------------------------------ BOOLEAN ------------------------------ */

export function encodeBooleanContent(value: boolean): Uint8Array {
  return Uint8Array.from([value ? 0xff : 0x00]);
}

export function decodeBooleanContent(
  content: Uint8Array,
  strict: boolean,
  offset: number,
  path: readonly PathStep[],
): boolean {
  if (content.length !== 1) {
    throw new Asn1Error(
      `non-DER: BOOLEAN content must be exactly one octet, got ${content.length}`,
      offset,
      path,
    );
  }
  const b = content[0];
  if (strict && b !== 0x00 && b !== 0xff) {
    throw new Asn1Error(
      'non-DER: BOOLEAN must be 0x00 (false) or 0xFF (true)',
      offset,
      path,
    );
  }
  return b !== 0x00;
}

/* ---------------------------- BIT STRING ----------------------------- */

export interface BitStringValue {
  /** Number of unused bits in the final content octet, 0..7. */
  unused: number;
  data: Uint8Array;
}

export function encodeBitStringContent(value: BitStringValue): Uint8Array {
  if (
    value === null ||
    typeof value !== 'object' ||
    typeof value.unused !== 'number' ||
    !(value.data instanceof Uint8Array)
  ) {
    throw new Asn1Error(
      'BIT STRING value must be { unused: number, data: Uint8Array }',
    );
  }
  const {unused} = value;
  const data = value.data.slice();
  if (!Number.isInteger(unused) || unused < 0 || unused > 7) {
    throw new Asn1Error(`BIT STRING unused-bits count out of range: ${unused}`);
  }
  if (data.length === 0 && unused !== 0) {
    throw new Asn1Error(
      'BIT STRING with zero content octets must declare zero unused bits',
    );
  }
  // Canonical form: unused trailing bits are zero.
  if (data.length > 0 && unused > 0) {
    data[data.length - 1] &= 0xff << unused & 0xff;
  }
  const out = new Uint8Array(data.length + 1);
  out[0] = unused;
  out.set(data, 1);
  return out;
}

export function decodeBitStringContent(
  content: Uint8Array,
  strict: boolean,
  offset: number,
  path: readonly PathStep[],
): BitStringValue {
  if (content.length === 0) {
    throw new Asn1Error(
      'non-DER: BIT STRING content is missing the unused-bits octet',
      offset,
      path,
    );
  }
  const unused = content[0];
  if (unused > 7) {
    throw new Asn1Error(
      `non-DER: BIT STRING unused-bits count is ${unused}, must be 0..7`,
      offset,
      path,
    );
  }
  const data = content.slice(1);
  if (strict) {
    if (data.length === 0 && unused !== 0) {
      throw new Asn1Error(
        'non-DER: empty BIT STRING declares nonzero unused bits',
        offset,
        path,
      );
    }
    if (data.length > 0 && unused > 0) {
      // Unused bits are the low-order (trailing) bits of the last octet.
      const mask = (0xff >>> (8 - unused)) & 0xff;
      if (data[data.length - 1] & mask) {
        throw new Asn1Error(
          'non-DER: unused trailing bits of BIT STRING are not zero',
          offset + content.length - 1,
          path,
        );
      }
    }
  }
  return {unused, data};
}

/* ------------------------ OBJECT IDENTIFIER -------------------------- */

export type OidValue = string | ReadonlyArray<number | bigint>;

export function encodeOidContent(value: OidValue): Uint8Array {
  const arcs = normalizeOidArcs(value);
  if (arcs.length < 2) {
    throw new Asn1Error('OBJECT IDENTIFIER needs at least two arcs');
  }
  const first = arcs[0];
  const second = arcs[1];
  if (first < 0n || first > 2n) {
    throw new Asn1Error(`OID first arc out of range: ${first.toString()}`);
  }
  if (first < 2n && second >= 40n) {
    throw new Asn1Error(
      `OID second arc ${second.toString()} must be below 40 under arc ${first.toString()}`,
    );
  }
  if (second < 0n) throw new Asn1Error('OID second arc is negative');
  for (let i = 2; i < arcs.length; i++) {
    if (arcs[i] < 0n) throw new Asn1Error(`OID arc ${i} is negative`);
  }

  const bytes: number[] = [];
  const pushArc = (arc: bigint) => {
    const digits = [Number(arc % 128n)];
    let rest = arc / 128n;
    while (rest > 0n) {
      digits.push(Number(rest % 128n));
      rest /= 128n;
    }
    for (let i = digits.length - 1; i >= 0; i--) {
      bytes.push(digits[i] | (i > 0 ? 0x80 : 0));
    }
  };
  pushArc(first * 40n + second);
  for (let i = 2; i < arcs.length; i++) pushArc(arcs[i]);
  return Uint8Array.from(bytes);
}

function normalizeOidArcs(value: OidValue): bigint[] {
  if (typeof value === 'string') {
    const text = value.trim();
    if (text.length === 0) throw new Asn1Error('empty OBJECT IDENTIFIER');
    const parts = text.split('.');
    return parts.map((part, i) => {
      if (!/^\d+$/.test(part)) {
        throw new Asn1Error(`OID arc ${i} is not a non-negative integer: ${part}`);
      }
      return BigInt(part);
    });
  }
  if (Array.isArray(value)) {
    return value.map((arc) => {
      if (typeof arc === 'bigint') return arc;
      if (typeof arc === 'number' && Number.isInteger(arc) && arc >= 0) {
        return BigInt(arc);
      }
      throw new Asn1Error(`OID arc must be an integer, got ${String(arc)}`);
    });
  }
  throw new Asn1Error('OBJECT IDENTIFIER value must be a dotted string or arc array');
}

export function decodeOidContent(
  content: Uint8Array,
  strict: boolean,
  offset: number,
  path: readonly PathStep[],
): string {
  if (content.length === 0) {
    throw new Asn1Error('non-DER: OBJECT IDENTIFIER content is empty', offset, path);
  }
  const arcs: bigint[] = [];
  const decodeArc = (arc: bigint) => {
    if (arcs.length === 0) {
      if (arc < 80n) arcs.push(arc / 40n, arc % 40n);
      else arcs.push(2n, arc - 80n);
    } else {
      arcs.push(arc);
    }
  };

  let current = 0n;
  let arcStart = 0;
  let octets = 0;
  for (let i = 0; i < content.length; i++) {
    const b = content[i];
    if (octets === 0) arcStart = i;
    if (strict && octets === 0 && b === 0x80) {
      throw new Asn1Error(
        'non-DER: OID subidentifier has a redundant leading 0x80 octet',
        offset + i,
        path,
      );
    }
    current = (current << 7n) | BigInt(b & 0x7f);
    octets++;
    if ((b & 0x80) === 0) {
      if (current > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Asn1Error(
          'OID subidentifier exceeds Number.MAX_SAFE_INTEGER',
          offset + arcStart,
          path,
        );
      }
      decodeArc(current);
      current = 0n;
      octets = 0;
    }
  }
  if (octets > 0) {
    throw new Asn1Error(
      'non-DER: OID ends inside a subidentifier (continuation bit still set)',
      offset + content.length,
      path,
    );
  }
  return arcs.map((a) => a.toString()).join('.');
}

/* ------------------------------ UTF8String ---------------------------- */

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal: true});

export function encodeUtf8Content(value: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new Asn1Error(`UTF8String value must be a string, got ${typeof value}`);
  }
  return encoder.encode(value);
}

export function decodeUtf8Content(
  content: Uint8Array,
  offset: number,
  path: readonly PathStep[],
): string {
  try {
    return decoder.decode(content);
  } catch {
    throw new Asn1Error(
      'non-DER: UTF8String is not valid UTF-8',
      offset,
      path,
    );
  }
}
