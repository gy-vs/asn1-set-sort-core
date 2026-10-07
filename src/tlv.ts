/**
 * X.690 identifier-octet and length-octet coding, plus byte helpers.
 * Everything here allocates nothing proportional to a *declared* length:
 * callers always work with subarray views bounded by the real buffer.
 */
import {Asn1Error, type PathStep} from './errors.js';
import type {TagClass} from './schema.js';

export interface TlvHeader {
  tagClass: TagClass;
  constructed: boolean;
  tagNumber: number;
  /** Offset of the first content octet. */
  contentStart: number;
  /** Offset one past the last content octet. */
  contentEnd: number;
}

/**
 * Parse one BER/DER TLV header in `buf[offset..end]`.
 * In strict mode every non-minimal encoding is rejected; indefinite lengths
 * are always rejected (they are BER, never DER, and this is a DER library).
 */
export function parseHeader(
  buf: Uint8Array,
  offset: number,
  end: number,
  strict: boolean,
  path: readonly PathStep[],
): TlvHeader {
  if (offset + 1 >= end) {
    throw new Asn1Error('truncated: missing tag octets', offset, path);
  }
  const first = buf[offset];
  const tagClass = (first >> 6) as TagClass;
  const constructed = (first & 0x20) !== 0;
  const low = first & 0x1f;
  let p = offset + 1;
  let tagNumber: number;

  if (low < 31) {
    tagNumber = low;
  } else {
    // High tag number form: base-128, big endian, minimally encoded.
    let number = 0n;
    let octets = 0;
    for (;;) {
      if (p >= end) {
        throw new Asn1Error(
          'truncated: tag number continuation octets',
          p,
          path,
        );
      }
      const b = buf[p];
      if (octets === 0 && b === 0x80) {
        throw new Asn1Error(
          'non-DER: high tag number uses a redundant leading 0x80 octet',
          p,
          path,
        );
      }
      number = (number << 7n) | BigInt(b & 0x7f);
      octets++;
      p++;
      if ((b & 0x80) === 0) break;
      if (p >= end) {
        throw new Asn1Error(
          'truncated: tag number continuation octets',
          p,
          path,
        );
      }
      if (number > BigInt(Number.MAX_SAFE_INTEGER) / 128n) {
        throw new Asn1Error('tag number too large', offset, path);
      }
    }
    if (number > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Asn1Error('tag number too large', offset, path);
    }
    // X.690 8.1.2.4.2 (c): a one-octet number below 31 must use low form.
    if (octets === 1 && number < 31n) {
      throw new Asn1Error(
        'non-DER: high-tag-number form used for a tag number below 31',
        offset,
        path,
      );
    }
    tagNumber = Number(number);
  }

  if (p >= end) {
    throw new Asn1Error('truncated: missing length octet', p, path);
  }
  const lenByte = buf[p++];
  let length: number;

  if (lenByte < 0x80) {
    length = lenByte;
  } else if (lenByte === 0x80) {
    throw new Asn1Error(
      'non-DER: indefinite length is BER only (definite length required)',
      p - 1,
      path,
    );
  } else {
    const n = lenByte & 0x7f;
    if (n > 8) {
      throw new Asn1Error(
        `unsupported: length encoded in ${n} octets`,
        p - 1,
        path,
      );
    }
    if (p + n > end) {
      throw new Asn1Error(
        'truncated: long-form length octets run past input',
        p,
        path,
      );
    }
    if (strict && n > 1 && buf[p] === 0x00) {
      throw new Asn1Error(
        'non-DER: length has a redundant leading zero octet',
        p,
        path,
      );
    }
    let raw = 0;
    for (let i = 0; i < n; i++) raw = raw * 256 + buf[p + i];
    p += n;
    if (strict && raw < 0x80) {
      throw new Asn1Error(
        'non-DER: length is not encoded in the minimum number of octets',
        offset,
        path,
      );
    }
    if (n === 8 && !Number.isSafeInteger(raw)) {
      throw new Asn1Error('unsupported: declared length exceeds 2^53-1', offset, path);
    }
    length = raw;
  }

  // Fail immediately against the *real* remaining bytes. Nothing is allocated
  // from `length`, so a lying huge length costs an integer comparison only.
  const contentEnd = p + length;
  if (contentEnd > end || contentEnd < p) {
    throw new Asn1Error(
      `truncated: declared length ${length} exceeds the ${end - p} remaining octets`,
      p,
      path,
    );
  }
  return {tagClass, constructed, tagNumber, contentStart: p, contentEnd};
}

/** Encode an identifier octet sequence. */
export function encodeTag(
  tagClass: TagClass,
  constructed: boolean,
  tagNumber: number,
): Uint8Array {
  const lead = (tagClass << 6) | (constructed ? 0x20 : 0);
  if (tagNumber < 31) {
    return Uint8Array.from([lead | tagNumber]);
  }
  if (!Number.isInteger(tagNumber) || tagNumber < 0) {
    throw new Asn1Error(`invalid tag number ${String(tagNumber)}`);
  }
  const digits: number[] = [];
  let n = tagNumber;
  do {
    digits.push(n & 0x7f);
    n = Math.floor(n / 128);
  } while (n > 0);
  const out = new Uint8Array(1 + digits.length);
  out[0] = lead | 0x1f;
  for (let i = 0; i < digits.length; i++) {
    out[1 + i] = digits[digits.length - 1 - i] | (i < digits.length - 1 ? 0x80 : 0);
  }
  return out;
}

/** Encode a definite length in minimal form. */
export function encodeLength(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new Asn1Error(`invalid length ${String(length)}`);
  }
  if (length < 0x80) return Uint8Array.from([length]);
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.push(n & 0xff);
    n = Math.floor(n / 256);
  }
  const out = new Uint8Array(1 + bytes.length);
  out[0] = 0x80 | bytes.length;
  for (let i = 0; i < bytes.length; i++) out[1 + i] = bytes[bytes.length - 1 - i];
  return out;
}

/** Wrap already-encoded content in tag + length TLV. */
export function wrapTlv(
  tagClass: TagClass,
  constructed: boolean,
  tagNumber: number,
  content: Uint8Array,
): Uint8Array {
  const tag = encodeTag(tagClass, constructed, tagNumber);
  const len = encodeLength(content.length);
  const out = new Uint8Array(tag.length + len.length + content.length);
  out.set(tag, 0);
  out.set(len, tag.length);
  out.set(content, tag.length + len.length);
  return out;
}

/** Concatenate chunks with a single allocation. */
export function concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

/**
 * DER SET ordering (X.690 11.6): ascending comparison of the complete
 * component encodings, treated as octet strings. Returns <0 / 0 / >0.
 */
export function compareTlv(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
