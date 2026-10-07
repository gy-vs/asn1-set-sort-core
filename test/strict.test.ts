import { describe, expect, it } from 'vitest';
import { asn1, decode, DERError, encode, sequence, setOf } from '../src/index.js';

const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));

function expectDER(hexStr: string, schema: Parameters<typeof decode>[0], strict = true) {
  let err: unknown;
  try {
    decode(schema, bytes(hexStr), { strict });
  } catch (e) {
    err = e;
  }
  expect(err, `expected rejection of ${hexStr}`).toBeInstanceOf(DERError);
  return err as DERError;
}

describe('strict mode rejects non-DER inputs', () => {
  it('non-minimal length (0x81 when short form suffices)', () => {
    expectDER('048103010203', asn1.octetString);
    expectDER('04820003010203', asn1.octetString);
  });

  it('constructed bit wrong for a primitive type', () => {
    // 0x22 = universal 2 (INTEGER) but constructed; valid DER primitive INTEGER
    // carries 0x02.
    expectDER('220105', asn1.integer);
  });

  it('primitive bit wrong for a constructed type', () => {
    // 0x10 = SEQUENCE with primitive bit clear.
    expectDER('1000', asn1.sequence([]));
  });

  it('indefinite length', () => {
    // SEQUENCE with indefinite length then EOC
    expectDER('30800201050000', asn1.sequence([['a', asn1.integer]]));
  });

  it('non-minimal length (0x81 when short form suffices)', () => {
    expectDER('048103010203', asn1.octetString);
    expectDER('04820003010203', asn1.octetString);
  });

  it('reserved 0xff length octet', () => {
    expectDER('04ff', asn1.octetString);
  });

  it('non-minimal INTEGER (redundant sign octets)', () => {
    expectDER('02020005', asn1.integer); // leading 00, next sign bit clear
    expectDER('0202ff80', asn1.integer); // leading ff, next sign bit set
  });

  it('non-canonical BOOLEAN', () => {
    expectDER('010101', asn1.boolean);
    expectDER('01017f', asn1.boolean);
  });

  it('empty INTEGER content', () => {
    expectDER('0200', asn1.integer);
  });

  it('NULL with content', () => {
    expectDER('050100', asn1.null);
  });

  it('unsorted SET OF', () => {
    // elements 020102 then 020101 (descending)
    const err = expectDER('3106020102020101', setOf(asn1.integer));
    expect(err.message).toMatch(/SET OF/);
    expect(err.offset).toBe(5); // offset of the second element TLV
  });

  it('unsorted SET (named fields)', () => {
    const schema = asn1.set([
      ['i', asn1.integer],
      ['flag', asn1.boolean],
    ]);
    // integer TLV first (02..), boolean second (01..) — wrong ascending order
    expectDER('31060201010101ff', schema);
  });

  it('trailing bytes after the top-level value', () => {
    const err = expectDER('020105' + '00', asn1.integer);
    expect(err.message).toMatch(/trailing/);
    expect(err.offset).toBe(3);
  });

  it('truncated: declared length longer than actual bytes', () => {
    const err = expectDER('04050102', asn1.octetString);
    expect(err.message).toMatch(/truncated|declared length/);
    expect(err.offset).toBe(0);
  });

  it('truncated tag/length headers', () => {
    expectDER('04', asn1.octetString);
    expectDER('0484', asn1.octetString);
  });

  it('high-tag-number form used for low tag number', () => {
    // 1f 01 = context constructed? Actually 1f is "high tag number", value 1
    expectDER('1f0100', asn1.null);
  });

  it('non-minimal OID subidentifier', () => {
    expectDER('0602802a', asn1.objectIdentifier);
  });

  it('BIT STRING unused bits non-zero', () => {
    // unused=1 but low bit of 0x03 is 1
    expectDER('03020103', asn1.bitString);
  });

  it('unknown field in SEQUENCE is rejected in strict mode', () => {
    const schema = sequence([['a', asn1.integer]]);
    const err = expectDER('30060201010101ff', schema);
    expect(err.message).toMatch(/unexpected/);
    expect(err.path).toBe('$');
  });

  it('explicit DEFAULT value written on the wire', () => {
    const schema = sequence([
      ['a', asn1.integer],
      ['b', asn1.boolean.default(false)],
    ]);
    // b=false (010100) present explicitly
    expectDER('3006020101010100', schema);
  });

  it('wrong type tag at field position', () => {
    const schema = sequence([['a', asn1.integer]]);
    expectDER('30030101ff', schema);
  });

  it('trailing bytes inside an explicit wrapper', () => {
    // [0] { INTEGER 5, BOOLEAN true } — extra TLV inside the wrapper
    expectDER('a0060201050101ff', asn1.integer.explicit(0));
  });
});

describe('error locations carry offset and structural path', () => {
  const cert = sequence([
    ['tbs', sequence([
      ['validity', sequence([
        ['notBefore', asn1.integer],
        ['notAfter', asn1.integer],
      ])],
    ])],
  ]);

  it('path points at the offending nested field', () => {
    // SEQUENCE { SEQUENCE { SEQUENCE { notBefore=bad-bool, notAfter=INT } } }
    const bad = bytes('300a' + '3008' + '3006' + '0101ff' + '020101');
    const err = expectDER(bad, cert);
    expect(err.path).toBe('$.tbs.validity.notBefore');
  });

  it('path includes array indices', () => {
    const schema = sequence([
      ['items', asn1.sequenceOf(asn1.integer)],
    ]);
    // items = [0, 1, BOOLEAN]
    const bad = bytes('300b' + '3009' + '020100' + '020101' + '0101ff');
    const err = expectDER(bad, schema);
    expect(err.path).toBe('$.items[2]');
  });

  it('SET OF error path includes the collection and index', () => {
    const schema = sequence([['many', setOf(asn1.integer)]]);
    // already sorted inside; corrupt order: 2 then 1
    const bad = bytes('3008' + '3106' + '020102' + '020101');
    const err = expectDER(bad, schema);
    expect(err.path).toBe('$.many[1]');
  });
});

describe('strict=false is lenient about DER uniqueness', () => {
  it('accepts non-minimal INTEGER and BOOLEAN', () => {
    expect(decode(asn1.integer, bytes('02020005'), { strict: false })).toBe(5n);
    expect(decode(asn1.boolean, bytes('010101'), { strict: false })).toBe(true);
  });

  it('accepts unsorted SET OF but re-encoding canonicalizes', () => {
    const schema = setOf(asn1.integer);
    const bad = bytes('3106020102020101');
    const v = decode(schema, bad, { strict: false }) as bigint[];
    expect(v).toEqual([2n, 1n]);
    const canonical = bytes('3106020101020102');
    expect(Buffer.from(encode(schema, v)).toString('hex')).toBe(Buffer.from(canonical).toString('hex'));
  });
});
