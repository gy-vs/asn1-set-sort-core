/**
 * A single component of a path into the data structure.
 * Object field names are strings; SEQUENCE OF / SET OF indices are numbers.
 */
export type PathStep = string | number;

function formatPath(path: readonly PathStep[] | undefined): string {
  if (!path || path.length === 0) return '<root>';
  let out = '';
  for (const step of path) {
    if (typeof step === 'number') out += `[${step}]`;
    else if (out.length === 0) out = step;
    else out += `.${step}`;
  }
  return out;
}

/**
 * Error thrown for every schema violation, encoding failure and malformed
 * (non-DER) input. Decoding errors always carry the byte `offset` at which
 * the problem was detected and the `path` of the value inside the structure,
 * e.g. `certs[3].validity`.
 */
export class Asn1Error extends Error {
  /** Byte offset into the input being decoded, or null when encoding. */
  readonly offset: number | null;
  /** Path through the structure, e.g. ["certs", 3, "validity"]. */
  readonly path: PathStep[];

  constructor(
    message: string,
    offset?: number | null,
    path?: readonly PathStep[],
  ) {
    const where: string[] = [];
    const p = formatPath(path);
    if (p) where.push(`at ${p}`);
    if (offset !== undefined && offset !== null) {
      where.push(`byte offset ${offset}`);
    }
    super(where.length ? `${message} (${where.join(', ')})` : message);
    this.name = 'Asn1Error';
    this.offset = offset === undefined ? null : offset;
    this.path = path ? [...path] : [];
  }
}
