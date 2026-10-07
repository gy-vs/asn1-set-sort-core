/**
 * Error raised for every DER encoding/decoding failure.
 *
 * - `offset` is the byte offset inside the input buffer (decoding), or
 *   `null` when the failure happened while encoding.
 * - `path` is a textual location inside the data structure, e.g.
 *   `$.certs[3].validity.notBefore`.
 */
export class DERError extends Error {
  readonly offset: number | null;
  readonly path: string;

  constructor(message: string, offset?: number | null, path?: string) {
    const p = path ?? '$';
    const where =
      offset === null || offset === undefined
        ? ` (path ${p})`
        : ` at byte offset ${offset} (path ${p})`;
    super(message + where);
    this.name = 'DERError';
    this.offset = offset ?? null;
    this.path = p;
  }
}
