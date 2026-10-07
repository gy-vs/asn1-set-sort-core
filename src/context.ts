import { DERError } from './errors.js';

/** Default cap on nested constructed TLVs; well below any plausible stack limit. */
export const DEFAULT_MAX_DEPTH = 512;

/**
 * Tracks the logical location inside the value being encoded or decoded.
 * Segments are rendered as `$`, `$.field`, `$[3]`, `$.certs[3].validity`.
 */
export class PathStack {
  private readonly segs: string[] = [];

  get text(): string {
    return '$' + this.segs.join('');
  }

  field(name: string): void {
    this.segs.push('.' + name);
  }

  index(i: number): void {
    this.segs.push('[' + i + ']');
  }

  pop(): void {
    this.segs.pop();
  }
}

/** Shared mutable state passed through the (de)encoder. */
export class CodingContext {
  readonly strict: boolean;
  readonly maxDepth: number;
  readonly path = new PathStack();
  depth = 0;

  constructor(strict: boolean, maxDepth: number) {
    this.strict = strict;
    this.maxDepth = maxDepth;
  }

  enter(): void {
    this.depth++;
    if (this.depth > this.maxDepth) {
      throw new DERError(
        `nesting depth ${this.depth} exceeds the allowed maximum of ${this.maxDepth}`,
        null,
        this.path.text,
      );
    }
  }

  leave(): void {
    this.depth--;
  }
}
