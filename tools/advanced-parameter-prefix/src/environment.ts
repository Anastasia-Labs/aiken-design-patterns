export const GENERATED_PREFIX_START = "// BEGIN GENERATED ADVANCED PARAMETER PREFIX";
export const GENERATED_PREFIX_END = "// END GENERATED ADVANCED PARAMETER PREFIX";

/** Replace only the marked generated section, preserving handwritten source verbatim. */
export function replaceGeneratedPrefix(source: string, generated: string): string {
  const start = source.indexOf(GENERATED_PREFIX_START);
  const end = source.indexOf(GENERATED_PREFIX_END);
  if (
    start < 0 ||
    end < start ||
    start !== source.lastIndexOf(GENERATED_PREFIX_START) ||
    end !== source.lastIndexOf(GENERATED_PREFIX_END)
  ) {
    throw new Error("environment must contain exactly one ordered pair of generated prefix markers");
  }

  const startEnd = start + GENERATED_PREFIX_START.length;
  const endEnd = end + GENERATED_PREFIX_END.length;
  const newline = source.slice(startEnd, startEnd + 2) === "\r\n" ? "\r\n" : "\n";
  if (
    (start > 0 && source[start - 1] !== "\n") ||
    source.slice(startEnd, startEnd + newline.length) !== newline ||
    (end > 0 && source[end - 1] !== "\n") ||
    (endEnd < source.length && source[endEnd] !== "\n" && source.slice(endEnd, endEnd + 2) !== "\r\n")
  ) {
    throw new Error("generated prefix markers must occupy separate lines");
  }

  const formatted = generated.trim().replace(/\r?\n/g, newline);
  return source.slice(0, startEnd) + newline + formatted + newline + newline + source.slice(end);
}
