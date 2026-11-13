/**
 * Shows the control, bidirectional and zero-width characters of text from the scanned site as
 * visible `\xNN` / `\uNNNN` escapes, the rule of `webvigil.core.text.show_controls`.
 */

// Code point ranges, inclusive: the C0 controls (tab and line feed are handled apart), DEL and
// the C1 range, the bidirectional marks, embeddings, overrides and isolates, and the zero-width
// characters. Kept in step with `INVISIBLE_CHARS` in `src/webvigil/core/text.py`.
const HIDDEN_RANGES: readonly (readonly [number, number])[] = [
  [0x00, 0x08],
  [0x0b, 0x1f],
  [0x7f, 0x9f],
  [0x061c, 0x061c],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
];
const TAB = 0x09;
const LINE_FEED = 0x0a;

function isHidden(code: number, oneLine: boolean): boolean {
  if (code === TAB || code === LINE_FEED) return oneLine;
  return HIDDEN_RANGES.some(([low, high]) => code >= low && code <= high);
}

function escapeCode(code: number): string {
  return code <= 0xff
    ? `\\x${code.toString(16).padStart(2, "0")}`
    : `\\u${code.toString(16).padStart(4, "0")}`;
}

/**
 * Whether a value holds a character that `showControls` would escape (tab and line feed
 * included): a link with one reads as another address than the one it opens.
 *
 * @param value - Text that may have come from the scanned site.
 * @returns `true` when one of those characters is present.
 */
export function hasHiddenCharacters(value: string): boolean {
  for (const char of value) {
    if (isHidden(char.codePointAt(0) ?? 0, true)) return true;
  }
  return false;
}

/**
 * Writes the control, bidirectional and invisible characters of a value as visible escapes.
 *
 * @param value - Text that may have come from the scanned site.
 * @param options - `oneLine` escapes tabs and line feeds too, for a title or a location.
 * @returns The value with each such character as `\xNN` (up to U+00FF) or `\uNNNN`; CRLF
 *   becomes LF first, so a body with Windows line endings reads as it did.
 */
export function showControls(value: string, options: { oneLine?: boolean } = {}): string {
  const oneLine = options.oneLine ?? false;
  const text = oneLine ? value : value.replaceAll("\r\n", "\n");
  let shown = "";
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    shown += isHidden(code, oneLine) ? escapeCode(code) : char;
  }
  return shown;
}
