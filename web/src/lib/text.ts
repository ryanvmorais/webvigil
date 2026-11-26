/**
 * Shows the control, bidirectional and zero-width characters of text from the scanned site as
 * visible `\xNN` / `\uNNNN` escapes, the rule of `webvigil.core.text.show_controls`.
 */

// Code point ranges, inclusive: the C0 controls (tab and line feed are handled apart), DEL and
// the C1 range, the bidirectional marks, embeddings, overrides and isolates, the zero-width
// characters, the characters that show as nothing in most fonts (soft hyphen, combining
// grapheme joiner, Hangul fillers, Khmer inherent vowels, Mongolian vowel separator,
// interlinear annotation, tags) and the line and paragraph separators. Kept in step with
// `INVISIBLE_CHARS` in `src/webvigil/core/text.py`.
const HIDDEN_RANGES: readonly (readonly [number, number])[] = [
  [0x00, 0x08],
  [0x0b, 0x1f],
  [0x7f, 0x9f],
  [0x00ad, 0x00ad],
  [0x034f, 0x034f],
  [0x061c, 0x061c],
  [0x115f, 0x1160],
  [0x17b4, 0x17b5],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
  [0x3164, 0x3164],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0xfff9, 0xfffb],
  [0xe0000, 0xe007f],
];
const TAB = 0x09;
const LINE_FEED = 0x0a;

function isHidden(code: number, oneLine: boolean): boolean {
  if (code === TAB || code === LINE_FEED) return oneLine;
  return HIDDEN_RANGES.some(([low, high]) => code >= low && code <= high);
}

// As Python writes them: four digits after `\u` always end the escape, so a code point past
// U+FFFF takes `\U` and eight.
function escapeCode(code: number): string {
  if (code <= 0xff) return `\\x${code.toString(16).padStart(2, "0")}`;
  if (code <= 0xffff) return `\\u${code.toString(16).padStart(4, "0")}`;
  return `\\U${code.toString(16).padStart(8, "0")}`;
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
 * @returns The value with each such character as `\xNN` (up to U+00FF), `\uNNNN` or, past
 *   U+FFFF, `\UNNNNNNNN`; CRLF becomes LF first, so a body with Windows line endings reads as it
 *   did.
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

/**
 * The one way the dashboard shows a value the API returns that a site, a file, a plugin or a
 * user chose: on one line by default, since most of them sit in a heading, a cell, a label, a
 * tooltip or the document title.
 *
 * @param value - A string from the API, or nothing.
 * @param options - `multiLine` keeps tabs and line feeds, for a description or an error body.
 * @returns `""` for `null` and `undefined`, otherwise the value through `showControls`.
 */
export function display(
  value: string | null | undefined,
  options: { multiLine?: boolean } = {},
): string {
  if (value === null || value === undefined) return "";
  return showControls(value, { oneLine: !(options.multiLine ?? false) });
}
