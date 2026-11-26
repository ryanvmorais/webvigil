import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { display, hasHiddenCharacters, showControls } from "@/lib/text";

const RLO = String.fromCodePoint(0x202e);
const ZWSP = String.fromCodePoint(0x200b);
const LRI = String.fromCodePoint(0x2066);
const BOM = String.fromCodePoint(0xfeff);
const ESC = String.fromCodePoint(0x1b);
const CSI = String.fromCodePoint(0x9b);

/** One case of the file `show_controls` (Python) and `showControls` both pass (spec 025, ADR-7). */
type SharedCase = { name: string; input: string; one_line: boolean; expected: string };

// `import.meta.url` is not a `file:` URL under jsdom; the directory is.
const CASES_FILE = join(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "tests",
  "data",
  "text-controls-cases.json",
);

/**
 * Reads the shared cases. The file lives outside `web/`, so a copy of the dashboard alone fails
 * here, naming the file, instead of skipping the comparison with the Python side.
 */
function loadCases(path: string): SharedCase[] {
  if (!existsSync(path)) {
    throw new Error(
      `The shared cases file ${path} is missing: run the dashboard's tests from a full checkout.`,
    );
  }
  return JSON.parse(readFileSync(path, "utf8")) as SharedCase[];
}

describe("the shared cases of tests/data/text-controls-cases.json", () => {
  const cases = loadCases(CASES_FILE);

  it("holds cases", () => {
    // a file emptied by mistake would pass every case below without running one
    expect(cases.length).toBeGreaterThan(50);
  });

  it.each(cases.map((sharedCase) => [sharedCase.name, sharedCase] as const))(
    "%s",
    (_name, sharedCase) => {
      expect(showControls(sharedCase.input, { oneLine: sharedCase.one_line })).toBe(
        sharedCase.expected,
      );
    },
  );

  it("fails with the file's name when the file is missing", () => {
    const missing = join(import.meta.dirname, "no-such-cases.json");
    expect(() => loadCases(missing)).toThrow(missing);
  });
});

describe("display", () => {
  it("gives an empty string for null and undefined", () => {
    expect(display(null)).toBe("");
    expect(display(undefined)).toBe("");
  });

  it("escapes tab and line feed by default, as on one line", () => {
    expect(display(`a\tb\nc${ESC}`)).toBe("a\\x09b\\x0ac\\x1b");
  });

  it("keeps tab and line feed and reads CRLF as LF with multiLine", () => {
    expect(display(`a\tb\r\nc${RLO}`, { multiLine: true })).toBe("a\tb\nc\\u202e");
  });
});

/** A code point as a test name shows it: 202E, not 8238. */
const hex = (code: number) => code.toString(16).toUpperCase().padStart(4, "0");

describe("showControls", () => {
  it("writes bidirectional and zero-width characters as \\u escapes", () => {
    expect(showControls(`a${RLO}b${ZWSP}c${LRI}d${BOM}é`)).toBe(
      "a\\u202eb\\u200bc\\u2066d\\ufeffé",
    );
  });

  it("writes C0, DEL and C1 controls as \\x escapes", () => {
    expect(showControls(`a${ESC}b\x7fc${CSI}d`)).toBe("a\\x1bb\\x7fc\\x9bd");
  });

  it("keeps tab and line feed and reads CRLF as LF", () => {
    expect(showControls("a\tb\r\nc\rd")).toBe("a\tb\nc\\x0dd");
  });

  it("escapes tab and line feed too on one line", () => {
    expect(showControls("a\tb\nc", { oneLine: true })).toBe("a\\x09b\\x0ac");
  });

  it("keeps both halves of a CRLF on one line: a title has no line endings to normalise", () => {
    expect(showControls("a\r\nb", { oneLine: true })).toBe("a\\x0d\\x0ab");
  });

  // Both ends of every range of `INVISIBLE_CHARS` (src/webvigil/core/text.py), so a range that
  // shrinks by one, or one that goes missing, fails here and not only in a sample.
  it.each(
    [
      [0x00, "\\x00"],
      [0x08, "\\x08"],
      [0x0b, "\\x0b"],
      [0x1f, "\\x1f"],
      [0x7f, "\\x7f"],
      [0x9f, "\\x9f"],
      [0x061c, "\\u061c"],
      [0x200b, "\\u200b"],
      [0x200f, "\\u200f"],
      [0x202a, "\\u202a"],
      [0x202e, "\\u202e"],
      [0x2060, "\\u2060"],
      [0x2064, "\\u2064"],
      [0x2066, "\\u2066"],
      [0x2069, "\\u2069"],
      [0xfeff, "\\ufeff"],
      [0x00ad, "\\xad"],
      [0x034f, "\\u034f"],
      [0x115f, "\\u115f"],
      [0x1160, "\\u1160"],
      [0x17b4, "\\u17b4"],
      [0x17b5, "\\u17b5"],
      [0x180e, "\\u180e"],
      [0x2028, "\\u2028"],
      [0x2029, "\\u2029"],
      [0x3164, "\\u3164"],
      [0xffa0, "\\uffa0"],
      [0xfff9, "\\ufff9"],
      [0xfffb, "\\ufffb"],
      [0xe0000, "\\U000e0000"],
      [0xe007f, "\\U000e007f"],
    ].map(([code, escape]) => [hex(code as number), code, escape] as const),
  )("escapes U+%s, an end of a hidden range", (_hex, code, escape) => {
    expect(showControls(`a${String.fromCodePoint(code as number)}b`)).toBe(`a${escape}b`);
  });

  // ...and the character just outside each end stays as it is.
  it.each(
    [
      0x20, 0x7e, 0xa0, 0xac, 0xae, 0x034e, 0x0350, 0x061b, 0x061d, 0x115e, 0x1161, 0x17b3, 0x17b6,
      0x180d, 0x180f, 0x200a, 0x2010, 0x2027, 0x202f, 0x205f, 0x2065, 0x206a, 0x3163, 0x3165,
      0xff9f, 0xffa1, 0xfff8, 0xfffc, 0xdffff, 0xe0080,
    ].map((code) => [hex(code), code] as const),
  )("leaves U+%s, just outside a hidden range, alone", (_hex, code) => {
    const char = String.fromCodePoint(code);
    expect(showControls(`a${char}b`)).toBe(`a${char}b`);
  });

  it("leaves ordinary text alone", () => {
    expect(showControls("Missing header on /café — ok")).toBe("Missing header on /café — ok");
  });
});

describe("hasHiddenCharacters", () => {
  it.each([`a${RLO}b`, `a${ZWSP}b`, `a${ESC}b`, "a\tb"])("finds one in %j", (value) => {
    expect(hasHiddenCharacters(value)).toBe(true);
  });

  it("finds none in ordinary text", () => {
    expect(hasHiddenCharacters("https://example.org/café")).toBe(false);
  });
});
