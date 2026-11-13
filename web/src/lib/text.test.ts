import { describe, expect, it } from "vitest";

import { hasHiddenCharacters, showControls } from "@/lib/text";

const RLO = String.fromCodePoint(0x202e);
const ZWSP = String.fromCodePoint(0x200b);
const LRI = String.fromCodePoint(0x2066);
const BOM = String.fromCodePoint(0xfeff);
const ESC = String.fromCodePoint(0x1b);
const CSI = String.fromCodePoint(0x9b);

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
