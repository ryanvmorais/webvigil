/**
 * Contrast guard for the design tokens in `globals.css` (WCAG AA, 4.5:1 for text).
 *
 * Reads the stylesheet as text and computes the ratios itself: jsdom has no layout or
 * cascade, so axe cannot measure colour contrast in the component tests, and Lighthouse
 * only runs against a live server. Nothing is mocked. The tokens that colour *text*
 * (severity levels, success, muted foreground) are checked in both themes on the page
 * background and on the `bg-muted/50` surface a table row takes on hover.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

type Rgb = [number, number, number];

const MIN_TEXT_CONTRAST = 4.5;

const TEXT_TOKENS = [
  "severity-info",
  "severity-low",
  "severity-medium",
  "severity-high",
  "severity-critical",
  "success",
  "muted-foreground",
] as const;

const css = readFileSync(resolve(__dirname, "globals.css"), "utf8");

/**
 * Parse the `--name: H S% L%;` declarations of one CSS block into HSL triples.
 *
 * @param block - The text between the braces of a `:root` rule.
 * @returns The token values keyed by name, without the leading dashes.
 */
function parseTokens(block: string): Record<string, [number, number, number]> {
  const tokens: Record<string, [number, number, number]> = {};
  for (const match of block.matchAll(/--([\w-]+):\s*([\d.]+)\s+([\d.]+)%\s+([\d.]+)%\s*;/g)) {
    tokens[match[1]] = [Number(match[2]), Number(match[3]), Number(match[4])];
  }
  return tokens;
}

const LIGHT = parseTokens(css.match(/:root\s*\{([^}]*)\}/)![1]);
const DARK = parseTokens(
  css.match(/prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{([^}]*)\}/)![1],
);

/** Convert an `[h, s%, l%]` triple to sRGB channels in the 0..1 range. */
function toRgb([h, s, l]: [number, number, number]): Rgb {
  const sat = s / 100;
  const light = l / 100;
  const chroma = (1 - Math.abs(2 * light - 1)) * sat;
  const channel = (n: number) => {
    const k = (n + h / 30) % 12;
    return light - (chroma / 2) * Math.max(-1, Math.min(k - 3, 9 - k, 1));
  };
  return [channel(0), channel(8), channel(4)];
}

/** Blend `top` over `bottom` at the given opacity (how `bg-muted/50` renders). */
function blend(top: Rgb, bottom: Rgb, alpha: number): Rgb {
  return top.map((value, i) => value * alpha + bottom[i] * (1 - alpha)) as Rgb;
}

/** WCAG relative luminance of an sRGB colour. */
function luminance(rgb: Rgb): number {
  const [r, g, b] = rgb.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG contrast ratio between two sRGB colours, from 1 to 21. */
function contrast(a: Rgb, b: Rgb): number {
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}

describe.each([
  ["light", LIGHT],
  ["dark", DARK],
])("text tokens in the %s theme", (_theme, overrides) => {
  // The dark block only overrides some tokens; the rest keep their light value.
  const tokens = { ...LIGHT, ...overrides };
  const background = toRgb(tokens.background);
  const hover = blend(toRgb(tokens.muted), background, 0.5);

  it.each(TEXT_TOKENS)("%s reaches 4.5:1 on the page background", (name) => {
    expect(contrast(toRgb(tokens[name]), background)).toBeGreaterThanOrEqual(MIN_TEXT_CONTRAST);
  });

  it.each(TEXT_TOKENS)("%s reaches 4.5:1 on the muted hover surface", (name) => {
    expect(contrast(toRgb(tokens[name]), hover)).toBeGreaterThanOrEqual(MIN_TEXT_CONTRAST);
  });
});
