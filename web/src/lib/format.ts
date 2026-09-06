/** Presentation helpers. The UI never computes scan data — only formats it (RNF-01). */

export function cweUrl(id: number): string {
  return `https://cwe.mitre.org/data/definitions/${id}.html`;
}

export function reportFilename(id: number, ext: string): string {
  return `webvigil-${id}.${ext}`;
}

// Copy is English (see requirements); times are formatted in `en` for consistency.
const LOCALE = "en";

export function absoluteTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(LOCALE);
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 60 * 60 * 1000],
  ["month", 30 * 24 * 60 * 60 * 1000],
  ["day", 24 * 60 * 60 * 1000],
  ["hour", 60 * 60 * 1000],
  ["minute", 60 * 1000],
  ["second", 1000],
];

export function relativeTime(iso: string | null, now: number = Date.now()): string {
  if (!iso) return "—";
  const deltaMs = new Date(iso).getTime() - now;
  const rtf = new Intl.RelativeTimeFormat(LOCALE, { numeric: "auto" });
  for (const [unit, ms] of UNITS) {
    if (Math.abs(deltaMs) >= ms || unit === "second") {
      return rtf.format(Math.round(deltaMs / ms), unit);
    }
  }
  return rtf.format(0, "second");
}
