const DEFAULT_NEXT = "/scans";

// Only used to ask the URL parser where a path really points; never requested.
const PROBE_ORIGIN = "http://webvigil.invalid";

/**
 * The post-login destination from `?next=`, or `fallback` when it is not a same-origin path.
 *
 * A bare `startsWith("/")` is not enough: browsers read `//host` as a protocol-relative URL,
 * turn `/\host` into `//host`, and drop tabs and newlines inside a URL, so `/<TAB>/host`
 * becomes `//host` too. The value must start with a single `/`, carry no backslash or control
 * character, and still resolve to the same origin once parsed.
 *
 * @param value - The raw `next` query parameter (`null` when absent).
 * @param fallback - Where to go when `value` is missing or unsafe.
 * @returns `value` when it is a safe in-app path, else `fallback`.
 */
export function safeNext(value: string | null, fallback: string = DEFAULT_NEXT): string {
  if (!value || !/^\/(?![/\\])/.test(value) || /[\\\p{Cc}]/u.test(value)) return fallback;
  try {
    return new URL(value, PROBE_ORIGIN).origin === PROBE_ORIGIN ? value : fallback;
  } catch {
    return fallback;
  }
}
