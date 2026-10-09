/**
 * The links the dashboard points at, and the rule for turning a URL the server sent into one
 * (#161).
 */

export const REPO_URL = "https://github.com/ryanvmorais/webvigil";
export const SECURITY_DOC_URL = `${REPO_URL}/blob/main/SECURITY.md`;

/**
 * Whether a reference URL may become a link.
 *
 * A finding's references come from the checks, except the ones the opt-in OSV lookup copies from
 * an advisory record that a third party wrote. React escapes an attribute, but a `javascript:` or
 * `data:` value is still a link, so only an absolute `http(s)` URL with a host and no whitespace
 * or control character qualifies (browsers drop tabs and newlines inside a URL). The Python side
 * keeps the same rule in `webvigil.core.urls.is_http_url` (#161).
 *
 * @param value - The reference as the API sent it.
 * @returns `true` when it is safe to render as an `<a href>`.
 */
export function isHttpUrl(value: string): boolean {
  if (/[\s\p{Cc}]/u.test(value)) return false;
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && url.hostname !== "";
  } catch {
    return false;
  }
}
