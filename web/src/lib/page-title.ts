/**
 * The one place that spells a tab title (WCAG 2.4.2): "<page> | WebVigil".
 *
 * Next's `title.template` is not used because it only reaches the segment right below the one
 * that declares it: a nested route (`/scans/new`) lost the suffix in the first measurement.
 */

export const APP_NAME = "WebVigil";

/**
 * The full tab title of a page.
 *
 * @param page - What the page is: "Scans", "New scan", or a scan's target address.
 * @returns The title with the app name after it.
 */
export function pageTitle(page: string): string {
  return `${page} | ${APP_NAME}`;
}
