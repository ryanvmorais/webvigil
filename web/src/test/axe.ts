import { configureAxe } from "jest-axe";

/**
 * Component-level renders have no `<html>`/`<main>` wrapper, so the page-structure rules
 * do not apply here (they are covered by the layouts and the Playwright run). Everything
 * else — labels, names, roles, contrast — stays on.
 */
export const axe = configureAxe({
  rules: {
    region: { enabled: false },
    "landmark-one-main": { enabled: false },
    "page-has-heading-one": { enabled: false },
    "html-has-lang": { enabled: false },
    "document-title": { enabled: false },
  },
});

export function noSeriousViolations(results: Awaited<ReturnType<typeof axe>>) {
  return results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
}
