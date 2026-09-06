import type { CheckOut, FindingOut, ScanOut, ScanSummary } from "@/lib/api";

let seq = 0;
const nextId = () => (seq += 1);

export function makeScanSummary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    id: nextId(),
    target: "https://example.com/",
    mode: "passive",
    scope: "host",
    status: "completed",
    counts: { INFO: 0, LOW: 1, MEDIUM: 0, HIGH: 2, CRITICAL: 0 },
    created_at: "2026-09-06T12:00:00Z",
    started_at: "2026-09-06T12:00:01Z",
    finished_at: "2026-09-06T12:00:09Z",
    ...overrides,
  };
}

export function makeScanOut(overrides: Partial<ScanOut> = {}): ScanOut {
  return {
    ...makeScanSummary(),
    authorized_by: null,
    tool_version: "0.2.0",
    error: null,
    pages_scanned: 3,
    options: { max_pages: 50, delay_ms: 200, follow_robots: true },
    ...overrides,
  };
}

export function makeFinding(overrides: Partial<FindingOut> = {}): FindingOut {
  return {
    check_id: "headers.csp",
    severity: "MEDIUM",
    confidence: "HIGH",
    title: "Content-Security-Policy header missing",
    description: "The response did not set a Content-Security-Policy header.",
    location: {
      url: "https://example.com/",
      method: "GET",
      param: null,
      header: null,
      cookie: null,
    },
    remediation: "Set a restrictive Content-Security-Policy.",
    evidence: [{ label: "Response headers", content: "server: nginx" }],
    cwe: [693],
    references: ["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
    fingerprint: `fp-${nextId()}`,
    ...overrides,
  };
}

export function makeCheck(overrides: Partial<CheckOut> = {}): CheckOut {
  return {
    id: "headers.csp",
    name: "Content-Security-Policy",
    category: "HEADERS",
    mode: "passive",
    default_severity: "MEDIUM",
    cwe: [693],
    references: ["https://owasp.org/www-project-secure-headers/"],
    ...overrides,
  };
}
