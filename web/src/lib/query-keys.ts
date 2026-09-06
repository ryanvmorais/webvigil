/**
 * One namespaced key factory for every TanStack Query cache entry (RF-04). Mutations
 * invalidate by the broadest prefix they affect (e.g. `["scans"]`).
 */
export type ScanListFilters = { status?: string };
export type FindingFilters = { severity?: string; checkId?: string };

export const keys = {
  auth: {
    me: () => ["auth", "me"] as const,
  },
  setup: () => ["setup"] as const,
  health: () => ["health"] as const,
  checks: () => ["checks"] as const,
  defaults: () => ["config", "defaults"] as const,
  scans: {
    all: () => ["scans"] as const,
    list: (filters: ScanListFilters = {}) => ["scans", "list", filters] as const,
    detail: (id: number) => ["scans", "detail", id] as const,
    findings: (id: number, filters: FindingFilters = {}) =>
      ["scans", "findings", id, filters] as const,
  },
};
