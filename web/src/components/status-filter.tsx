"use client";

import { FieldSelect } from "@/components/field-select";
import { statusLabel } from "@/components/status-badge";
import { useQueryParams } from "@/hooks/use-query-param";
import { SCAN_STATUSES } from "@/lib/api";

const ALL = "all";

const OPTIONS = [
  { value: ALL, label: "All statuses" },
  ...SCAN_STATUSES.map((status) => ({ value: status, label: statusLabel(status) })),
];

/** Status filter for the scan list; the choice lives in `?status=` (RF-12). */
export function StatusFilter() {
  const { search, setParams } = useQueryParams();
  const value = search.get("status") ?? ALL;

  return (
    <FieldSelect
      label="Filter by status"
      className="w-[190px]"
      value={value}
      onValueChange={(next) => setParams({ status: next === ALL ? null : next })}
      options={OPTIONS}
    />
  );
}
