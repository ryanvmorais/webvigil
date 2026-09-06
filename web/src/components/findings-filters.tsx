"use client";

import { FieldSelect } from "@/components/field-select";
import { useChecks } from "@/hooks/use-checks";
import { useQueryParams } from "@/hooks/use-query-param";
import { SEVERITY_LABEL, SEVERITY_NAMES } from "@/lib/severity";

const ALL = "all";

/** Minimum-severity and check-id filters for the findings table; both live in the URL (RF-23). */
export function FindingsFilters() {
  const { search, setParams } = useQueryParams();
  const checks = useChecks();

  const severity = search.get("severity") ?? ALL;
  const checkId = search.get("check_id") ?? ALL;

  return (
    <div className="flex flex-wrap gap-3">
      <FieldSelect
        label="Minimum severity"
        className="w-[180px]"
        value={severity}
        onValueChange={(next) => setParams({ severity: next === ALL ? null : next })}
        options={[
          { value: ALL, label: "Any severity" },
          ...SEVERITY_NAMES.map((name) => ({ value: name, label: SEVERITY_LABEL[name] })),
        ]}
      />
      <FieldSelect
        label="Check"
        className="w-[200px]"
        value={checkId}
        onValueChange={(next) => setParams({ check_id: next === ALL ? null : next })}
        options={[
          { value: ALL, label: "All checks" },
          ...(checks.data ?? []).map((check) => ({ value: check.id, label: check.id })),
        ]}
      />
    </div>
  );
}
