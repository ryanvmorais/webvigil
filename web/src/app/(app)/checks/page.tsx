"use client";

import { useMemo, useState } from "react";

import { ChecksTable } from "@/components/checks-table";
import { Empty, FullPageSpinner, LoadFailed } from "@/components/error-states";
import { FieldSelect } from "@/components/field-select";
import { useChecks } from "@/hooks/use-checks";

export default function ChecksPage() {
  const query = useChecks();
  const [category, setCategory] = useState("all");
  const [mode, setMode] = useState("all");

  const categories = useMemo(
    () => Array.from(new Set(query.data?.map((check) => check.category) ?? [])).sort(),
    [query.data],
  );

  if (query.isLoading) return <FullPageSpinner />;
  if (query.isError) {
    return (
      <LoadFailed message="Could not load the check catalogue." onRetry={() => query.refetch()} />
    );
  }

  const checks = query.data ?? [];

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Check catalogue</h1>
      <p className="text-sm text-muted-foreground">
        {checks.length} checks. These are the same checks the scan form can disable per scan.
      </p>

      <div className="flex flex-wrap gap-3">
        <FieldSelect
          label="Filter by category"
          className="w-[190px]"
          value={category}
          onValueChange={setCategory}
          options={[
            { value: "all", label: "All categories" },
            ...categories.map((value) => ({ value, label: value })),
          ]}
        />
        <FieldSelect
          label="Filter by mode"
          className="w-[190px]"
          value={mode}
          onValueChange={setMode}
          options={[
            { value: "all", label: "All modes" },
            { value: "passive", label: "Passive" },
            { value: "active", label: "Active" },
          ]}
        />
      </div>

      {checks.length === 0 ? (
        <Empty title="No checks registered" />
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <ChecksTable checks={checks} category={category} mode={mode} />
        </div>
      )}
    </div>
  );
}
