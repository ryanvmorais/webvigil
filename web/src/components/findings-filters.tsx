/**
 * The filters above a scan's findings (RF-23): a text search, a minimum severity and a check. All
 * three live in the URL and run on the server, so they cover every page of findings, not only the
 * rows already loaded (S-46).
 */
"use client";

import { useEffect, useState } from "react";

import { FieldSelect } from "@/components/field-select";
import { Input } from "@/components/ui/input";
import { useFindingChecks } from "@/hooks/use-findings";
import { useQueryParams } from "@/hooks/use-query-param";
import { SEVERITY_LABEL, SEVERITY_NAMES } from "@/lib/severity";

const ALL = "all";
/** Typing pauses this long before the search reaches the URL, so each keystroke is not a request. */
const SEARCH_DELAY_MS = 300;
/** The API refuses a longer search (`_SEARCH_MAX_LENGTH` in `api/routes/scans.py`). */
const SEARCH_MAX_LENGTH = 200;

/**
 * Search, minimum-severity and check filters for one scan's findings.
 *
 * @param scanId - The scan whose checks fill the Check list.
 */
export function FindingsFilters({ scanId }: { scanId: number }) {
  const { search, setParams } = useQueryParams();
  const checks = useFindingChecks(scanId);

  const severity = search.get("severity") ?? ALL;
  const checkId = search.get("check_id") ?? ALL;
  const urlQuery = search.get("q") ?? "";
  const [text, setText] = useState(urlQuery);

  useEffect(() => {
    const next = text.trim();
    if (next === urlQuery) return;
    const timer = setTimeout(() => setParams({ q: next || null }), SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [text, urlQuery, setParams]);

  // Only the checks that found something in this scan, so a choice never leads to an empty
  // table. A check id from a shared link that this scan does not have still shows, with 0.
  const counts = checks.data ?? [];
  const checkOptions = counts.map((item) => ({
    value: item.check_id,
    label: `${item.check_id} (${item.count})`,
  }));
  if (checkId !== ALL && !counts.some((item) => item.check_id === checkId)) {
    checkOptions.push({ value: checkId, label: `${checkId} (0)` });
  }

  return (
    <div className="flex flex-wrap gap-3">
      <Input
        type="search"
        aria-label="Search findings"
        placeholder="Search title, URL, parameter"
        maxLength={SEARCH_MAX_LENGTH}
        value={text}
        onChange={(event) => setText(event.target.value)}
        className="w-full sm:w-[260px]"
      />
      <FieldSelect
        label="Minimum severity"
        className="w-full sm:w-[180px]"
        value={severity}
        onValueChange={(next) => setParams({ severity: next === ALL ? null : next })}
        options={[
          { value: ALL, label: "Any severity" },
          ...SEVERITY_NAMES.map((name) => ({ value: name, label: SEVERITY_LABEL[name] })),
        ]}
      />
      <FieldSelect
        label="Check"
        className="w-full sm:w-[260px]"
        value={checkId}
        onValueChange={(next) => setParams({ check_id: next === ALL ? null : next })}
        options={[{ value: ALL, label: "All checks" }, ...checkOptions]}
      />
    </div>
  );
}
