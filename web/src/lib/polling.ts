/**
 * `refetchInterval` helpers (RF-13, RF-21, ADR-5). Polling runs only while the tab is
 * visible and something on screen is still non-terminal; otherwise it is off.
 */
import { TERMINAL_STATUSES } from "@/lib/api";

export const LIST_POLL_MS = 3000;
export const DETAIL_POLL_MS = 2000;

function tabVisible(): boolean {
  return typeof document === "undefined" || document.visibilityState === "visible";
}

function isTerminal(status: string): boolean {
  return TERMINAL_STATUSES.has(status as never);
}

/** Poll the scan list while any loaded row is queued/running. */
export function listInterval(statuses: string[]): number | false {
  if (!tabVisible()) return false;
  return statuses.some((status) => !isTerminal(status)) ? LIST_POLL_MS : false;
}

/** Poll one scan until it reaches a terminal status. */
export function detailInterval(status: string | undefined): number | false {
  if (!tabVisible() || status === undefined) return false;
  return isTerminal(status) ? false : DETAIL_POLL_MS;
}
