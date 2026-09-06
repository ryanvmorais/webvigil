/**
 * The one typed wrapper over `fetch` for the Web API (RF-03). Every call is same-origin
 * (`/api/*`, proxied by `next.config` — ADR-3), sends the session cookie
 * (`credentials: "include"`), and turns a non-2xx response into a typed {@link ApiError}.
 * The session cookie is `HttpOnly`; nothing here reads it (RNF-06).
 */
import type { components } from "@/lib/api-types";

type Schemas = components["schemas"];

export type UserOut = Schemas["UserOut"];
export type HealthOut = Schemas["HealthOut"];
export type CheckOut = Schemas["CheckOut"];
export type ScanDefaults = Schemas["ScanDefaults"];
export type ScanSummary = Schemas["ScanSummary"];
export type ScanOut = Schemas["ScanOut"];
export type FindingOut = Schemas["FindingOut"];
export type LocationOut = Schemas["LocationOut"];
export type EvidenceOut = Schemas["EvidenceOut"];
export type ScanCreate = Schemas["ScanCreate"];
export type ScanPage = Schemas["Page_ScanSummary_"];
export type ScanMode = Schemas["ScanMode"];
export type Scope = Schemas["Scope"];
export type ScanStatus = Schemas["ScanStatus"];
export type ValidationItem = Schemas["ValidationError"];

export const SCAN_STATUSES: readonly ScanStatus[] = [
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
  "interrupted",
];

export const TERMINAL_STATUSES: ReadonlySet<ScanStatus> = new Set<ScanStatus>([
  "completed",
  "failed",
  "cancelled",
  "interrupted",
]);

export const REPORTABLE_STATUSES: ReadonlySet<ScanStatus> = new Set<ScanStatus>([
  "completed",
  "interrupted",
]);

export const REPORT_FORMATS = ["json", "sarif", "html", "md"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export type SetupStatus = { needs_setup: boolean };

/** Thrown for any non-2xx response. `detail` is the FastAPI `{ detail }` payload. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: string | ValidationItem[];

  constructor(status: number, detail: string | ValidationItem[]) {
    super(typeof detail === "string" ? detail : "validation error");
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

type Json = Record<string, unknown> | unknown[] | null;

async function parseBody(res: Response): Promise<Json> {
  if (res.status === 204) return null;
  return (await res.json().catch(() => null)) as Json;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "include",
    headers:
      init?.body === undefined
        ? init?.headers
        : { "content-type": "application/json", ...init?.headers },
  });
  const body = await parseBody(res);
  if (!res.ok) {
    const detail = (body as { detail?: string | ValidationItem[] } | null)?.detail;
    throw new ApiError(res.status, detail ?? res.statusText);
  }
  if (res.status === 204) return undefined as T;
  return body as T;
}

async function requestBlob(path: string): Promise<Blob> {
  const res = await fetch(path, { credentials: "include" });
  if (!res.ok) {
    const detail = ((await res.json().catch(() => null)) as { detail?: string } | null)?.detail;
    throw new ApiError(res.status, detail ?? res.statusText);
  }
  return res.blob();
}

/** Map a 422 `ApiError` to `{ field: message }` keyed by the last path segment of `loc`. */
export function fieldErrors(err: unknown): Record<string, string> {
  if (!(err instanceof ApiError) || typeof err.detail === "string") return {};
  const out: Record<string, string> = {};
  for (const item of err.detail) {
    const field = item.loc.filter((seg) => seg !== "body").at(-1);
    if (field !== undefined && out[String(field)] === undefined) {
      out[String(field)] = item.msg;
    }
  }
  return out;
}

/** The single generic message for an error, for toasts and full-page states. */
export function errorMessage(err: unknown, fallback = "Something went wrong."): string {
  if (err instanceof ApiError) {
    return typeof err.detail === "string" ? err.detail : (err.detail[0]?.msg ?? fallback);
  }
  return err instanceof Error ? err.message : fallback;
}

function query(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined && value !== "") search.set(key, String(value));
  }
  const str = search.toString();
  return str ? `?${str}` : "";
}

export type ScanListParams = { status?: ScanStatus; limit?: number; cursor?: string };

export const api = {
  // --- setup / auth ---
  setupStatus: () => request<SetupStatus>("/api/setup"),
  setup: (body: Schemas["SetupIn"]) =>
    request<UserOut>("/api/setup", { method: "POST", body: JSON.stringify(body) }),
  login: (body: Schemas["LoginIn"]) =>
    request<void>("/api/auth/login", { method: "POST", body: JSON.stringify(body) }),
  logout: () => request<void>("/api/auth/logout", { method: "POST" }),
  me: () => request<UserOut>("/api/auth/me"),
  changePassword: (body: Schemas["PasswordChangeIn"]) =>
    request<void>("/api/auth/password", { method: "POST", body: JSON.stringify(body) }),

  // --- meta ---
  health: () => request<HealthOut>("/api/health"),
  checks: () => request<CheckOut[]>("/api/checks"),
  defaults: () => request<ScanDefaults>("/api/config/defaults"),

  // --- scans ---
  listScans: (params: ScanListParams = {}) =>
    request<ScanPage>(`/api/scans${query({ limit: 20, ...params })}`),
  createScan: (body: ScanCreate) =>
    request<ScanOut>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  getScan: (id: number) => request<ScanOut>(`/api/scans/${id}`),
  cancelScan: (id: number) => request<void>(`/api/scans/${id}/cancel`, { method: "POST" }),
  deleteScan: (id: number) => request<void>(`/api/scans/${id}`, { method: "DELETE" }),
  findings: (id: number, params: { severity?: string; check_id?: string } = {}) =>
    request<FindingOut[]>(`/api/scans/${id}/findings${query(params)}`),

  // --- reports ---
  reportUrl: (id: number, format: ReportFormat, download: boolean) =>
    `/api/scans/${id}/report${query({ format, download })}`,
  reportBlob: (id: number) =>
    requestBlob(`/api/scans/${id}/report${query({ format: "html", download: false })}`),
};
