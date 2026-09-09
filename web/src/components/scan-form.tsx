/**
 * The new-scan form (RF-15..RF-19): react-hook-form + a zod schema that mirrors the API's
 * validation, pre-filled from `GET /api/config/defaults`. Active mode reveals the
 * "authorized by" field and a warning. Server-side field errors merge back onto the form.
 */
"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { AlertTriangle } from "lucide-react";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { DisabledChecksField } from "@/components/disabled-checks-field";
import { FieldSelect } from "@/components/field-select";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { useCreateScan } from "@/hooks/use-scans";
import { useScanDefaults } from "@/hooks/use-defaults";
import { ApiError, fieldErrors, type ScanCreate } from "@/lib/api";
import { SECURITY_DOC_URL } from "@/lib/links";

const TARGET_RE = /^\S+\.\S+$|^https?:\/\/\S+$|^https?:\/\/localhost(:\d+)?(\/\S*)?$/i;

const schema = z
  .object({
    target: z
      .string()
      .trim()
      .min(1, "Target is required.")
      .regex(TARGET_RE, "Enter a URL like https://example.com."),
    mode: z.enum(["passive", "active"]),
    scope: z.enum(["host", "subdomains"]),
    max_pages: z.coerce.number().int().positive("Must be greater than 0."),
    delay_ms: z.coerce.number().int().min(0, "Cannot be negative."),
    follow_robots: z.boolean(),
    authorized_by: z.string().trim().max(200).optional().default(""),
    disabled_checks: z.array(z.string()),
  })
  .refine((values) => values.mode !== "active" || values.authorized_by.trim().length > 0, {
    path: ["authorized_by"],
    message: "Active scans require an authorization attestation.",
  });

type FormValues = z.input<typeof schema>;

const FALLBACK: FormValues = {
  target: "",
  mode: "passive",
  scope: "host",
  max_pages: 50,
  delay_ms: 200,
  follow_robots: true,
  authorized_by: "",
  disabled_checks: [],
};

export function ScanForm() {
  const defaults = useScanDefaults();
  const createScan = useCreateScan();

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: FALLBACK,
  });

  useEffect(() => {
    if (!defaults.data) return;
    form.reset({
      ...FALLBACK,
      target: form.getValues("target"),
      mode: defaults.data.mode === "active" ? "active" : "passive",
      scope: defaults.data.scope === "subdomains" ? "subdomains" : "host",
      max_pages: defaults.data.max_pages,
      delay_ms: defaults.data.delay_ms,
      follow_robots: defaults.data.follow_robots,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [defaults.data]);

  // react-hook-form's watch() is opaque to the React Compiler lint; it is the
  // library's supported subscription API and there is no compiler-friendly form.
  // eslint-disable-next-line react-hooks/incompatible-library
  const mode = form.watch("mode");

  function onSubmit(values: FormValues) {
    const parsed = schema.parse(values);
    const body: ScanCreate = {
      target: parsed.target,
      mode: parsed.mode,
      scope: parsed.scope,
      max_pages: parsed.max_pages,
      delay_ms: parsed.delay_ms,
      follow_robots: parsed.follow_robots,
      disabled_checks: parsed.disabled_checks,
      ...(parsed.mode === "active" ? { authorized_by: parsed.authorized_by } : {}),
    };
    createScan.mutate(body, {
      onError: (error) => {
        if (error instanceof ApiError) {
          for (const [field, message] of Object.entries(fieldErrors(error))) {
            form.setError(field as keyof FormValues, { message });
          }
        }
      },
    });
  }

  const genericError =
    createScan.isError &&
    (!(createScan.error instanceof ApiError) ||
      Object.keys(fieldErrors(createScan.error)).length === 0);

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="max-w-2xl space-y-6">
        <FormField
          control={form.control}
          name="target"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Target</FormLabel>
              <FormControl>
                <Input placeholder="https://example.com" autoComplete="off" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="mode"
            render={({ field }) => (
              <FormItem>
                <FormLabel htmlFor="scan-mode">Mode</FormLabel>
                <FieldSelect
                  id="scan-mode"
                  label="Mode"
                  value={field.value}
                  onValueChange={field.onChange}
                  options={[
                    { value: "passive", label: "Passive (safe, default)" },
                    { value: "active", label: "Active (intrusive)" },
                  ]}
                />
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="scope"
            render={({ field }) => (
              <FormItem>
                <FormLabel htmlFor="scan-scope">Scope</FormLabel>
                <FieldSelect
                  id="scan-scope"
                  label="Scope"
                  value={field.value}
                  onValueChange={field.onChange}
                  options={[
                    { value: "host", label: "This host only" },
                    { value: "subdomains", label: "Host + subdomains" },
                  ]}
                />
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {mode === "active" ? (
          <>
            <div
              role="alert"
              className="border-severity-high/50 bg-severity-high/5 flex gap-2 rounded-md border p-3 text-sm"
            >
              <AlertTriangle className="text-severity-high mt-0.5 size-4 shrink-0" aria-hidden />
              <div>
                Active scans send potentially intrusive traffic. Only run them against systems you
                are authorized to test.{" "}
                <a
                  href={SECURITY_DOC_URL}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="font-medium underline"
                >
                  Read the guidance
                </a>
                .
              </div>
            </div>
            <FormField
              control={form.control}
              name="authorized_by"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Authorized by</FormLabel>
                  <FormControl>
                    <Input placeholder="name / engagement reference" {...field} />
                  </FormControl>
                  <FormDescription>Recorded in every report for this scan.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        ) : null}

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="max_pages"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Max pages</FormLabel>
                <FormControl>
                  <Input type="number" min={1} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="delay_ms"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Delay between requests (ms)</FormLabel>
                <FormControl>
                  <Input type="number" min={0} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="follow_robots"
          render={({ field }) => (
            <FormItem>
              <label className="flex items-center gap-2 text-sm font-medium">
                <input
                  type="checkbox"
                  className="size-4"
                  checked={field.value}
                  onChange={(event) => field.onChange(event.target.checked)}
                />
                Follow robots.txt
              </label>
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="disabled_checks"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Checks to disable for this scan</FormLabel>
              <DisabledChecksField value={field.value} onChange={field.onChange} />
            </FormItem>
          )}
        />

        <p className="text-muted-foreground text-sm">
          fail-on: <span className="font-medium">{defaults.data?.fail_on ?? "medium"}</span>{" "}
          (informational — the API has no exit code).
        </p>

        {genericError ? (
          <p className="text-destructive text-sm" role="alert">
            Could not start the scan. Check the fields and try again.
          </p>
        ) : null}

        <Button type="submit" disabled={createScan.isPending}>
          Start scan
        </Button>
      </form>
    </Form>
  );
}
