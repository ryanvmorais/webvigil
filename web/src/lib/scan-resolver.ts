/**
 * Validation for the new-scan form (RF-15..RF-19): a zod schema that mirrors the API's rules
 * and the react-hook-form resolver built on it.
 *
 * This module is the only importer of zod and is loaded with a dynamic `import()` the first
 * time the form validates (see `scan-form.tsx`). Zod is ~100 KiB gzipped; a static import
 * puts it in the initial bundle of `/scans/new` and, through `next/link` prefetching, makes
 * `/scans` download it too. `scan-resolver.test.ts` fails if anything else imports it.
 */
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const TARGET_RE = /^\S+\.\S+$|^https?:\/\/\S+$|^https?:\/\/localhost(:\d+)?(\/\S*)?$/i;

const scanSchema = z
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

/** The form's field values as the inputs hold them (before coercion and defaults). */
export type ScanFormInput = z.input<typeof scanSchema>;

/** The validated values the resolver hands to `onSubmit` (numbers coerced, defaults applied). */
export type ScanFormOutput = z.output<typeof scanSchema>;

/** The react-hook-form resolver for {@link ScanFormInput}. */
export const scanResolver = zodResolver(scanSchema);
