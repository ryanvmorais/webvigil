/**
 * The 404 for any URL no route matches. It lives outside the `(app)` shell (an unknown URL has
 * no session context), so it brings its own `<main>` and reuses the "not found" placeholder of
 * the scan pages, with a way back, instead of the bare Next default.
 */
import type { Metadata } from "next";

import { NotFound } from "@/components/error-states";
import { pageTitle } from "@/lib/page-title";

export const metadata: Metadata = { title: pageTitle("Page not found") };

export default function NotFoundPage() {
  return (
    <main className="grid min-h-screen place-items-center p-4">
      <NotFound title="Page not found" message="There is nothing at this address." />
    </main>
  );
}
