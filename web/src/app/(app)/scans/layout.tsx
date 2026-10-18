/** Titles the tab for `/scans`; `/scans/new` and `/scans/[id]` set their own below it. */
import type { Metadata } from "next";

import { pageTitle } from "@/lib/page-title";

export const metadata: Metadata = { title: pageTitle("Scans") };

export default function ScansLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
