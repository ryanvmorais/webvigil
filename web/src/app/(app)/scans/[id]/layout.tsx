/**
 * Titles the tab for `/scans/[id]` until the scan loads; the page then puts the target in the
 * title (`useDocumentTitle`), which only the client knows.
 */
import type { Metadata } from "next";

import { pageTitle } from "@/lib/page-title";

export const metadata: Metadata = { title: pageTitle("Scan") };

export default function ScanDetailLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
