/** Titles the tab for `/scans/new`. */
import type { Metadata } from "next";

import { pageTitle } from "@/lib/page-title";

export const metadata: Metadata = { title: pageTitle("New scan") };

export default function NewScanLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
