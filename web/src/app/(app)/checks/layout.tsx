/** Titles the tab for `/checks`. */
import type { Metadata } from "next";

import { pageTitle } from "@/lib/page-title";

export const metadata: Metadata = { title: pageTitle("Checks") };

export default function ChecksLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
