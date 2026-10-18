/** Titles the tab for `/setup`. */
import type { Metadata } from "next";

import { pageTitle } from "@/lib/page-title";

export const metadata: Metadata = { title: pageTitle("Create account") };

export default function SetupLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
