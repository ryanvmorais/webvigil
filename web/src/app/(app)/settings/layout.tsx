/** Titles the tab for `/settings`. */
import type { Metadata } from "next";

import { pageTitle } from "@/lib/page-title";

export const metadata: Metadata = { title: pageTitle("Settings") };

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
