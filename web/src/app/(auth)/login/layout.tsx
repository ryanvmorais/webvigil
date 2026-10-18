/** Titles the tab for `/login`. */
import type { Metadata } from "next";

import { pageTitle } from "@/lib/page-title";

export const metadata: Metadata = { title: pageTitle("Sign in") };

export default function LoginLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
