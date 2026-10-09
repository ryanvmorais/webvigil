/**
 * Root layout: the `<html>`/`<body>` shell, the global stylesheet, and `<Providers>`
 * (the one client boundary — everything below it can be a Client Component). It also opts the
 * whole tree into per-request rendering, which the Content-Security-Policy nonce needs (spec 022).
 */
import type { Metadata } from "next";

import { Providers } from "@/components/providers";

import "./globals.css";

// A nonce exists only for a rendered request (`src/proxy.ts`): a prerendered page would ship
// scripts the policy refuses. Declared once here, in the layout every route shares, so a page
// written later cannot forget it (spec 022 RF-07, ADR-3).
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "WebVigil",
  description: "Dashboard for the WebVigil web vulnerability scanner",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
