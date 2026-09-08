/**
 * Root layout: the `<html>`/`<body>` shell, the global stylesheet, and `<Providers>`
 * (the one client boundary — everything below it can be a Client Component).
 */
import type { Metadata } from "next";

import { Providers } from "@/components/providers";

import "./globals.css";

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
