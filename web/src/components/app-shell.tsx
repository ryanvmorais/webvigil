"use client";

import { Menu, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { LogoutButton } from "@/components/logout-button";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/scans", label: "Scans" },
  { href: "/checks", label: "Checks" },
  { href: "/settings", label: "Settings" },
];

function isActive(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen">
      <header className="border-b">
        <div className="container flex h-14 items-center gap-4">
          <Link href="/scans" className="flex items-center gap-2 font-semibold">
            <ShieldCheck className="size-5 text-primary" aria-hidden />
            WebVigil
          </Link>

          <nav aria-label="Primary" className="hidden flex-1 items-center gap-1 sm:flex">
            {NAV.map((item) => (
              <Button
                key={item.href}
                asChild
                variant="ghost"
                size="sm"
                className={cn(isActive(pathname, item.href) && "bg-accent text-accent-foreground")}
              >
                <Link
                  href={item.href}
                  aria-current={isActive(pathname, item.href) ? "page" : undefined}
                >
                  {item.label}
                </Link>
              </Button>
            ))}
          </nav>

          <div className="ml-auto hidden sm:block">
            <LogoutButton />
          </div>

          <div className="ml-auto sm:hidden">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" aria-label="Open menu">
                  <Menu className="size-5" aria-hidden />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {NAV.map((item) => (
                  <DropdownMenuItem key={item.href} asChild>
                    <Link href={item.href}>{item.label}</Link>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
        <div className="container pb-2 sm:hidden">
          <LogoutButton className="px-0" />
        </div>
      </header>

      <main className="container overflow-x-auto py-6">{children}</main>
    </div>
  );
}
