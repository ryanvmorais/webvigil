"use client";

import { LogOut } from "lucide-react";

import { Button } from "@/components/ui/button";
import { useLogout } from "@/hooks/use-auth";

export function LogoutButton({
  variant = "ghost",
  className,
}: {
  variant?: React.ComponentProps<typeof Button>["variant"];
  className?: string;
}) {
  const logout = useLogout();
  return (
    <Button
      variant={variant}
      size="sm"
      className={className}
      onClick={() => logout.mutate()}
      disabled={logout.isPending}
    >
      <LogOut className="size-4" aria-hidden />
      Log out
    </Button>
  );
}
