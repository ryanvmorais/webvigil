/** `/settings` — the API version (RF-30), the change-password form, and logout. */
"use client";

import { useState } from "react";

import { LogoutButton } from "@/components/logout-button";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useChangePassword, useHealth } from "@/hooks/use-auth";
import { ApiError } from "@/lib/api";

export default function SettingsPage() {
  const health = useHealth();
  const changePassword = useChangePassword();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const wrongCurrent =
    changePassword.error instanceof ApiError && changePassword.error.status === 403;
  const otherError = changePassword.isError && !wrongCurrent;

  function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setDone(false);
    if (next.length < 8) {
      setLocalError("The new password must be at least 8 characters.");
      return;
    }
    if (next !== confirm) {
      setLocalError("The new passwords do not match.");
      return;
    }
    setLocalError(null);
    changePassword.mutate(
      { current_password: current, new_password: next },
      {
        onSuccess: () => {
          setCurrent("");
          setNext("");
          setConfirm("");
          setDone(true);
        },
      },
    );
  }

  return (
    <div className="max-w-md space-y-8">
      <h1 className="text-xl font-semibold">Settings</h1>

      <section className="space-y-4">
        <h2 className="text-lg font-semibold">Change password</h2>
        <form onSubmit={onSubmit} noValidate className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="current">Current password</Label>
            <Input
              id="current"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
            {wrongCurrent ? (
              <p className="text-sm text-destructive">Current password is incorrect.</p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new">New password</Label>
            <Input
              id="new"
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="confirm">Confirm new password</Label>
            <Input
              id="confirm"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </div>

          {localError ? <p className="text-sm text-destructive">{localError}</p> : null}
          {otherError ? (
            <p className="text-sm text-destructive" role="alert">
              Could not change the password. Try again.
            </p>
          ) : null}
          {done ? (
            <p className="text-sm text-emerald-600" role="status">
              Password changed.
            </p>
          ) : null}

          <Button type="submit" disabled={changePassword.isPending}>
            Change password
          </Button>
        </form>
      </section>

      <section className="space-y-2">
        <h2 className="text-lg font-semibold">About</h2>
        <p className="text-sm text-muted-foreground">API version: {health.data?.version ?? "…"}</p>
        <LogoutButton variant="outline" />
      </section>
    </div>
  );
}
