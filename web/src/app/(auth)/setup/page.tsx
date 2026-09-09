/**
 * `/setup` (RF-06) — first-run: create the single admin account. Client-side checks
 * mirror the API; a 409 means setup already ran (links to `/login`).
 */
"use client";

import Link from "next/link";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSetup } from "@/hooks/use-auth";
import { ApiError, fieldErrors } from "@/lib/api";

export default function SetupPage() {
  const setup = useSetup();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [localError, setLocalError] = useState<Record<string, string>>({});

  const alreadyDone = setup.error instanceof ApiError && setup.error.status === 409;
  const serverFields = setup.error instanceof ApiError ? fieldErrors(setup.error) : {};
  const errors = { ...serverFields, ...localError };

  function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    const next: Record<string, string> = {};
    if (username.length < 1 || username.length > 64) next.username = "1–64 characters.";
    if (password.length < 8) next.password = "At least 8 characters.";
    if (confirm !== password) next.confirm = "Passwords do not match.";
    setLocalError(next);
    if (Object.keys(next).length === 0) setup.mutate({ username, password });
  }

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-xl font-semibold">Create your account</h1>
        <p className="text-muted-foreground text-sm">
          WebVigil is single-user. This is the only account.
        </p>
      </div>

      {alreadyDone ? (
        <p className="border-border bg-muted rounded-md border p-3 text-sm" role="alert">
          Setup is already complete.{" "}
          <Link href="/login" className="font-medium underline">
            Go to sign in
          </Link>
          .
        </p>
      ) : null}

      <form onSubmit={onSubmit} noValidate className="space-y-4">
        <Field id="username" label="Username" error={errors.username}>
          <Input
            id="username"
            value={username}
            autoComplete="username"
            onChange={(e) => setUsername(e.target.value)}
          />
        </Field>
        <Field id="password" label="Password" error={errors.password}>
          <Input
            id="password"
            type="password"
            value={password}
            autoComplete="new-password"
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Field id="confirm" label="Confirm password" error={errors.confirm}>
          <Input
            id="confirm"
            type="password"
            value={confirm}
            autoComplete="new-password"
            onChange={(e) => setConfirm(e.target.value)}
          />
        </Field>

        {setup.isError && !alreadyDone && Object.keys(serverFields).length === 0 ? (
          <p className="text-destructive text-sm" role="alert">
            Could not create the account. Try again.
          </p>
        ) : null}

        <Button type="submit" className="w-full" disabled={setup.isPending}>
          Create account
        </Button>
      </form>
    </div>
  );
}

function Field({
  id,
  label,
  error,
  children,
}: {
  id: string;
  label: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {error ? (
        <p id={`${id}-error`} className="text-destructive text-sm">
          {error}
        </p>
      ) : null}
    </div>
  );
}
