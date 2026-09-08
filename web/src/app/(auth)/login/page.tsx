/**
 * `/login` (RF-07): username + password. A 401 clears the password and shows an inline
 * error; on success `useLogin` redirects to `?next=` or `/scans`. `<Suspense>`-wrapped
 * for `useSearchParams`.
 */
"use client";

import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { FullPageSpinner } from "@/components/error-states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useLogin } from "@/hooks/use-auth";
import { ApiError } from "@/lib/api";

function LoginForm() {
  const login = useLogin();
  const search = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const invalidCredentials = login.error instanceof ApiError && login.error.status === 401;
  const otherError = login.isError && !invalidCredentials;

  function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    login.mutate({ username, password }, { onError: () => setPassword("") });
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Sign in</h1>

      {search.get("setup") === "done" ? (
        <p className="rounded-md border border-border bg-muted p-3 text-sm" role="status">
          Account created. Sign in to continue.
        </p>
      ) : null}
      {search.get("reason") === "expired" ? (
        <p className="rounded-md border border-border bg-muted p-3 text-sm" role="status">
          Your session expired. Sign in again.
        </p>
      ) : null}

      <form onSubmit={onSubmit} noValidate className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="username">Username</Label>
          <Input
            id="username"
            value={username}
            autoComplete="username"
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            value={password}
            autoComplete="current-password"
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {invalidCredentials ? (
          <p className="text-sm text-destructive" role="alert">
            Invalid username or password.
          </p>
        ) : null}
        {otherError ? (
          <p className="text-sm text-destructive" role="alert">
            Could not sign in. Try again.
          </p>
        ) : null}

        <Button type="submit" className="w-full" disabled={login.isPending}>
          Sign in
        </Button>
      </form>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<FullPageSpinner />}>
      <LoginForm />
    </Suspense>
  );
}
