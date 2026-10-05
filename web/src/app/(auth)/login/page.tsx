/**
 * `/login` (RF-07): username + password. A 401 clears the password and shows an inline
 * error; on success `useLogin` redirects to `?next=` or `/scans`.
 *
 * The form itself reads no search params, so it is in the prerendered HTML at its real
 * height. Only the notices (`?setup=done`, `?reason=expired`) need `useSearchParams`; they
 * live in their own `<Suspense fallback={null}>`, which adds nothing to the layout until
 * a notice actually shows.
 */
"use client";

import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useLogin } from "@/hooks/use-auth";
import { ApiError } from "@/lib/api";

function LoginNotices() {
  const search = useSearchParams();
  return (
    <>
      {search.get("setup") === "done" ? (
        <p className="border-border bg-muted rounded-md border p-3 text-sm" role="status">
          Account created. Sign in to continue.
        </p>
      ) : null}
      {search.get("reason") === "expired" ? (
        <p className="border-border bg-muted rounded-md border p-3 text-sm" role="status">
          Your session expired. Sign in again.
        </p>
      ) : null}
    </>
  );
}

function LoginForm() {
  const login = useLogin();
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

      <Suspense fallback={null}>
        <LoginNotices />
      </Suspense>

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
          <p className="text-destructive text-sm" role="alert">
            Invalid username or password.
          </p>
        ) : null}
        {otherError ? (
          <p className="text-destructive text-sm" role="alert">
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
  return <LoginForm />;
}
