/** Layout for the authenticated `(app)` routes: `<AuthGuard>` gate wrapped in `<AppShell>` chrome. */
import { AppShell } from "@/components/app-shell";
import { AuthGuard } from "@/components/auth-guard";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <AppShell>{children}</AppShell>
    </AuthGuard>
  );
}
