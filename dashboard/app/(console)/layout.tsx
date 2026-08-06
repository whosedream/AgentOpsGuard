import { redirect } from "next/navigation";

import { DashboardAuthProvider } from "../../components/auth/AuthProvider";
import { Shell } from "../../components/Shell";
import { serverAuthContext } from "../../lib/server-api";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  try {
    const auth = await serverAuthContext();
    return (
      <DashboardAuthProvider auth={auth}>
        <Shell auth={auth}>{children}</Shell>
      </DashboardAuthProvider>
    );
  } catch (error) {
    const status = typeof error === "object" && error && "status" in error ? Number((error as { status?: number }).status) : 500;
    if (status === 401) {
      redirect("/login");
    }
    throw error;
  }
}
