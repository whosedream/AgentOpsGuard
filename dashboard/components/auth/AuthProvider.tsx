"use client";

import { createContext, useContext } from "react";

import type { AuthContext } from "../../lib/api";

const DashboardAuthContext = createContext<AuthContext | null>(null);

export function DashboardAuthProvider({
  auth,
  children,
}: {
  auth: AuthContext;
  children: React.ReactNode;
}) {
  return <DashboardAuthContext.Provider value={auth}>{children}</DashboardAuthContext.Provider>;
}

export function useDashboardAuth(): AuthContext {
  const value = useContext(DashboardAuthContext);
  if (!value) {
    throw new Error("Dashboard auth context is not available");
  }
  return value;
}
