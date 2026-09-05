import type { AuthContext } from "./api";

export const ROLE_ORDER = ["read_only", "developer", "security_reviewer", "admin"] as const;
export type RoleName = (typeof ROLE_ORDER)[number];

export function hasCapability(auth: AuthContext | null | undefined, capability: string): boolean {
  if (!auth) return false;
  if (auth.is_operator || auth.capabilities.includes("admin:*")) return true;
  if (auth.capabilities.includes(capability)) return true;
  const [prefix] = capability.split(":", 1);
  return auth.capabilities.includes(`${prefix}:*`);
}

export function roleRank(role: string | null | undefined): number {
  return Math.max(ROLE_ORDER.indexOf((role ?? "read_only") as RoleName), 0);
}

export function atLeastRole(auth: AuthContext | null | undefined, role: RoleName): boolean {
  if (!auth) return false;
  if (auth.is_operator) return true;
  return roleRank(auth.active_role) >= roleRank(role);
}

export function canManageGovernance(auth: AuthContext): boolean {
  return hasCapability(auth, "policies:admin") || hasCapability(auth, "control:admin");
}

export function canReadGovernance(auth: AuthContext): boolean {
  return canManageGovernance(auth) || atLeastRole(auth, "security_reviewer");
}

export function canReviewApprovals(auth: AuthContext): boolean {
  return hasCapability(auth, "approvals:write");
}

export function canManageMcp(auth: AuthContext): boolean {
  return hasCapability(auth, "mcp:admin");
}

export function canTestMcp(auth: AuthContext): boolean {
  return hasCapability(auth, "mcp:invoke");
}

export function canAccessScanner(auth: AuthContext): boolean {
  return hasCapability(auth, "scanner:read");
}

export function canAccessPolicy(auth: AuthContext): boolean {
  return hasCapability(auth, "policies:read");
}

export function canReadRawContent(auth: AuthContext): boolean {
  return hasCapability(auth, "raw_content:read");
}

export function canReadJobs(auth: AuthContext): boolean {
  return hasCapability(auth, "jobs:read");
}

export function canManageJobs(auth: AuthContext): boolean {
  return hasCapability(auth, "jobs:admin");
}

export function canCreateReplay(auth: AuthContext): boolean {
  return hasCapability(auth, "replays:write");
}

export function canRunEval(auth: AuthContext): boolean {
  return hasCapability(auth, "evals:write");
}
