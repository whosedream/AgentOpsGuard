import Link from "next/link";
import { Activity, Bot, BriefcaseBusiness, ClipboardCheck, FileWarning, FolderKanban, LayoutDashboard, LogOut, ScanSearch, Shield, TestTubeDiagonal, Wrench } from "lucide-react";

import type { AuthContext } from "../lib/api";
import { atLeastRole, canAccessPolicy, canAccessScanner, canReadGovernance, canTestMcp } from "../lib/auth";
import { LogoutButton } from "./auth/LogoutButton";

type NavItem = {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  visible: (auth: AuthContext) => boolean;
};

const navItems: NavItem[] = [
  { label: "Overview", href: "/", icon: LayoutDashboard, visible: () => true },
  { label: "Setup", href: "/setup", icon: Activity, visible: () => true },
  { label: "Runs", href: "/runs", icon: Bot, visible: () => true },
  { label: "Risks", href: "/risks", icon: FileWarning, visible: () => true },
  { label: "Replays", href: "/replays", icon: ClipboardCheck, visible: () => true },
  { label: "Evals", href: "/evals", icon: TestTubeDiagonal, visible: () => true },
  { label: "Scanner", href: "/scanner", icon: ScanSearch, visible: (auth) => canAccessScanner(auth) },
  { label: "Policy", href: "/policy", icon: Shield, visible: (auth) => canAccessPolicy(auth) },
  { label: "Governance", href: "/governance", icon: FolderKanban, visible: (auth) => canReadGovernance(auth) },
  { label: "MCP", href: "/mcp", icon: Wrench, visible: (auth) => canTestMcp(auth) && atLeastRole(auth, "developer") },
];

function roleLabel(role: string | null | undefined): string {
  if (!role) return "session";
  return role.replaceAll("_", " ");
}

export function Shell({ auth, children }: { auth: AuthContext; children: React.ReactNode }) {
  const visibleNav = navItems.filter((item) => item.visible(auth));
  const organizationTag = auth.organization_id ? auth.organization_id.slice(0, 12) : "no-org";
  const userName = auth.user?.display_name ?? auth.user?.email ?? "session";

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(6,182,212,0.08),transparent_24rem),#020617] text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-white/10 bg-slate-950/90 px-6 py-7 shadow-2xl shadow-slate-950/60 backdrop-blur lg:block">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-lg font-black text-cyan-200">AG</div>
          <div>
            <div className="text-lg font-bold tracking-tight text-white">AgentOps Guard</div>
            <div className="text-xs uppercase tracking-[0.28em] text-slate-500">Governance Console</div>
          </div>
        </div>
        <div className="mt-7 rounded-2xl border border-white/10 bg-white/[0.03] p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Active Identity</div>
          <div className="mt-3 text-sm font-semibold text-white">{userName}</div>
          <div className="mt-1 text-sm text-slate-400">{roleLabel(auth.active_role)}</div>
          <div className="mt-3 flex items-center gap-2 text-xs text-slate-500">
            <BriefcaseBusiness className="h-3.5 w-3.5" />
            <span>{organizationTag}</span>
          </div>
        </div>
        <nav className="mt-7 space-y-1.5">
          {visibleNav.map(({ label, href, icon: Icon }) => (
            <Link key={href} href={href} className="group flex items-center justify-between rounded-xl px-4 py-3 text-sm font-medium text-slate-300 transition hover:bg-cyan-400/10 hover:text-cyan-100">
              <span className="flex items-center gap-3">
                <Icon className="h-4 w-4 text-slate-500 transition group-hover:text-cyan-200" />
                <span>{label}</span>
              </span>
              <span className="h-1.5 w-1.5 rounded-full bg-slate-700 transition group-hover:bg-cyan-300" />
            </Link>
          ))}
        </nav>
      </aside>

      <div className="lg:ml-72">
        <header className="sticky top-0 z-10 border-b border-white/10 bg-slate-950/80 backdrop-blur">
          <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-4 lg:px-10">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs uppercase tracking-[0.24em] text-slate-500">Session</div>
                <div className="mt-2 flex flex-wrap items-center gap-3">
                  <div className="text-lg font-semibold text-white">{userName}</div>
                  <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200">
                    {roleLabel(auth.active_role)}
                  </span>
                  {auth.project_id ? (
                    <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs font-medium text-slate-400">
                      project {auth.project_id}
                    </span>
                  ) : null}
                </div>
              </div>
              <LogoutButton />
            </div>
            <div className="overflow-x-auto lg:hidden">
              <div className="flex min-w-max gap-2 pb-1">
                {visibleNav.map(({ label, href, icon: Icon }) => (
                  <Link key={href} href={href} className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-slate-300">
                    <Icon className="h-4 w-4 text-slate-500" />
                    <span>{label}</span>
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </header>

        <main className="min-h-screen px-5 py-6 lg:px-10 lg:py-9">
          <div className="mx-auto max-w-7xl">{children}</div>
        </main>
      </div>
    </div>
  );
}
