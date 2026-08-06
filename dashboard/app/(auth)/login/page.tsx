import { ShieldCheck, UserRoundCog, Workflow, KeyRound } from "lucide-react";

import { LoginPanel } from "../../../components/auth/LoginPanel";

const roleCards = [
  { title: "Admin", detail: "Organization, project, key, governance, MCP, approvals." },
  { title: "Reviewer", detail: "Risk review, approvals, governance read, raw content access." },
  { title: "Developer", detail: "Runs, replay, eval, scanner, policy, MCP tool testing." },
  { title: "Read-only", detail: "Operational visibility without governance or sensitive actions." },
];

const surfaceCards = [
  { icon: ShieldCheck, title: "Session-first console", detail: "Dashboard identity now comes from server session and HttpOnly cookie." },
  { icon: Workflow, title: "Organization boundary", detail: "Project, policy, MCP and risk views stay inside the active organization scope." },
  { icon: UserRoundCog, title: "Fixed role model", detail: "Four roles map directly to navigation, page access and action-level controls." },
  { icon: KeyRound, title: "API key stays automation-only", detail: "Project API keys continue to serve bots and CI, not human dashboard login." },
];

export default function LoginPage() {
  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(6,182,212,0.16),transparent_26rem),radial-gradient(circle_at_bottom_right,rgba(245,158,11,0.08),transparent_28rem),#020617] px-6 py-8 text-slate-100 lg:px-10 lg:py-10">
      <div className="mx-auto grid min-h-[calc(100vh-4rem)] max-w-7xl gap-8 lg:grid-cols-[1.15fr_0.85fr]">
        <section className="flex flex-col justify-between rounded-[28px] border border-white/10 bg-slate-950/70 p-8 shadow-2xl shadow-slate-950/60 backdrop-blur xl:p-10">
          <div>
            <div className="inline-flex items-center rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-200">
              AgentOps Guard
            </div>
            <h1 className="mt-6 max-w-3xl text-4xl font-black tracking-tight text-white xl:text-5xl">
              Multi-user governance console for agent runtime, policy and MCP operations.
            </h1>
            <p className="mt-4 max-w-2xl text-base text-slate-400">
              Session-backed dashboard access with organization-aware routing, review controls and execution visibility.
            </p>
          </div>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            {surfaceCards.map(({ icon: Icon, title, detail }) => (
              <div key={title} className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-200">
                  <Icon className="h-5 w-5" />
                </div>
                <div className="mt-4 text-sm font-semibold text-white">{title}</div>
                <p className="mt-2 text-sm leading-6 text-slate-400">{detail}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="flex flex-col gap-6">
          <LoginPanel />
          <div className="rounded-[24px] border border-white/10 bg-slate-950/70 p-6 shadow-xl shadow-slate-950/40 backdrop-blur">
            <div className="text-sm font-semibold uppercase tracking-[0.22em] text-slate-500">Role Surface</div>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              {roleCards.map((card) => (
                <div key={card.title} className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                  <div className="text-sm font-semibold text-white">{card.title}</div>
                  <div className="mt-2 text-sm leading-6 text-slate-400">{card.detail}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
