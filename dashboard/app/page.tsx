import { Shell } from "../components/Shell";
import { StatCard } from "../components/StatCard";
import { apiGet, Run, RiskEvent, SystemStatus } from "../lib/api";

export default async function Home() {
  const runs = await apiGet<Run[]>("/v1/runs").catch(() => []);
  const risks = await apiGet<RiskEvent[]>("/v1/risks").catch(() => []);
  const system = await apiGet<SystemStatus>("/v1/system/status").catch(() => null);
  const completed = runs.filter((run) => run.status === "completed").length;
  const successRate = runs.length ? Math.round((completed / runs.length) * 100) : 0;
  const cost = runs.reduce((sum, run) => sum + run.total_cost_usd, 0).toFixed(4);
  const highRisk = risks.filter((risk) => ["high", "critical"].includes(risk.severity)).length;

  return (
    <Shell>
      <div className="mb-8 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="mb-3 inline-flex rounded-full border border-cyan-300/20 bg-cyan-300/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-200">Agent tracing · evaluation · security</div>
          <h1 className="text-4xl font-black tracking-tight text-white lg:text-5xl">AgentOps Overview</h1>
          <p className="mt-3 max-w-2xl text-base text-slate-400">Self-hosted control center for MCP + Python agents.</p>
        </div>
        <a href="/setup" className="rounded-2xl border border-emerald-300/20 bg-emerald-300/10 px-4 py-3 text-sm text-emerald-200">API {system?.api.status ?? "unknown"} · Database {system?.database.status ?? "unknown"}</a>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Runs" value={runs.length} detail="Total captured executions" />
        <StatCard label="Success Rate" value={`${successRate}%`} detail="Completed vs total runs" />
        <StatCard label="Cost" value={`$${cost}`} detail="Reported model spend" />
        <StatCard label="High Risk" value={highRisk} detail="High or critical risk events" />
      </div>
      <div className="mt-8 grid gap-6 xl:grid-cols-2">
        <section className="overflow-hidden rounded-3xl border border-white/10 bg-white/[0.04] shadow-xl shadow-slate-950/30 backdrop-blur">
          <div className="flex items-center justify-between border-b border-white/10 px-6 py-5"><h2 className="text-xl font-bold text-white">Recent Runs</h2><a href="/runs" className="rounded-xl bg-cyan-300 px-4 py-2 text-sm font-semibold text-slate-950">View all</a></div>
          <div className="divide-y divide-white/10">{runs.slice(0, 5).map((run) => <a key={run.id} href={`/runs/${run.id}`} className="block px-6 py-4 transition hover:bg-white/[0.04]"><div className="flex items-center justify-between"><div><div className="font-semibold text-white">{run.name ?? run.id}</div><div className="mt-1 text-sm text-slate-500">{run.agent_id ?? "unknown agent"}</div></div><span className="rounded-full bg-slate-950/60 px-3 py-1 text-sm">{run.status}</span></div></a>)}{runs.length === 0 ? <div className="px-6 py-10 text-center text-slate-500">No runs captured yet.</div> : null}</div>
        </section>
        <section className="overflow-hidden rounded-3xl border border-white/10 bg-white/[0.04] shadow-xl shadow-slate-950/30 backdrop-blur">
          <div className="flex items-center justify-between border-b border-white/10 px-6 py-5"><h2 className="text-xl font-bold text-white">Recent Risks</h2><a href="/risks" className="rounded-xl border border-white/10 px-4 py-2 text-sm">Investigate</a></div>
          <div className="divide-y divide-white/10">{risks.slice(0, 5).map((risk) => <div key={risk.id} className="px-6 py-4"><div className="font-semibold text-white">{risk.risk_type}</div><div className="mt-1 text-sm text-slate-500">{risk.severity} · {risk.labels.join(", ")}</div></div>)}</div>
        </section>
      </div>
    </Shell>
  );
}
