import Link from "next/link";

const nav = [
  ["Overview", "/"],
  ["Setup", "/setup"],
  ["Governance", "/governance"],
  ["Scanner", "/scanner"],
  ["Policy", "/policy"],
  ["Runs", "/runs"],
  ["Replays", "/replays"],
  ["Risks", "/risks"],
  ["Evals", "/evals"],
  ["MCP", "/mcp"],
];

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-white/10 bg-slate-950/85 px-6 py-7 shadow-2xl shadow-slate-950/60 backdrop-blur lg:block">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-2xl bg-cyan-400/15 text-lg font-black text-cyan-300 ring-1 ring-cyan-300/30">AG</div>
          <div>
            <div className="text-lg font-bold tracking-tight">AgentOps Guard</div>
            <div className="text-xs uppercase tracking-[0.28em] text-slate-500">Control Center</div>
          </div>
        </div>
        <div className="mt-7 rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">Trace · Policy · Replay · MCP</div>
        <nav className="mt-7 space-y-1.5">
          {nav.map(([label, href]) => (
            <Link key={href} href={href} className="group flex items-center justify-between rounded-xl px-4 py-3 text-sm font-medium text-slate-300 transition hover:bg-cyan-400/10 hover:text-cyan-100">
              <span>{label}</span>
              <span className="h-1.5 w-1.5 rounded-full bg-slate-700 transition group-hover:bg-cyan-300" />
            </Link>
          ))}
        </nav>
      </aside>
      <main className="min-h-screen px-5 py-6 lg:ml-72 lg:px-10 lg:py-9"><div className="mx-auto max-w-7xl">{children}</div></main>
    </div>
  );
}
