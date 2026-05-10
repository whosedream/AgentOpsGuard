"use client";

import { Run } from "../../lib/api";
import { EmptyState } from "../ui/States";

export function RunsFilter({
  runs,
  status,
  agent,
  risk,
  onStatusChange,
  onAgentChange,
  onRiskChange,
}: {
  runs: Run[];
  status: string;
  agent: string;
  risk: string;
  onStatusChange: (value: string) => void;
  onAgentChange: (value: string) => void;
  onRiskChange: (value: string) => void;
}) {

  return (
    <div>
      <div className="mb-5 grid gap-3 md:grid-cols-3">
        <select aria-label="Status filter" value={status} onChange={(event) => onStatusChange(event.target.value)} className="rounded-xl border border-white/10 bg-slate-950 p-3"><option value="all">all statuses</option><option value="completed">completed</option><option value="running">running</option><option value="failed">failed</option><option value="blocked">blocked</option><option value="awaiting_approval">awaiting approval</option><option value="suppressed">suppressed</option></select>
        <input aria-label="Agent filter" placeholder="filter agent" value={agent} onChange={(event) => onAgentChange(event.target.value)} className="rounded-xl border border-white/10 bg-slate-950 p-3" />
        <input aria-label="Risk filter" placeholder="filter risk label" value={risk} onChange={(event) => onRiskChange(event.target.value)} className="rounded-xl border border-white/10 bg-slate-950 p-3" />
      </div>
      {runs.length === 0 ? <EmptyState label="No runs match the current filters" /> : <div className="overflow-hidden rounded-3xl border border-white/10 bg-white/[0.04]">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-950/80 text-slate-400"><tr><th className="p-4">Run</th><th>Status</th><th>Agent</th><th>Risk</th><th>Tokens</th><th>Started</th></tr></thead>
          <tbody>{runs.map((run) => <tr key={run.id} className="border-t border-white/10 hover:bg-white/[0.04]"><td className="p-4"><a className="text-cyan-200" href={`/runs/${run.id}`}>{run.name ?? run.id}</a></td><td>{run.status}</td><td>{run.agent_id ?? "-"}</td><td>{run.risk_score.toFixed(2)} {run.risk_labels.join(", ")}</td><td>{run.total_tokens}</td><td>{run.started_at ? new Date(run.started_at).toLocaleString() : "-"}</td></tr>)}</tbody>
        </table>
      </div>}
    </div>
  );
}
