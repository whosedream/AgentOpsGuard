"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Shell } from "../../components/Shell";
import { EmptyState, ErrorState, LoadingState } from "../../components/ui/States";
import { apiGet, buildRisksQuery, nextCursor, pageItems, Page, RiskEvent } from "../../lib/api";
import { riskTone } from "../../lib/payloads";

export default function RisksPage() {
  return (
    <Suspense fallback={<Shell><LoadingState label="Loading risks" /></Shell>}>
      <RisksContent />
    </Suspense>
  );
}

function RisksContent() {
  const [risks, setRisks] = useState<RiskEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();
  const searchParams = useSearchParams();
  const projectId = searchParams.get("project_id") ?? "default";
  const severity = searchParams.get("severity") ?? "all";
  const currentCursor = searchParams.get("cursor");

  function load() {
    setLoading(true);
    setError(null);
    apiGet<RiskEvent[] | Page<RiskEvent>>(buildRisksQuery({ projectId, severity, cursor: currentCursor }))
      .then((page) => {
        setRisks(pageItems(page));
        setCursor(nextCursor(page));
      })
      .catch((exc) => {
        setRisks([]);
        setCursor(null);
        setError(exc instanceof Error ? exc.message : "Failed to load risks");
      })
      .finally(() => setLoading(false));
  }

  useEffect(load, [projectId, severity, currentCursor]);

  function setSeverity(value: string) {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("cursor");
    if (value === "all") params.delete("severity");
    else params.set("severity", value);
    const query = params.toString();
    router.push(query ? `/risks?${query}` : "/risks");
  }

  function goNext() {
    if (!cursor) return;
    const params = new URLSearchParams(searchParams.toString());
    params.set("cursor", cursor);
    router.push(`/risks?${params.toString()}`);
  }

  return (
    <Shell>
      <div className="mb-8 flex items-end justify-between">
        <div><h1 className="text-4xl font-black text-white">Risk Events</h1><p className="mt-2 text-slate-400">Filter risks, inspect evidence, and jump to related runs.</p></div>
        <label className="text-sm text-slate-400">Severity filter<select value={severity} onChange={(event) => setSeverity(event.target.value)} className="ml-3 rounded-xl border border-white/10 bg-slate-950 p-3" aria-label="Severity filter"><option value="all">all</option><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option></select></label>
      </div>
      {error ? <ErrorState message={error} onRetry={load} /> : null}
      {loading ? <LoadingState label="Loading risks" /> : risks.length === 0 ? <EmptyState label="No risks match the current filters" /> : <div className="grid gap-4">{risks.map((risk) => <div key={risk.id} className="rounded-3xl border border-white/10 bg-white/[0.04] p-5"><div className="flex items-center justify-between"><div className="text-lg font-semibold">{risk.risk_type}</div><div className={`rounded-full border px-3 py-1 text-sm ${riskTone(risk.severity)}`}>{risk.severity}</div></div><p className="mt-2 text-slate-400">{risk.description ?? "No description"}</p><div className="mt-3 flex flex-wrap gap-2">{risk.labels.map((label) => <span key={label} className="rounded-full bg-slate-800 px-3 py-1 text-sm text-cyan-200">{label}</span>)}</div><div className="mt-4 space-y-2">{(risk.evidence ?? []).map((item, index) => <div key={index} className="rounded-xl bg-slate-950/70 p-3 text-sm text-slate-300">{String(item.snippet ?? item.label ?? JSON.stringify(item))}</div>)}</div>{risk.run_id ? <Link href={`/runs/${risk.run_id}`} className="mt-4 inline-block text-sm text-cyan-200">Open related run</Link> : null}</div>)}</div>}
      <div className="mt-5 flex justify-end">
        {cursor ? <button onClick={goNext} className="rounded-xl border border-white/10 px-4 py-2 text-sm text-cyan-100">Next page</button> : null}
      </div>
    </Shell>
  );
}
