"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shell } from "../../components/Shell";
import { RunsFilter } from "../../components/forms/RunsFilter";
import { ErrorState, LoadingState } from "../../components/ui/States";
import { apiGet, buildRunsQuery, nextCursor, pageItems, Page, Run } from "../../lib/api";

export default function RunsPage() {
  return (
    <Suspense fallback={<Shell><LoadingState label="Loading runs" /></Shell>}>
      <RunsContent />
    </Suspense>
  );
}

function RunsContent() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();
  const searchParams = useSearchParams();
  const projectId = searchParams.get("project_id") ?? "default";
  const status = searchParams.get("status") ?? "all";
  const agent = searchParams.get("agent") ?? "";
  const risk = searchParams.get("risk_label") ?? "";
  const currentCursor = searchParams.get("cursor");

  function setFilter(key: string, value: string) {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("cursor");
    if (!value || value === "all") params.delete(key);
    else params.set(key, value);
    const query = params.toString();
    router.push(query ? `/runs?${query}` : "/runs");
  }

  function load() {
    setLoading(true);
    setError(null);
    apiGet<Run[] | Page<Run>>(buildRunsQuery({ projectId, status, agent, riskLabel: risk, cursor: currentCursor }))
      .then((page) => {
        setRuns(pageItems(page));
        setCursor(nextCursor(page));
      })
      .catch((exc) => {
        setRuns([]);
        setCursor(null);
        setError(exc instanceof Error ? exc.message : "Failed to load runs");
      })
      .finally(() => setLoading(false));
  }

  useEffect(load, [projectId, status, agent, risk, currentCursor]);

  function goNext() {
    if (!cursor) return;
    const params = new URLSearchParams(searchParams.toString());
    params.set("cursor", cursor);
    router.push(`/runs?${params.toString()}`);
  }

  return (
    <Shell>
      <div className="mb-8"><h1 className="text-4xl font-black text-white">Runs</h1><p className="mt-2 text-slate-400">Filter execution traces by status, agent, and risk label.</p></div>
      {error ? <ErrorState message={error} onRetry={load} /> : null}
      {loading ? <LoadingState label="Loading runs" /> : <RunsFilter runs={runs} status={status} agent={agent} risk={risk} onStatusChange={(value) => setFilter("status", value)} onAgentChange={(value) => setFilter("agent", value)} onRiskChange={(value) => setFilter("risk_label", value)} />}
      <div className="mt-5 flex justify-end">
        {cursor ? <button onClick={goNext} className="rounded-xl border border-white/10 px-4 py-2 text-sm text-cyan-100">Next page</button> : null}
      </div>
    </Shell>
  );
}
