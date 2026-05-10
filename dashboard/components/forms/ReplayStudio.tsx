"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPost, Job, Page, pageItems, pollJob, Replay, Run } from "../../lib/api";
import { EmptyState, ErrorState, LoadingState } from "../ui/States";

export function ReplayStudio() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [replays, setReplays] = useState<Replay[]>([]);
  const [runId, setRunId] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const loadedRuns = pageItems(await apiGet<Run[] | Page<Run>>("/v1/runs?page_mode=envelope").catch(() => [] as Run[]));
    setRuns(loadedRuns);
    setRunId((current) => current || loadedRuns[0]?.id || "");
    setReplays(pageItems(await apiGet<Replay[] | Page<Replay>>("/v1/replays?page_mode=envelope").catch(() => [] as Replay[])));
  }

  async function createReplay() {
    if (!runId) return;
    setLoading(true);
    setError(null);
    try {
      const queued = await apiPost<Job>("/v1/replays/jobs", { project_id: "default", source_run_id: runId, mode: "exact" });
      setJob(queued);
      setJob(await pollJob(queued.id));
      await load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Replay job failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <div className="grid gap-6 lg:grid-cols-[0.8fr_1fr]">
      <section className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
        <label className="text-sm font-semibold text-slate-300">Run</label>
        <select value={runId} onChange={(event) => setRunId(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3">
          {runs.map((run) => <option key={run.id} value={run.id}>{run.name ?? run.id}</option>)}
        </select>
        <button onClick={createReplay} className="mt-4 rounded-xl bg-cyan-300 px-4 py-2 font-semibold text-slate-950">Create Replay Job</button>
        {loading ? <div className="mt-4"><LoadingState label="Replay job running" /></div> : null}
        {error ? <div className="mt-4"><ErrorState message={error} onRetry={createReplay} /></div> : null}
        {job ? <div className="mt-4 rounded-xl border border-white/10 p-3 text-sm text-slate-300">Job {job.id}: {job.status}{job.error ? ` · ${job.error}` : ""}</div> : null}
      </section>
      <section className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
        <h2 className="text-xl font-bold">Replay History</h2>
        <div className="mt-4 space-y-3">{replays.length ? replays.map((replay) => <div key={replay.id} className="rounded-xl border border-white/10 p-3"><b>{replay.id}</b><div className="text-sm text-slate-500">{String(replay.summary.likely_failure_reason ?? "no reason")}</div></div>) : <EmptyState label="No replay history" />}</div>
      </section>
    </div>
  );
}
