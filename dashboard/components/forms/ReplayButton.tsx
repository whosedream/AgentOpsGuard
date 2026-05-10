"use client";

import { useState } from "react";
import { apiPost, Replay, Run } from "../../lib/api";

export function ReplayButton({ run }: { run: Run }) {
  const [replay, setReplay] = useState<Replay | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function createReplay() {
    setError(null);
    try {
      setReplay(await apiPost<Replay>("/v1/replays", { project_id: run.project_id, source_run_id: run.id, mode: "exact" }));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Replay failed");
    }
  }

  return (
    <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
      <button onClick={createReplay} className="rounded-xl bg-cyan-300 px-4 py-2 font-semibold text-slate-950 hover:bg-cyan-200">Create Replay</button>
      {error ? <div className="mt-3 text-sm text-rose-200">{error}</div> : null}
      {replay ? <pre className="mt-4 overflow-auto rounded-2xl bg-slate-950/80 p-4 text-sm text-slate-300">{JSON.stringify(replay.summary, null, 2)}</pre> : null}
    </div>
  );
}
