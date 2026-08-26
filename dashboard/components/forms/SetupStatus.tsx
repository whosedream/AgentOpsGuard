"use client";

import { useEffect, useState } from "react";

import { apiGet, gatewayGet, SystemStatus } from "../../lib/api";
import { useDashboardAuth } from "../auth/AuthProvider";

export function SetupStatus() {
  const auth = useDashboardAuth();
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [gatewayOk, setGatewayOk] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const projectId = auth.project_id ?? "default";

  useEffect(() => {
    async function load() {
      try {
        const system = await apiGet<SystemStatus>(`/v1/system/status?project_id=${encodeURIComponent(projectId)}`);
        setStatus(system);
        await gatewayGet("/mcp/tools/list");
        setGatewayOk(true);
      } catch (exc) {
        setError(exc instanceof Error ? exc.message : "Health check failed");
      }
    }
    load();
  }, [projectId]);

  return (
    <div className="grid gap-4 md:grid-cols-3">
      <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
        <div className="text-sm text-slate-400">API</div>
        <div className="mt-2 text-2xl font-bold text-emerald-200">{status?.api.status ?? "loading"}</div>
      </div>
      <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
        <div className="text-sm text-slate-400">Database</div>
        <div className="mt-2 text-2xl font-bold text-emerald-200">Database {status?.database.status ?? "loading"}</div>
      </div>
      <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
        <div className="text-sm text-slate-400">Gateway</div>
        <div className="mt-2 text-2xl font-bold text-emerald-200">{gatewayOk ? "Gateway ok" : "checking"}</div>
      </div>
      {status ? <pre className="md:col-span-3 overflow-auto rounded-3xl border border-white/10 bg-slate-950/80 p-5 text-sm text-slate-300">{JSON.stringify(status.counts, null, 2)}</pre> : null}
      {error ? <div className="md:col-span-3 rounded-xl border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200">{error}</div> : null}
    </div>
  );
}
