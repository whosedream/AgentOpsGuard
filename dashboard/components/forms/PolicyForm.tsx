"use client";

import { useState } from "react";

import { apiPost, PolicyDecision } from "../../lib/api";
import { buildPolicyPayload, riskTone } from "../../lib/payloads";
import { useDashboardAuth } from "../auth/AuthProvider";

export function PolicyForm() {
  const auth = useDashboardAuth();
  const [agentId, setAgentId] = useState("coding-agent");
  const [toolName, setToolName] = useState("shell.execute");
  const [command, setCommand] = useState("rm -rf /");
  const [riskLabels, setRiskLabels] = useState("");
  const [result, setResult] = useState<PolicyDecision | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    try {
      setResult(await apiPost<PolicyDecision>("/v1/policies/evaluate", buildPolicyPayload({ projectId: auth.project_id ?? "default", agentId, toolName, command, riskLabels })));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Policy evaluation failed");
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[0.9fr_1fr]">
      <section className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
        <label htmlFor="agent-id" className="text-sm font-semibold text-slate-300">Agent ID</label>
        <input id="agent-id" value={agentId} onChange={(event) => setAgentId(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3" />
        <label htmlFor="tool-name" className="mt-4 block text-sm font-semibold text-slate-300">Tool name</label>
        <input id="tool-name" value={toolName} onChange={(event) => setToolName(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3" />
        <label htmlFor="command" className="mt-4 block text-sm font-semibold text-slate-300">Command</label>
        <input id="command" value={command} onChange={(event) => setCommand(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3" />
        <label htmlFor="risk-labels" className="mt-4 block text-sm font-semibold text-slate-300">Risk labels</label>
        <input id="risk-labels" value={riskLabels} onChange={(event) => setRiskLabels(event.target.value)} placeholder="credential_exfiltration, data_exfiltration" className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3" />
        <button onClick={submit} className="mt-5 rounded-xl bg-cyan-300 px-5 py-3 font-semibold text-slate-950 hover:bg-cyan-200">Evaluate policy</button>
        {error ? <div className="mt-4 rounded-xl border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200">{error}</div> : null}
      </section>
      <section className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
        <h2 className="text-xl font-bold">Policy Decision</h2>
        {result ? (
          <div className="mt-4 space-y-4">
            <div className={`inline-flex rounded-full border px-3 py-1 text-sm ${riskTone(result.severity)}`}>{result.action}</div>
            <div className="text-2xl font-bold text-white">{result.reason_code}</div>
            <div className="text-sm text-slate-400">Matched policy: {result.matched_policy ?? "-"}</div>
            {result.remediation ? <div className="rounded-2xl bg-slate-950/70 p-4 text-sm text-slate-300">{result.remediation}</div> : null}
          </div>
        ) : <p className="mt-4 text-slate-500">Submit a tool context to see allow/deny/approval behavior.</p>}
      </section>
    </div>
  );
}
