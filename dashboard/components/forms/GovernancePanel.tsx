"use client";

import { useEffect, useMemo, useState } from "react";
import {
  apiGet,
  apiPatch,
  apiPost,
  ApprovalRequest,
  ControlPlaneStatus,
  pageItems,
  PolicyPack,
  ScanRule,
} from "../../lib/api";
import { EmptyState, ErrorState, LoadingState } from "../ui/States";

export function GovernancePanel() {
  const [projectId, setProjectId] = useState("default");
  const [status, setStatus] = useState<ControlPlaneStatus | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [packs, setPacks] = useState<PolicyPack[]>([]);
  const [rules, setRules] = useState<ScanRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [retentionDays, setRetentionDays] = useState("30");
  const [storeRaw, setStoreRaw] = useState(false);
  const [policyFailMode, setPolicyFailMode] = useState("closed_for_high_risk");
  const [scanPattern, setScanPattern] = useState("(?i)wire money|seed phrase|private key");

  async function load(targetProject = projectId) {
    setLoading(true);
    setError(null);
    try {
      const [control, approvalPage, packPage, rulePage] = await Promise.all([
        apiGet<ControlPlaneStatus>(`/v1/control-plane/status?project_id=${encodeURIComponent(targetProject)}`),
        apiGet<ApprovalRequest[] | { items: ApprovalRequest[] }>(`/v1/approvals?project_id=${encodeURIComponent(targetProject)}&status=pending&page_mode=envelope`),
        apiGet<PolicyPack[] | { items: PolicyPack[] }>(`/v1/policy-packs?project_id=${encodeURIComponent(targetProject)}&page_mode=envelope`),
        apiGet<ScanRule[] | { items: ScanRule[] }>(`/v1/scanner/rules?project_id=${encodeURIComponent(targetProject)}&page_mode=envelope`),
      ]);
      setStatus(control);
      setRetentionDays(String(control.project.retention_days));
      setStoreRaw(control.project.store_raw_content);
      setPolicyFailMode(control.project.policy_fail_mode);
      setApprovals(pageItems(approvalPage));
      setPacks(pageItems(packPage));
      setRules(pageItems(rulePage));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Governance load failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load("default");
  }, []);

  const runStatuses = useMemo(() => Object.entries(status?.run_statuses ?? {}), [status]);

  async function saveProject() {
    setSaving(true);
    setError(null);
    try {
      await apiPatch(`/v1/projects/${encodeURIComponent(projectId)}`, {
        retention_days: Number(retentionDays),
        store_raw_content: storeRaw,
        policy_fail_mode: policyFailMode,
      });
      await load(projectId);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Project update failed");
    } finally {
      setSaving(false);
    }
  }

  async function seedPolicyPack() {
    setSaving(true);
    setError(null);
    try {
      await apiPost("/v1/policy-packs", {
        project_id: projectId,
        name: "High risk approval gate",
        version: "0.7.0",
        description: "Require approval for high-risk shell or terminal actions.",
        rules: [
          {
            id: "high-risk-shell-approval",
            action: "require_approval",
            severity: "high",
            reason_code: "policy_pack_high_risk_shell",
            remediation: "Route through an approval queue before executing shell commands.",
            when: { tool_name_in: ["shell.execute", "terminal.run"], min_risk_score: 0.5 },
          },
        ],
      });
      await load(projectId);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Policy pack create failed");
    } finally {
      setSaving(false);
    }
  }

  async function createScanRule() {
    setSaving(true);
    setError(null);
    try {
      await apiPost("/v1/scanner/rules", {
        project_id: projectId,
        label: "custom_sensitive_transfer",
        pattern: scanPattern,
        severity: "high",
        score: 0.8,
        description: "Project-specific high-risk transfer or secret phrase detector.",
      });
      await load(projectId);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Scan rule create failed");
    } finally {
      setSaving(false);
    }
  }

  async function reviewApproval(id: string, statusValue: "approved" | "denied") {
    setSaving(true);
    try {
      await apiPost(`/v1/approvals/${id}/review`, { status: statusValue, resolved_by: "dashboard" });
      await load(projectId);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Approval review failed");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <LoadingState label="Loading governance" />;

  return (
    <div className="space-y-6">
      {error ? <ErrorState message={error} onRetry={() => load(projectId)} /> : null}
      <section className="grid gap-4 md:grid-cols-4">
        {[
          ["Pending approvals", status?.pending_approvals ?? 0],
          ["Policy packs", status?.active_policy_packs ?? 0],
          ["Scan rules", status?.enabled_scan_rules ?? 0],
          ["Suppressions", status?.active_suppressions ?? 0],
        ].map(([label, value]) => (
          <div key={label} className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
            <div className="text-sm text-slate-400">{label}</div>
            <div className="mt-2 text-3xl font-black text-white">{value}</div>
          </div>
        ))}
      </section>

      <section className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
        <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
          <h2 className="text-xl font-bold">Project Configuration</h2>
          <label htmlFor="project-id" className="mt-4 block text-sm font-semibold text-slate-300">Project ID</label>
          <input id="project-id" value={projectId} onChange={(event) => setProjectId(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3" />
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <label className="text-sm font-semibold text-slate-300">
              Retention days
              <input value={retentionDays} onChange={(event) => setRetentionDays(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3" />
            </label>
            <label className="text-sm font-semibold text-slate-300">
              Policy fail mode
              <input value={policyFailMode} onChange={(event) => setPolicyFailMode(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3" />
            </label>
          </div>
          <label className="mt-4 flex items-center gap-3 text-sm text-slate-300">
            <input type="checkbox" checked={storeRaw} onChange={(event) => setStoreRaw(event.target.checked)} /> Store raw content for this project
          </label>
          <div className="mt-5 flex gap-3">
            <button onClick={saveProject} disabled={saving} className="rounded-xl bg-cyan-300 px-4 py-2 font-semibold text-slate-950 disabled:opacity-50">Save config</button>
            <button onClick={() => load(projectId)} className="rounded-xl border border-white/10 px-4 py-2 text-slate-200">Reload</button>
          </div>
        </div>

        <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
          <h2 className="text-xl font-bold">Run Status Mix</h2>
          {runStatuses.length ? (
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {runStatuses.map(([label, value]) => (
                <div key={label} className="rounded-2xl bg-slate-950/70 p-4">
                  <div className="text-sm text-slate-400">{label}</div>
                  <div className="mt-1 text-2xl font-bold text-white">{value}</div>
                </div>
              ))}
            </div>
          ) : <EmptyState label="No runs for this project yet" />}
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-xl font-bold">Approvals</h2>
            <span className="rounded-full bg-amber-300/10 px-3 py-1 text-xs text-amber-100">pending</span>
          </div>
          <div className="mt-4 space-y-3">
            {approvals.length ? approvals.map((item) => (
              <div key={item.id} className="rounded-2xl bg-slate-950/70 p-4 text-sm">
                <div className="font-semibold text-white">{item.reason_code}</div>
                <div className="mt-1 text-slate-400">{item.run_id ?? "no run"} · {item.severity}</div>
                <div className="mt-3 flex gap-2">
                  <button onClick={() => reviewApproval(item.id, "approved")} className="rounded-lg bg-emerald-300 px-3 py-1 text-slate-950">Approve</button>
                  <button onClick={() => reviewApproval(item.id, "denied")} className="rounded-lg bg-rose-300 px-3 py-1 text-slate-950">Deny</button>
                </div>
              </div>
            )) : <EmptyState label="No pending approvals" />}
          </div>
        </div>

        <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-xl font-bold">Policy Packs</h2>
            <button onClick={seedPolicyPack} disabled={saving} className="rounded-lg border border-cyan-300/30 px-3 py-1 text-xs text-cyan-100">Seed pack</button>
          </div>
          <div className="mt-4 space-y-3">
            {packs.length ? packs.map((pack) => (
              <div key={pack.id} className="rounded-2xl bg-slate-950/70 p-4 text-sm">
                <div className="font-semibold text-white">{pack.name}</div>
                <div className="mt-1 text-slate-400">v{pack.version} · {pack.status} · {pack.rules.length} rule(s)</div>
              </div>
            )) : <EmptyState label="No policy packs configured" />}
          </div>
        </div>

        <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
          <h2 className="text-xl font-bold">Scan Rules</h2>
          <input value={scanPattern} onChange={(event) => setScanPattern(event.target.value)} className="mt-4 w-full rounded-xl border border-white/10 bg-slate-950 p-3 text-sm" />
          <button onClick={createScanRule} disabled={saving} className="mt-3 rounded-xl bg-cyan-300 px-4 py-2 font-semibold text-slate-950 disabled:opacity-50">Add rule</button>
          <div className="mt-4 space-y-3">
            {rules.length ? rules.map((rule) => (
              <div key={rule.id} className="rounded-2xl bg-slate-950/70 p-4 text-sm">
                <div className="font-semibold text-white">{rule.label}</div>
                <div className="mt-1 text-slate-400">{rule.severity} · {rule.score} · {rule.status}</div>
              </div>
            )) : <EmptyState label="No custom scan rules" />}
          </div>
        </div>
      </section>
    </div>
  );
}
