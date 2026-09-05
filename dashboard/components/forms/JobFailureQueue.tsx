"use client";

import { useEffect, useState } from "react";

import { useDashboardAuth } from "../auth/AuthProvider";
import { EmptyState, ErrorState, LoadingState } from "../ui/States";
import {
  apiGet,
  apiPost,
  buildExecutionsQuery,
  buildJobsQuery,
  ExecutionRequest,
  ExecutionResolution,
  Job,
  JobReconciliation,
  pageItems,
  Page,
} from "../../lib/api";
import { canManageJobs } from "../../lib/auth";

const STATUSES = ["dead", "pending", "running", "completed", "all"];

export function JobFailureQueue() {
  const auth = useDashboardAuth();
  const projectId = auth.project_id ?? "default";
  const canRetry = canManageJobs(auth);
  const [status, setStatus] = useState("dead");
  const [jobs, setJobs] = useState<Job[]>([]);
  const [unknownExecutions, setUnknownExecutions] = useState<ExecutionRequest[]>([]);
  const [evidenceByExecution, setEvidenceByExecution] = useState<Record<string, string>>({});
  const [resolving, setResolving] = useState<string | null>(null);
  const [report, setReport] = useState<JobReconciliation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.all([
      apiGet<Job[] | Page<Job>>(buildJobsQuery({ projectId, status })),
      apiGet<JobReconciliation>(`/v1/jobs/reconciliation?project_id=${encodeURIComponent(projectId)}`),
      apiGet<ExecutionRequest[] | Page<ExecutionRequest>>(buildExecutionsQuery({ projectId })),
    ])
      .then(([page, reconciliation, executions]) => {
        setJobs(pageItems(page));
        setReport(reconciliation);
        setUnknownExecutions(pageItems(executions));
      })
      .catch((exc) => {
        setJobs([]);
        setReport(null);
        setUnknownExecutions([]);
        setError(exc instanceof Error ? exc.message : "Failed to load jobs");
      })
      .finally(() => setLoading(false));
  }

  useEffect(load, [projectId, status]);

  async function retry(jobId: string) {
    setError(null);
    try {
      await apiPost<Job>(`/v1/jobs/${jobId}/retry`);
      load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Failed to retry job");
    }
  }

  async function resolveExecution(
    executionId: string,
    resolution: "confirmed_succeeded" | "confirmed_failed" | "confirmed_not_executed",
  ) {
    const evidenceSha256 = (evidenceByExecution[executionId] ?? "").trim();
    if (!/^[0-9a-f]{64}$/.test(evidenceSha256)) {
      setError("Evidence must be a 64-character lowercase SHA-256 digest.");
      return;
    }
    if (
      resolution === "confirmed_not_executed"
      && !window.confirm("Confirm the external system shows no execution. This allows one new claim under the original approval bounds.")
    ) return;
    setResolving(executionId);
    setError(null);
    try {
      await apiPost<ExecutionResolution>(`/v1/executions/${executionId}/resolve`, {
        resolution,
        evidence_sha256: evidenceSha256,
      });
      setEvidenceByExecution((current) => ({ ...current, [executionId]: "" }));
      load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Failed to reconcile execution outcome");
    } finally {
      setResolving(null);
    }
  }

  return (
    <div>
      {report ? (
        <dl className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <Summary label="Stale pending" value={report.stale_pending_jobs} />
          <Summary label="Expired leases" value={report.expired_running_jobs} />
          <Summary label="Dead jobs" value={report.dead_jobs} />
          <Summary label="Undelivered" value={report.undelivered_outbox_events} />
          <Summary label="Unknown outcomes" value={report.outcome_unknown_executions} />
        </dl>
      ) : null}
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white">Background jobs</h2>
          <p className="mt-2 text-sm text-slate-400">
            Failed jobs stop after three attempts. Error values are fixed codes, not raw exception text.
          </p>
        </div>
        <label className="text-sm text-slate-400">
          Status
          <select
            aria-label="Job status"
            className="ml-3 rounded-xl border border-white/10 bg-slate-950 p-3"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          >
            {STATUSES.map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>
        </label>
      </div>
      {error ? <ErrorState message={error} onRetry={load} /> : null}
      {loading ? (
        <LoadingState label="Loading jobs" />
      ) : (
        <>
          <section className="mb-8">
            <h2 className="text-xl font-bold text-white">Unknown tool outcomes</h2>
            <p className="mt-2 text-sm text-slate-400">
              Keep evidence in the external system. Enter only its lowercase SHA-256 digest here.
              Only a confirmed non-execution can make the original request claimable again.
            </p>
            {unknownExecutions.length === 0 ? (
              <div className="mt-4"><EmptyState label="No unknown tool outcomes" /></div>
            ) : (
              <div className="mt-4 grid gap-4">
                {unknownExecutions.map((execution) => (
                  <article key={execution.id} className="rounded-3xl border border-amber-400/20 bg-amber-400/[0.04] p-5">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="font-semibold text-white">{execution.tool_name}</div>
                        <div className="mt-1 font-mono text-xs text-slate-500">{execution.id}</div>
                      </div>
                      <span className="rounded-full border border-amber-400/30 px-3 py-1 text-sm text-amber-100">
                        outcome unknown
                      </span>
                    </div>
                    <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
                      <div><dt className="text-slate-500">Server</dt><dd className="mt-1 text-slate-200">{execution.server_id}</dd></div>
                      <div><dt className="text-slate-500">Tool revision</dt><dd className="mt-1 font-mono text-xs text-slate-200">{execution.tool_revision_id}</dd></div>
                      <div><dt className="text-slate-500">Expires</dt><dd className="mt-1 text-slate-200">{execution.expires_at}</dd></div>
                    </dl>
                    {canRetry ? (
                      <div className="mt-4">
                        <label className="block text-sm text-slate-400">
                          External evidence SHA-256
                          <input
                            aria-label={`Evidence SHA-256 for ${execution.id}`}
                            className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3 font-mono text-sm text-slate-100"
                            maxLength={64}
                            spellCheck={false}
                            value={evidenceByExecution[execution.id] ?? ""}
                            onChange={(event) => setEvidenceByExecution((current) => ({
                              ...current,
                              [execution.id]: event.target.value,
                            }))}
                          />
                        </label>
                        <div className="mt-3 flex flex-wrap gap-2">
                          <ResolutionButton disabled={resolving === execution.id} onClick={() => resolveExecution(execution.id, "confirmed_succeeded")}>Confirm succeeded</ResolutionButton>
                          <ResolutionButton disabled={resolving === execution.id} onClick={() => resolveExecution(execution.id, "confirmed_failed")}>Confirm failed</ResolutionButton>
                          <ResolutionButton disabled={resolving === execution.id} onClick={() => resolveExecution(execution.id, "confirmed_not_executed")}>Confirm not executed</ResolutionButton>
                        </div>
                      </div>
                    ) : null}
                  </article>
                ))}
              </div>
            )}
          </section>
          {jobs.length === 0 ? (
            <EmptyState label={`No ${status === "all" ? "" : `${status} `}jobs`} />
          ) : <div className="grid gap-4">
            {jobs.map((job) => (
            <article key={job.id} className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-semibold text-white">{job.kind}</div>
                  <div className="mt-1 font-mono text-xs text-slate-500">{job.id}</div>
                </div>
                <span className="rounded-full border border-white/10 px-3 py-1 text-sm text-cyan-100">
                  {job.status}
                </span>
              </div>
              <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
                <div><dt className="text-slate-500">Attempts</dt><dd className="mt-1 text-slate-200">{job.attempts}</dd></div>
                <div><dt className="text-slate-500">Error code</dt><dd className="mt-1 text-slate-200">{job.error ?? "none"}</dd></div>
                <div><dt className="text-slate-500">Finished</dt><dd className="mt-1 text-slate-200">{job.finished_at ?? "not finished"}</dd></div>
              </dl>
              {job.status === "dead" && canRetry ? (
                <button
                  className="mt-4 rounded-xl border border-cyan-400/20 bg-cyan-400/10 px-4 py-2 text-sm font-semibold text-cyan-100"
                  onClick={() => retry(job.id)}
                >
                  Create controlled retry
                </button>
              ) : null}
            </article>
            ))}
          </div>}
        </>
      )}
    </div>
  );
}

function ResolutionButton({
  children,
  disabled,
  onClick,
}: {
  children: React.ReactNode;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      className="rounded-xl border border-amber-400/20 bg-amber-400/10 px-4 py-2 text-sm font-semibold text-amber-100 disabled:cursor-not-allowed disabled:opacity-50"
      disabled={disabled}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function Summary({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
      <dt className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</dt>
      <dd className="mt-2 text-2xl font-bold text-white">{value}</dd>
    </div>
  );
}
