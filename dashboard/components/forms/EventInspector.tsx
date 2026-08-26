"use client";

import { useState } from "react";

import { apiGet, ContentObject, TraceEvent } from "../../lib/api";
import { canReadRawContent } from "../../lib/auth";
import { eventDisplayName, riskTone } from "../../lib/payloads";
import { useDashboardAuth } from "../auth/AuthProvider";
import { EmptyState } from "../ui/States";

function ContentRefButton({ label, contentId }: { label: string; contentId?: string | null }) {
  const auth = useDashboardAuth();
  const [content, setContent] = useState<ContentObject | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (!contentId) return <div className="text-sm text-slate-500">{label}: -</div>;
  if (!canReadRawContent(auth)) return <div className="text-sm text-slate-500">{label}: redacted for current role</div>;

  async function loadContent() {
    setError(null);
    try {
      setContent(await apiGet<ContentObject>(`/v1/content/${contentId}`));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Content load failed");
    }
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/60 p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm text-slate-400">{label}: <span className="text-slate-200">{contentId}</span></div>
        <button onClick={loadContent} className="rounded-lg border border-white/10 px-3 py-1 text-xs text-cyan-100">Load content</button>
      </div>
      {error ? <div className="mt-2 text-sm text-rose-200">{error}</div> : null}
      {content ? (
        <div className="mt-3 space-y-2 text-sm">
          <div className="text-slate-400">Hash: {content.content_hash.slice(0, 16)}...</div>
          {content.labels.length ? <div className="text-amber-200">Labels: {content.labels.join(", ")}</div> : null}
          <pre className="overflow-auto rounded-xl bg-black/30 p-3 text-slate-300">{content.redacted_text ?? content.summary ?? "No redacted content"}</pre>
        </div>
      ) : null}
    </div>
  );
}

export function EventInspector({ event }: { event: TraceEvent | null }) {
  if (!event) return <EmptyState label="Select a DAG node or timeline event to inspect details" />;
  return (
    <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-white">{eventDisplayName(event)}</h2>
          <div className="mt-1 text-sm text-slate-400">{event.event_type} · {event.status}</div>
        </div>
        <div className={`rounded-full border px-3 py-1 text-sm ${riskTone(event.risk_score >= 0.7 ? "high" : event.risk_score >= 0.4 ? "medium" : "low")}`}>{event.risk_score.toFixed(2)}</div>
      </div>
      <div className="mt-4 grid gap-3 text-sm md:grid-cols-2">
        <div className="rounded-2xl bg-slate-950/60 p-3 text-slate-300">span {event.span_id}</div>
        <div className="rounded-2xl bg-slate-950/60 p-3 text-slate-300">parent {event.parent_span_id ?? "root"}</div>
      </div>
      {event.risk_labels.length ? <div className="mt-4 text-sm text-amber-200">Risk labels: {event.risk_labels.join(", ")}</div> : null}
      <div className="mt-4 space-y-3">
        <ContentRefButton label="Input" contentId={event.input_ref} />
        <ContentRefButton label="Output" contentId={event.output_ref} />
      </div>
      <pre className="mt-4 overflow-auto rounded-2xl bg-slate-950/80 p-4 text-xs text-slate-300">{JSON.stringify(event.metadata, null, 2)}</pre>
    </div>
  );
}
