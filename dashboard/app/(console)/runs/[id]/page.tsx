"use client";

import { use, useEffect, useState } from "react";

import { EventInspector } from "../../../../components/forms/EventInspector";
import { ReplayButton } from "../../../../components/forms/ReplayButton";
import { RunDagView } from "../../../../components/forms/RunDagView";
import { EmptyState, ErrorState, LoadingState } from "../../../../components/ui/States";
import { apiGet, Run, TraceEvent } from "../../../../lib/api";
import { eventDisplayName } from "../../../../lib/payloads";

export default function RunDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.all([
      apiGet<Run>(`/v1/runs/${id}`),
      apiGet<TraceEvent[]>(`/v1/runs/${id}/events`).catch(() => []),
    ])
      .then(([runResponse, eventsResponse]) => {
        setRun(runResponse);
        setEvents(eventsResponse);
        setSelectedEventId((current) => current ?? eventsResponse[0]?.id ?? null);
      })
      .catch((exc) => setError(exc instanceof Error ? exc.message : "Run detail failed to load"))
      .finally(() => setLoading(false));
  }

  useEffect(load, [id]);

  if (loading) return <LoadingState label="Loading run" />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!run) return <EmptyState label="Run not found" />;

  const selectedEvent = events.find((event) => event.id === selectedEventId) ?? null;

  return (
    <>
      <div className="mb-8 flex items-center justify-between"><div><h1 className="text-4xl font-black text-white">{run.name ?? run.id}</h1><p className="mt-1 text-slate-400">{run.trace_id}</p></div><div className="rounded-full bg-slate-800 px-4 py-2 text-sm">{run.status}</div></div>
      <div className="grid gap-6 xl:grid-cols-[1fr_420px]">
        <section>
          <h2 className="mb-3 text-xl font-bold">Trace DAG</h2>
          {events.length ? <RunDagView events={events} selectedEventId={selectedEventId} onSelectEvent={(event) => setSelectedEventId(event.id)} /> : <EmptyState label="No trace events recorded for this run" />}
          <div className="mt-6 space-y-3">
            {events.map((event) => (
              <button key={event.id} onClick={() => setSelectedEventId(event.id)} className={`block w-full rounded-3xl border p-5 text-left transition ${event.id === selectedEventId ? "border-cyan-300/70 bg-cyan-300/10" : "border-white/10 bg-white/[0.04] hover:bg-white/[0.07]"}`}>
                <div className="flex justify-between"><div className="font-semibold">{eventDisplayName(event)}</div><div className="text-sm text-slate-400">{event.status}</div></div>
                <div className="mt-2 text-sm text-slate-500">span {event.span_id} · parent {event.parent_span_id ?? "root"} · input {event.input_ref ?? "-"} · output {event.output_ref ?? "-"}</div>
                {event.risk_labels.length ? <div className="mt-3 text-sm text-amber-300">Risk: {event.risk_labels.join(", ")}</div> : null}
              </button>
            ))}
          </div>
        </section>
        <aside className="space-y-6">
          <EventInspector event={selectedEvent} />
          <ReplayButton run={run} />
        </aside>
      </div>
    </>
  );
}
