"use client";

import { ReactNode, useCallback, useMemo } from "react";
import ReactFlow, { Background, Controls, Edge, EdgeTypes, Node, NodeTypes, ReactFlowProvider, useStoreApi } from "reactflow";
import "reactflow/dist/style.css";
import { TraceEvent } from "../../lib/api";
import { eventDisplayName } from "../../lib/payloads";

const nodeTypes: NodeTypes = {};
const edgeTypes: EdgeTypes = {};

function ReactFlowErrorBoundary({ children, onError }: { children: ReactNode; onError: (code: string, message: string) => void }) {
  const store = useStoreApi();
  if (store.getState().onError !== onError) {
    store.setState({ onError });
  }
  return children;
}

export function RunDagView({ events, selectedEventId, onSelectEvent }: { events: TraceEvent[]; selectedEventId?: string | null; onSelectEvent?: (event: TraceEvent) => void }) {
  const nodes: Node[] = useMemo(() => events.map((event, index) => ({
    id: event.span_id,
    position: { x: (index % 3) * 260, y: Math.floor(index / 3) * 140 },
    data: { label: `${eventDisplayName(event)}\n${event.status}` },
    style: { background: "#0f172a", color: "#e2e8f0", border: event.id === selectedEventId ? "2px solid #67e8f9" : "1px solid rgba(255,255,255,.16)", borderRadius: 16, padding: 12 },
  })), [events, selectedEventId]);
  const edges: Edge[] = useMemo(() => events.filter((event) => event.parent_span_id).map((event) => ({ id: `${event.parent_span_id}-${event.span_id}`, source: event.parent_span_id as string, target: event.span_id })), [events]);
  const bySpan = useMemo(() => new Map(events.map((event) => [event.span_id, event])), [events]);
  const handleNodeClick = useCallback((mouseEvent: unknown, node: Node) => {
    void mouseEvent;
    const event = bySpan.get(node.id);
    if (event) onSelectEvent?.(event);
  }, [bySpan, onSelectEvent]);
  const handleReactFlowError = useCallback((code: string, message: string) => {
    if (code === "002") return;
    console.warn(message);
  }, []);

  return (
    <div className="h-[360px] overflow-hidden rounded-3xl border border-white/10 bg-slate-950/70">
      <ReactFlowProvider>
        <ReactFlowErrorBoundary onError={handleReactFlowError}>
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView onNodeClick={handleNodeClick} onError={handleReactFlowError}><Background /><Controls /></ReactFlow>
        </ReactFlowErrorBoundary>
      </ReactFlowProvider>
    </div>
  );
}
