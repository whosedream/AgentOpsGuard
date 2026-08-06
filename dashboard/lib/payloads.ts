export type PolicyForm = {
  projectId: string;
  agentId: string;
  toolName: string;
  command: string;
  riskLabels: string;
};

export function parseLabels(value: string): string[] {
  return value
    .split(",")
    .map((label) => label.trim())
    .filter(Boolean);
}

export function buildPolicyPayload(form: PolicyForm) {
  const labels = parseLabels(form.riskLabels);
  return {
    project_id: form.projectId,
    actor: { agent_id: form.agentId || undefined },
    tool: { name: form.toolName, command: form.command, args: { command: form.command } },
    risk_labels: labels,
    data: { labels },
  };
}

export function formatSeverity(severity: string): string {
  return severity ? `${severity[0].toUpperCase()}${severity.slice(1)}` : "Unknown";
}

export function riskTone(severity: string): string {
  if (["critical", "high"].includes(severity)) return "border-rose-400/30 bg-rose-400/10 text-rose-200";
  if (severity === "medium") return "border-amber-400/30 bg-amber-400/10 text-amber-200";
  return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200";
}

export function mcpStatusTone(status: string): string {
  if (status === "active") return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200";
  if (status === "quarantined") return "border-amber-400/30 bg-amber-400/10 text-amber-200";
  if (status === "disabled") return "border-slate-400/30 bg-slate-400/10 text-slate-200";
  if (status === "error") return "border-rose-400/30 bg-rose-400/10 text-rose-200";
  return "border-white/10 bg-white/[0.04] text-slate-300";
}

export function mcpToolRiskLabels(tool: { riskLabels?: string[]; risk_labels?: string[]; riskScore?: number; risk_score?: number }): string[] {
  const labels = tool.riskLabels ?? tool.risk_labels ?? [];
  const score = tool.riskScore ?? tool.risk_score ?? 0;
  return [...labels, `score=${score.toFixed(2)}`];
}

export function eventDisplayName(event: { event_type: string; metadata?: Record<string, unknown> }): string {
  const metadata = event.metadata ?? {};
  return String(metadata.name ?? metadata.tool_name ?? metadata.model ?? event.event_type);
}

export function safeJson(value: string, fallback: unknown) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
