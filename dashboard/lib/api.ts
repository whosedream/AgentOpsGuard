export {
  canAccessPolicy,
  canAccessScanner,
  canCreateReplay,
  canManageGovernance,
  canManageMcp,
  canReadGovernance,
  canReadRawContent,
  canRunEval,
  canTestMcp,
  hasCapability,
} from "./auth";

export function apiBase(): string {
  if (typeof window !== "undefined") {
    return window.localStorage.getItem("apiBase") ?? "/api/backend";
  }
  return process.env.NEXT_PUBLIC_AGENTOPS_API_URL ?? "http://localhost:8000";
}

export function gatewayBase(): string {
  if (typeof window !== "undefined") {
    return window.localStorage.getItem("gatewayBase") ?? "/api/gateway";
  }
  return "/api/gateway";
}

async function request<T>(base: string, path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`API ${path} failed: ${response.status}`);
  return response.json();
}

export async function apiGet<T>(path: string): Promise<T> {
  return request<T>(apiBase(), path);
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(apiBase(), path, { method: "POST", body: JSON.stringify(body ?? {}) });
}

export async function apiPatch<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(apiBase(), path, { method: "PATCH", body: JSON.stringify(body ?? {}) });
}

export async function apiDelete<T>(path: string): Promise<T> {
  return request<T>(apiBase(), path, { method: "DELETE" });
}

export async function gatewayGet<T>(path: string): Promise<T> {
  return request<T>(gatewayBase(), path);
}

export async function gatewayPost<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(gatewayBase(), path, { method: "POST", body: JSON.stringify(body ?? {}) });
}

export type AuthContext = {
  kind: string;
  user?: {
    id: string;
    email: string;
    display_name: string;
  } | null;
  organization_id?: string | null;
  memberships: Array<{
    id: string;
    organization_id: string;
    role: string;
    status: string;
  }>;
  active_membership_id?: string | null;
  active_role?: string | null;
  project_id?: string | null;
  scopes: string[];
  capabilities: string[];
  is_operator: boolean;
};

export type Page<T> = { items: T[]; next_cursor?: string | null };

export function pageItems<T>(value: T[] | Page<T>): T[] {
  return Array.isArray(value) ? value : value.items;
}

export function nextCursor<T>(value: T[] | Page<T>): string | null {
  return Array.isArray(value) ? null : (value.next_cursor ?? null);
}

function appendParam(params: URLSearchParams, key: string, value?: string | number | null) {
  if (value === undefined || value === null || value === "" || value === "all") return;
  params.set(key, String(value));
}

export function buildRunsQuery({
  projectId = "default",
  status = "all",
  agent = "",
  riskLabel = "",
  cursor,
  limit = 25,
}: {
  projectId?: string;
  status?: string;
  agent?: string;
  riskLabel?: string;
  cursor?: string | null;
  limit?: number;
}): string {
  const params = new URLSearchParams();
  params.set("project_id", projectId);
  params.set("limit", String(limit));
  params.set("page_mode", "envelope");
  appendParam(params, "cursor", cursor);
  appendParam(params, "status", status);
  appendParam(params, "agent", agent);
  appendParam(params, "risk_label", riskLabel);
  return `/v1/runs?${params.toString()}`;
}

export function buildRisksQuery({
  projectId = "default",
  severity = "all",
  cursor,
  limit = 25,
}: {
  projectId?: string;
  severity?: string;
  cursor?: string | null;
  limit?: number;
}): string {
  const params = new URLSearchParams();
  params.set("project_id", projectId);
  params.set("limit", String(limit));
  params.set("page_mode", "envelope");
  appendParam(params, "cursor", cursor);
  appendParam(params, "severity", severity);
  return `/v1/risks?${params.toString()}`;
}

export async function pollJob(id: string, attempts = 30, delayMs = 1000): Promise<Job> {
  let latest: Job | null = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    latest = await apiGet<Job>(`/v1/jobs/${id}`);
    if (["completed", "failed"].includes(latest.status)) return latest;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  if (latest) return latest;
  throw new Error(`Job ${id} did not return a status`);
}

export type Run = {
  id: string;
  project_id: string;
  agent_id?: string;
  trace_id: string;
  name?: string;
  status: string;
  risk_score: number;
  risk_labels: string[];
  total_cost_usd: number;
  total_tokens: number;
  started_at?: string;
  ended_at?: string;
};

export type TraceEvent = {
  id: string;
  run_id?: string;
  project_id?: string;
  trace_id?: string;
  span_id: string;
  parent_span_id?: string | null;
  event_type: string;
  status: string;
  risk_score: number;
  risk_labels: string[];
  metadata: Record<string, unknown>;
  input_ref?: string | null;
  output_ref?: string | null;
  created_at?: string;
};

export type ContentObject = {
  id: string;
  content_hash: string;
  summary?: string | null;
  redacted_text?: string | null;
  labels: string[];
};

export type RiskEvent = {
  id: string;
  project_id?: string;
  run_id?: string | null;
  event_id?: string | null;
  risk_type: string;
  severity: string;
  score: number;
  labels: string[];
  evidence?: Array<Record<string, unknown>>;
  description?: string;
  created_at: string;
};

export type ProjectConfig = {
  id: string;
  name: string;
  store_raw_content: boolean;
  retention_days: number;
  policy_fail_mode: string;
  status: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type ControlPlaneStatus = {
  project: ProjectConfig;
  pending_approvals: number;
  active_policy_packs: number;
  enabled_scan_rules: number;
  active_suppressions: number;
  run_statuses: Record<string, number>;
};

export type ApprovalRequest = {
  id: string;
  project_id: string;
  run_id?: string | null;
  action: string;
  status: string;
  reason_code: string;
  severity: string;
  risk_score: number;
  risk_labels: string[];
  created_at: string;
};

export type PolicyPack = {
  id: string;
  project_id: string;
  name: string;
  version: string;
  status: string;
  description?: string | null;
  rules: Array<Record<string, unknown>>;
  created_at: string;
};

export type ScanRule = {
  id: string;
  project_id: string;
  label: string;
  pattern: string;
  severity: string;
  score: number;
  status: string;
  description?: string | null;
  created_at: string;
};

export type SystemStatus = {
  api: { status: string; detail?: string };
  database: { status: string; detail?: string };
  gateway: { status: string; url?: string; detail?: string };
  counts: Record<string, number>;
  config: { project_id: string; store_raw_content: boolean; policy_fail_mode: string; retention_days?: number; status?: string };
};

export type ScanResponse = {
  risk_score: number;
  risk_labels: string[];
  evidence_spans: Array<{ label: string; start: number; end: number; snippet: string }>;
  sanitized_text: string;
  severity: string;
};

export type PolicyDecision = {
  action: string;
  reason_code: string;
  severity: string;
  matched_policy?: string;
  remediation?: string;
};

export type Replay = {
  id: string;
  project_id: string;
  source_run_id: string;
  mode: string;
  status: string;
  confidence: string;
  summary: Record<string, unknown>;
  diff: Array<Record<string, unknown>>;
  created_at: string;
};

export type EvalSuite = { id: string; project_id: string; name: string; description?: string; cases: unknown[]; created_at: string };
export type EvalRun = { id: string; project_id: string; suite_id?: string; status: string; passed: boolean; summary: Record<string, unknown>; results: Array<Record<string, unknown>>; created_at: string };
export type McpServer = { id: string; project_id: string; name: string; transport: string; command?: string; args: string[]; url?: string; trust_level: string; allowed_agents: string[]; status: string; created_at: string };
export type McpTool = { name: string; serverId?: string; server_id?: string; description?: string; riskScore?: number; risk_score?: number; riskLabels?: string[]; risk_labels?: string[]; status?: string };
export type Job = { id: string; project_id: string; kind: string; status: string; rq_job_id?: string | null; payload: Record<string, unknown>; result?: Record<string, unknown> | null; error?: string | null; attempts: number; created_at: string; started_at?: string | null; finished_at?: string | null };


