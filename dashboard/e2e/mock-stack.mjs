import { spawn } from "node:child_process";
import { createServer } from "node:http";

const dashboardPort = Number(process.env.DASHBOARD_PORT ?? "3100");
const backendPort = Number(process.env.MOCK_BACKEND_PORT ?? "38000");
const gatewayPort = Number(process.env.MOCK_GATEWAY_PORT ?? "38001");

const now = () => new Date().toISOString();

const run = {
  id: "run_demo",
  project_id: "default",
  agent_id: "demo-agent",
  trace_id: "trace_demo",
  name: "demo trace",
  status: "completed",
  risk_score: 0,
  risk_labels: [],
  total_cost_usd: 0,
  total_tokens: 0,
};

const risk = {
  id: "risk_1",
  project_id: "default",
  run_id: "run_demo",
  event_id: "evt_model",
  risk_type: "instruction_override",
  severity: "critical",
  score: 0.9,
  labels: ["instruction_override"],
  evidence: [{ label: "instruction_override", snippet: "Ignore previous instructions" }],
  description: "Prompt injection",
  created_at: now(),
};

const server = {
  id: "local_files",
  project_id: "default",
  name: "local_files",
  transport: "stdio",
  trust_level: "internal",
  allowed_agents: [],
  status: "active",
  created_at: now(),
};

const tool = {
  id: "local_files:local_files.echo",
  project_id: "default",
  server_id: "local_files",
  name: "local_files.echo",
  serverId: "local_files",
  description: "Echo",
  input_schema: { type: "object" },
  annotations: {},
  risk_score: 0,
  riskScore: 0,
  risk_labels: [],
  riskLabels: [],
  status: "active",
  created_at: now(),
};

const suite = { id: "suite_1", project_id: "default", name: "UI Suite", cases: [{ name: "case" }], created_at: now() };
const evalRun = {
  id: "eval_1",
  project_id: "default",
  suite_id: "suite_1",
  status: "completed",
  passed: true,
  summary: { case_count: 1, passed_count: 1, failed_count: 0 },
  results: [{ name: "case", passed: true, failures: [] }],
  created_at: now(),
};

const roleCapabilities = {
  read_only: ["projects:read", "runs:read", "replays:read", "evals:read", "mcp:read", "jobs:read"],
  developer: ["projects:read", "runs:read", "runs:write", "replays:read", "replays:write", "evals:read", "evals:write", "policies:read", "scanner:read", "mcp:read", "mcp:invoke", "jobs:read"],
  security_reviewer: ["projects:read", "control:read", "approvals:read", "approvals:write", "audit:read", "runs:read", "replays:read", "evals:read", "raw_content:read", "policies:read", "scanner:read", "jobs:read"],
  admin: ["organizations:write", "projects:read", "projects:write", "control:read", "control:admin", "mcp:read", "mcp:invoke", "mcp:admin", "runs:read", "runs:write", "replays:read", "replays:write", "evals:read", "evals:write", "approvals:read", "approvals:write", "audit:read", "raw_content:read", "api_keys:write", "policies:read", "policies:admin", "scanner:read", "scanner:admin", "jobs:read", "jobs:admin", "runs:admin"],
};

function envelope(items) {
  return { items, next_cursor: null };
}

function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...extraHeaders });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
  });
}

function authContext(role) {
  return {
    kind: "session_user",
    user: { id: `user_${role}`, email: `${role}@example.com`, display_name: role },
    organization_id: "org_demo",
    memberships: [{ id: `membership_${role}`, organization_id: "org_demo", role, status: "active" }],
    active_membership_id: `membership_${role}`,
    active_role: role,
    project_id: "default",
    scopes: [],
    capabilities: roleCapabilities[role],
    is_operator: false,
  };
}

function currentRole(req) {
  const cookie = req.headers.cookie ?? "";
  const match = cookie.match(/agentops_session=([^;]+)/);
  if (!match) return null;
  const value = decodeURIComponent(match[1]);
  if (!value.startsWith("sess_")) return null;
  const role = value.slice(5);
  return roleCapabilities[role] ? role : null;
}

function job(id, kind, result) {
  return { id, project_id: "default", kind, status: "completed", rq_job_id: null, payload: {}, result, error: null, attempts: 1, created_at: now(), started_at: now(), finished_at: now() };
}

function startBackend() {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://127.0.0.1:${backendPort}`);
    const role = currentRole(req);

    if (req.method === "POST" && url.pathname === "/v1/auth/dev-login") {
      const payload = JSON.parse((await readBody(req)) || "{}");
      const sessionRole = payload.role ?? "admin";
      return json(res, 200, {
        session_id: `sess_${sessionRole}`,
        user: { id: `user_${sessionRole}`, email: payload.email, display_name: payload.display_name, auth_provider: "dev_stub", status: "active", created_at: now() },
        membership: { id: `membership_${sessionRole}`, organization_id: "org_demo", user_id: `user_${sessionRole}`, role: sessionRole, status: "active", created_at: now(), user: { id: `user_${sessionRole}`, email: payload.email, display_name: payload.display_name, auth_provider: "dev_stub", status: "active", created_at: now() } },
        project_id: "default",
      }, { "Set-Cookie": `agentops_session=sess_${sessionRole}; Path=/; HttpOnly; SameSite=Lax` });
    }

    if (req.method === "POST" && url.pathname === "/v1/auth/logout") {
      return json(res, 200, { status: "ok" }, { "Set-Cookie": "agentops_session=; Path=/; Max-Age=0" });
    }

    if (url.pathname === "/v1/health") return json(res, 200, { status: "ok" });

    if (url.pathname === "/v1/auth/context") {
      if (!role) return json(res, 401, { detail: "Authentication required" });
      return json(res, 200, authContext(role));
    }

    if (!role) return json(res, 401, { detail: "Authentication required" });

    if (url.pathname === "/v1/system/status") {
      return json(res, 200, {
        api: { status: "ok" },
        database: { status: "ok" },
        gateway: { status: "unknown", url: `http://127.0.0.1:${gatewayPort}` },
        counts: { runs: 1, risks: 1, eval_suites: 1, eval_runs: 1, replays: 1, mcp_servers: 1, mcp_tools: 1 },
        config: { project_id: "default", store_raw_content: false, policy_fail_mode: "closed_for_high_risk" },
      });
    }
    if (url.pathname === "/v1/runs") return json(res, 200, url.searchParams.get("page_mode") === "envelope" ? envelope([run]) : [run]);
    if (url.pathname === "/v1/runs/run_demo") return json(res, 200, run);
    if (url.pathname === "/v1/runs/run_demo/events") return json(res, 200, [{ id: "evt_model", run_id: "run_demo", project_id: "default", trace_id: "trace_demo", span_id: "span_model", parent_span_id: null, event_type: "model_call", status: "completed", actor: {}, metadata: { model: "demo" }, risk_score: 0, risk_labels: [], created_at: now() }]);
    if (url.pathname === "/v1/risks") return json(res, 200, url.searchParams.get("page_mode") === "envelope" ? envelope([risk]) : [risk]);
    if (req.method === "POST" && url.pathname === "/v1/scanner/scan") return json(res, 200, { risk_score: 0.75, risk_labels: ["instruction_override"], evidence_spans: [{ label: "instruction_override", start: 0, end: 28, snippet: "Ignore previous instructions" }], sanitized_text: "Ignore previous instructions", severity: "high" });
    if (req.method === "POST" && url.pathname === "/v1/policies/evaluate") return json(res, 200, { action: "deny", reason_code: "dangerous_command", severity: "critical", matched_policy: "dangerous_command", remediation: "Replace the command." });
    if (url.pathname === "/v1/replays") {
      const replay = { id: "replay_1", project_id: "default", source_run_id: "run_demo", mode: "exact", status: "completed", confidence: "high", summary: { likely_failure_reason: req.method === "POST" ? "policy_blocked_high_risk_action" : "no_failure_detected", suggestions: ["Review policy"] }, diff: [], created_at: now() };
      return json(res, 200, req.method === "POST" ? replay : [replay]);
    }
    if (url.pathname === "/v1/replays/jobs") return json(res, 200, job("job_replay", "replay", { replay_id: "replay_1", status: "completed" }));
    if (url.pathname === "/v1/eval-suites") return json(res, 200, req.method === "POST" ? suite : [suite]);
    if (url.pathname === "/v1/eval-suites/suite_1/jobs") return json(res, 200, job("job_eval", "eval_run", { eval_run_id: "eval_1", status: "completed", passed: true }));
    if (url.pathname === "/v1/eval-runs") return json(res, 200, url.searchParams.get("page_mode") === "envelope" ? envelope([evalRun]) : [evalRun]);
    if (url.pathname === "/v1/jobs/reconciliation") return json(res, 200, { project_id: "default", stale_pending_jobs: 0, expired_running_jobs: 0, dead_jobs: 1, undelivered_outbox_events: 0, outcome_unknown_executions: 0, checked_at: now() });
    if (url.pathname === "/v1/jobs") {
      const failedJob = { ...job("job_dead", "eval_run", null), status: "dead", error: "job_execution_failed", attempts: 3 };
      return json(res, 200, url.searchParams.get("page_mode") === "envelope" ? envelope([failedJob]) : [failedJob]);
    }
    if (req.method === "POST" && url.pathname === "/v1/jobs/job_dead/retry") return json(res, 200, job("job_retry", "eval_run", null));
    if (url.pathname === "/v1/jobs/job_eval") return json(res, 200, job("job_eval", "eval_run", { eval_run_id: "eval_1", status: "completed", passed: true }));
    if (url.pathname === "/v1/jobs/job_replay") return json(res, 200, job("job_replay", "replay", { replay_id: "replay_1", status: "completed" }));
    if (url.pathname === "/v1/jobs/job_mcp") return json(res, 200, job("job_mcp", "mcp_refresh", { server_id: "local_files", status: "completed", tools: 1 }));
    if (url.pathname === "/v1/mcp/servers") return json(res, 200, req.method === "POST" ? server : [server]);
    if (url.pathname === "/v1/mcp/tools") return json(res, 200, [tool]);
    if (url.pathname === "/v1/mcp/servers/local_files/refresh") return json(res, 200, job("job_mcp", "mcp_refresh", { server_id: "local_files", status: "completed", tools: 1 }));
    if (url.pathname === "/v1/mcp/servers/local_files") return json(res, 200, req.method === "DELETE" ? { status: "deleted", id: "local_files" } : server);
    if (url.pathname === "/v1/control-plane/status") {
      if (!roleCapabilities[role].includes("control:read") && role !== "admin") return json(res, 403, { detail: "forbidden" });
      return json(res, 200, {
        project: { id: "default", organization_id: "org_demo", name: "Default Project", store_raw_content: false, retention_days: 30, policy_fail_mode: "closed_for_high_risk", status: "active", metadata: {}, created_at: now() },
        pending_approvals: 1,
        active_policy_packs: 1,
        enabled_scan_rules: 1,
        active_suppressions: 0,
        run_statuses: { completed: 1 },
      });
    }
    if (url.pathname === "/v1/approvals") return json(res, 200, envelope([{ id: "approval_1", project_id: "default", run_id: "run_demo", action: "require_approval", status: "pending", reason_code: "manual_review", severity: "high", risk_score: 0.9, risk_labels: ["instruction_override"], created_at: now() }]));
    if (url.pathname === "/v1/approvals/approval_1/review") return json(res, roleCapabilities[role].includes("approvals:write") ? 200 : 403, { status: "ok" });
    if (url.pathname === "/v1/policy-packs") return json(res, 200, envelope([{ id: "pack_1", family_id: "family_1", project_id: "default", name: "High risk approval gate", version: "0.7.0", status: "active", description: "", rules: [{}], created_at: now() }]));
    if (url.pathname === "/v1/scanner/rules") return json(res, 200, envelope([{ id: "rule_1", project_id: "default", label: "custom_sensitive_transfer", pattern: "wire money", severity: "high", score: 0.8, status: "enabled", created_at: now() }]));
    if (url.pathname.startsWith("/v1/projects/")) return json(res, role === "admin" ? 200 : 403, { status: "ok" });
    if (url.pathname.startsWith("/v1/content/")) {
      if (!roleCapabilities[role].includes("raw_content:read")) return json(res, 403, { detail: "forbidden" });
      return json(res, 200, { id: "content_1", content_hash: "abcdef1234567890", redacted_text: "redacted sample", labels: ["instruction_override"] });
    }

    return json(res, 404, { detail: "Not Found" });
  }).listen(backendPort, "127.0.0.1");
}

function startGateway() {
  return createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://127.0.0.1:${gatewayPort}`);
    if (url.pathname === "/mcp/tools/list") return json(res, 200, { tools: [tool] });
    if (url.pathname === "/mcp/tools/call") return json(res, 200, { content: [{ type: "text", text: "hello" }], policyDecision: { action: "allow" }, risk: { risk_labels: [] } });
    return json(res, 404, { detail: "Not Found" });
  }).listen(gatewayPort, "127.0.0.1");
}

const backend = startBackend();
const gateway = startGateway();

const child = spawn(
  process.execPath,
  ["./node_modules/next/dist/bin/next", "dev", "--hostname", "127.0.0.1", "--port", String(dashboardPort)],
  {
    stdio: "inherit",
    env: {
      ...process.env,
      AGENTOPS_SERVER_API_URL: `http://127.0.0.1:${backendPort}`,
      AGENTOPS_SERVER_GATEWAY_URL: `http://127.0.0.1:${gatewayPort}`,
      NEXT_PUBLIC_AGENTOPS_ENV: "dev",
    },
  },
);

function shutdown(code = 0) {
  backend.close();
  gateway.close();
  child.kill("SIGTERM");
  setTimeout(() => process.exit(code), 250);
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));
child.on("exit", (code) => shutdown(code ?? 0));
