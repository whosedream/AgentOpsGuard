"use client";

import { useEffect, useState } from "react";

import { apiDelete, apiGet, apiPatch, apiPost, gatewayGet, gatewayPost, Job, McpServer, McpTool, pollJob } from "../../lib/api";
import { canManageMcp, canTestMcp } from "../../lib/auth";
import { mcpStatusTone, mcpToolRiskLabels } from "../../lib/payloads";
import { useDashboardAuth } from "../auth/AuthProvider";
import { ErrorState, LoadingState } from "../ui/States";

export function McpManager() {
  const auth = useDashboardAuth();
  const [servers, setServers] = useState<McpServer[]>([]);
  const [tools, setTools] = useState<McpTool[]>([]);
  const [name, setName] = useState("local_files");
  const [toolResult, setToolResult] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadServers() {
    setServers(await apiGet<McpServer[]>(`/v1/mcp/servers?project_id=${encodeURIComponent(auth.project_id ?? "default")}`).catch(() => []));
  }

  async function loadCachedTools() {
    setTools(await apiGet<McpTool[]>(`/v1/mcp/tools?project_id=${encodeURIComponent(auth.project_id ?? "default")}`).catch(() => []));
  }

  async function refreshTools() {
    setLoading(true);
    setError(null);
    try {
      const server = servers[0];
      if (server) {
        const queued = await apiPost<Job>(`/v1/mcp/servers/${server.id}/refresh`);
        setJob(queued);
        setJob(await pollJob(queued.id));
      }
      const response = await gatewayGet<{ tools: McpTool[] }>("/mcp/tools/list").catch(() => ({ tools: [] }));
      if (response.tools.length > 0) {
        setTools(response.tools);
      } else {
        await loadCachedTools();
      }
      await loadServers();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Tool refresh failed");
      await loadCachedTools();
      await loadServers();
    } finally {
      setLoading(false);
    }
  }

  async function createServer() {
    const created = await apiPost<McpServer>("/v1/mcp/servers", {
      id: name,
      name,
      project_id: auth.project_id ?? "default",
      transport: "stdio",
      trust_level: "internal",
      allowed_agents: [],
    });
    setServers([created, ...servers.filter((server) => server.id !== created.id)]);
  }

  async function deleteServer(id: string) {
    if (!window.confirm(`Delete MCP server ${id} and its cached tools?`)) return;
    await apiDelete(`/v1/mcp/servers/${id}`);
    setServers(servers.filter((server) => server.id !== id));
  }

  async function updateServerStatus(server: McpServer, status: "active" | "quarantined") {
    if (status === "quarantined" && !window.confirm(`Quarantine MCP server ${server.id}?`)) return;
    setError(null);
    try {
      const updated = await apiPatch<McpServer>(`/v1/mcp/servers/${server.id}`, { status });
      setServers(servers.map((item) => (item.id === updated.id ? updated : item)));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Server status update failed");
    }
  }

  async function testTool() {
    if (!canTestMcp(auth)) return;
    const tool = tools[0] ?? { name: "local_files.echo", serverId: "local_files" };
    const serverId = tool.serverId ?? tool.server_id ?? "local_files";
    const result = await gatewayPost<Record<string, unknown>>("/mcp/tools/call", { serverId, name: tool.name, arguments: { text: "hello" } });
    setToolResult(JSON.stringify(result, null, 2));
  }

  useEffect(() => {
    loadServers();
    loadCachedTools();
  }, [auth.project_id]);

  const canManage = canManageMcp(auth);
  const canTest = canTestMcp(auth);

  return (
    <div className="grid gap-6 lg:grid-cols-[0.8fr_1fr]">
      <section className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
        <label className="text-sm font-semibold text-slate-300">Server ID</label>
        <input value={name} onChange={(event) => setName(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950 p-3" />
        <div className="mt-4 flex flex-wrap gap-3">
          <button onClick={createServer} disabled={!canManage} className="rounded-xl border border-cyan-300/30 px-4 py-2 text-cyan-200 disabled:opacity-50">Create server</button>
          <button onClick={refreshTools} disabled={!canManage} className="rounded-xl bg-cyan-300 px-4 py-2 font-semibold text-slate-950 disabled:opacity-50">Refresh tools</button>
          <button onClick={testTool} disabled={!canTest} className="rounded-xl border border-white/10 px-4 py-2 disabled:opacity-50">Test tool</button>
        </div>
        <div className="mt-5 space-y-2">
          {servers.map((server) => (
            <div key={server.id} className="rounded-xl border border-white/10 p-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-semibold text-white">{server.name}</div>
                  <div className="text-xs text-slate-500">{server.transport} · {server.trust_level}</div>
                </div>
                <span className={`rounded-full border px-2 py-1 text-xs ${mcpStatusTone(server.status)}`}>{server.status}</span>
              </div>
              <div className="mt-3 flex flex-wrap gap-3 text-sm">
                {server.status === "quarantined" ? (
                  <button onClick={() => updateServerStatus(server, "active")} disabled={!canManage} className="text-emerald-200 disabled:opacity-50">Restore</button>
                ) : (
                  <button onClick={() => updateServerStatus(server, "quarantined")} disabled={!canManage} className="text-amber-200 disabled:opacity-50">Quarantine</button>
                )}
                <button onClick={() => deleteServer(server.id)} disabled={!canManage} className="text-rose-200 disabled:opacity-50">Delete</button>
              </div>
            </div>
          ))}
        </div>
        {loading ? <div className="mt-4"><LoadingState label="MCP refresh job running" /></div> : null}
        {error ? <div className="mt-4"><ErrorState message={error} onRetry={refreshTools} /></div> : null}
        {job ? (
          <div className="mt-4 rounded-xl border border-white/10 p-3 text-sm text-slate-300">
            <div>Job {job.id}: {job.status}{job.error ? ` · ${job.error}` : ""}</div>
            {job.result ? <pre className="mt-2 overflow-auto text-xs text-slate-500">{JSON.stringify(job.result, null, 2)}</pre> : null}
          </div>
        ) : null}
      </section>
      <section className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
        <h2 className="text-xl font-bold">Tools</h2>
        <div className="mt-4 space-y-3">
          {tools.map((tool) => (
            <div key={`${tool.serverId ?? tool.server_id}:${tool.name}`} className="rounded-xl border border-white/10 p-3">
              <div className="flex items-center justify-between gap-3">
                <b>{tool.name}</b>
                <span className={`rounded-full border px-2 py-1 text-xs ${mcpStatusTone(tool.status ?? "active")}`}>{tool.status ?? "active"}</span>
              </div>
              {tool.description ? <div className="mt-2 text-sm text-slate-400">{tool.description}</div> : null}
              <div className="mt-3 flex flex-wrap gap-2">
                {mcpToolRiskLabels(tool).map((label) => (
                  <span key={label} className="rounded-full border border-white/10 bg-white/[0.04] px-2 py-1 text-xs text-slate-300">{label}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
        {toolResult ? <pre className="mt-4 overflow-auto rounded-2xl bg-slate-950/80 p-4 text-sm text-slate-300">{toolResult}</pre> : null}
      </section>
    </div>
  );
}
