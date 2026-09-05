import { describe, expect, it } from "vitest";
import { buildRunsQuery, buildRisksQuery, nextCursor, pageItems, pollJob } from "../lib/api";
import { buildPolicyPayload, eventDisplayName, formatSeverity, mcpStatusTone, mcpToolRiskLabels, riskTone } from "../lib/payloads";

describe("SPEC-POLICY-001 payload helpers", () => {
  it("builds a policy payload from form fields", () => {
    expect(
      buildPolicyPayload({
        projectId: "default",
        agentId: "coding-agent",
        toolName: "shell.execute",
        command: "rm -rf /",
        riskLabels: "credential_exfiltration, data_exfiltration",
      }),
    ).toEqual({
      project_id: "default",
      actor: { agent_id: "coding-agent" },
      tool: { name: "shell.execute", command: "rm -rf /", args: { command: "rm -rf /" } },
      risk_labels: ["credential_exfiltration", "data_exfiltration"],
      data: { labels: ["credential_exfiltration", "data_exfiltration"] },
    });
  });
});

describe("SPEC-RISK-001 severity formatting", () => {
  it("normalizes severity copy and tone", () => {
    expect(formatSeverity("critical")).toBe("Critical");
    expect(riskTone("critical")).toContain("rose");
    expect(riskTone("low")).toContain("emerald");
  });
});

describe("pagination helpers", () => {
  it("supports legacy arrays and envelope pages", () => {
    expect(pageItems([{ id: "legacy" }])).toEqual([{ id: "legacy" }]);
    expect(nextCursor([{ id: "legacy" }])).toBeNull();
    expect(pageItems({ items: [{ id: "page" }], next_cursor: "1" })).toEqual([{ id: "page" }]);
    expect(nextCursor({ items: [{ id: "page" }], next_cursor: "1" })).toBe("1");
  });
});

describe("job polling helper", () => {
  it("polls until completion", async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return new Response(JSON.stringify({ id: "job_1", project_id: "default", kind: "replay", status: calls > 1 ? "completed" : "running", payload: {}, attempts: 1, created_at: "now" }), { status: 200, headers: { "Content-Type": "application/json" } });
    };
    try {
      await expect(pollJob("job_1", 3, 1)).resolves.toMatchObject({ status: "completed" });
      expect(calls).toBe(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});


describe("SPEC-RUN-001 and SPEC-RISK-001 query builders", () => {
  it("builds stable URL query strings for runs filters", () => {
    expect(buildRunsQuery({ projectId: "demo", status: "completed", agent: "coder", riskLabel: "credential", cursor: "5", limit: 10 })).toBe(
      "/v1/runs?project_id=demo&limit=10&page_mode=envelope&cursor=5&status=completed&agent=coder&risk_label=credential",
    );
  });

  it("omits default filters for risks", () => {
    expect(buildRisksQuery({ projectId: "demo", severity: "all", limit: 25 })).toBe(
      "/v1/risks?project_id=demo&limit=25&page_mode=envelope",
    );
    expect(buildRisksQuery({ projectId: "demo", severity: "high", cursor: "25", limit: 25 })).toBe(
      "/v1/risks?project_id=demo&limit=25&page_mode=envelope&cursor=25&severity=high",
    );
  });
});


describe("SPEC-RUN-002 event inspector helpers", () => {
  it("builds stable labels for event inspector and DAG nodes", () => {
    expect(eventDisplayName({ event_type: "tool_call", metadata: { tool_name: "search.web" } })).toBe("search.web");
    expect(eventDisplayName({ event_type: "model_call", metadata: { model: "gpt-test" } })).toBe("gpt-test");
    expect(eventDisplayName({ event_type: "state_change", metadata: {} })).toBe("state_change");
  });
});

describe("SPEC-MCP-004 mcp helper formatting", () => {
  it("maps server status to stable tones", () => {
    expect(mcpStatusTone("active")).toContain("emerald");
    expect(mcpStatusTone("quarantined")).toContain("amber");
    expect(mcpStatusTone("disabled")).toContain("slate");
    expect(mcpStatusTone("error")).toContain("rose");
  });

  it("normalizes tool risk labels from gateway and API payloads", () => {
    expect(mcpToolRiskLabels({ riskLabels: ["instruction_override"], riskScore: 0.9 })).toEqual(["instruction_override", "score=0.90"]);
    expect(mcpToolRiskLabels({ risk_labels: [], risk_score: 0.1 })).toEqual(["score=0.10"]);
  });
});
