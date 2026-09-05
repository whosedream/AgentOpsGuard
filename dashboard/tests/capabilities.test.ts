import { describe, expect, it } from "vitest";
import {
  buildExecutionsQuery,
  canManageGovernance,
  canManageJobs,
  canManageMcp,
  canReadJobs,
} from "../lib/api";

describe("SPEC-P2-003 capability helpers", () => {
  it("maps scopes to governance and MCP permissions", () => {
    const auth = (capability: string) => ({
      capabilities: [capability],
      scopes: [capability],
      kind: "project_key",
      memberships: [],
      is_operator: false,
    });

    expect(canManageGovernance(auth("policies:admin"))).toBe(true);
    expect(canManageMcp(auth("mcp:admin"))).toBe(true);
    expect(canReadJobs(auth("jobs:read"))).toBe(true);
    expect(canManageJobs(auth("jobs:admin"))).toBe(true);
    expect(canManageJobs(auth("jobs:read"))).toBe(false);
    expect(canManageGovernance(auth("runs:read"))).toBe(false);
  });

  it("builds an outcome-unknown execution queue without raw evidence fields", () => {
    expect(buildExecutionsQuery({ projectId: "project one" })).toBe(
      "/v1/executions?project_id=project+one&limit=50&page_mode=envelope&status=outcome_unknown",
    );
  });
});
