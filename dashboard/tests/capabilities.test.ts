import { describe, expect, it } from "vitest";
import { canManageGovernance, canManageMcp } from "../lib/api";

describe("SPEC-P2-003 capability helpers", () => {
  it("maps scopes to governance and MCP permissions", () => {
    expect(canManageGovernance({ capabilities: ["policies:admin"], scopes: ["policies:admin"], kind: "project_key", is_operator: false })).toBe(true);
    expect(canManageMcp({ capabilities: ["mcp:admin"], scopes: ["mcp:admin"], kind: "project_key", is_operator: false })).toBe(true);
    expect(canManageGovernance({ capabilities: ["runs:read"], scopes: ["runs:read"], kind: "project_key", is_operator: false })).toBe(false);
  });
});
