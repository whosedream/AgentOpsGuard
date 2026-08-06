import { describe, expect, it } from "vitest";
import { canManageGovernance, canManageMcp } from "../lib/api";

describe("v1 auth context capability mapping", () => {
  it("keeps read_only users out of governance and MCP admin actions", () => {
    const auth = {
      kind: "session_user",
      organization_id: "org_1",
      project_id: "project_1",
      scopes: [],
      capabilities: ["runs:read", "replays:read"],
      is_operator: false,
      active_role: "read_only",
      memberships: [],
    };
    expect(canManageGovernance(auth as never)).toBe(false);
    expect(canManageMcp(auth as never)).toBe(false);
  });
});
