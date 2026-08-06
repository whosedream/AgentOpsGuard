import { McpManager } from "../../../components/forms/McpManager";
import { CapabilityGate } from "../../../components/ui/CapabilityGate";
import { atLeastRole, canTestMcp } from "../../../lib/auth";
import { serverAuthContext } from "../../../lib/server-api";

export default async function McpPage() {
  const auth = await serverAuthContext();
  const allowed = canTestMcp(auth) && atLeastRole(auth, "developer");

  return (
    <CapabilityGate
      allowed={allowed}
      title="MCP Manager"
      detail="This area requires MCP test capability. Read-only users cannot access the MCP console."
    >
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">MCP Manager</h1>
        <p className="mt-2 text-slate-400">Manage server registry, refresh tools, and test gateway calls.</p>
      </div>
      <McpManager />
    </CapabilityGate>
  );
}
