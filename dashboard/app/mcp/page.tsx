import { Shell } from "../../components/Shell";
import { McpManager } from "../../components/forms/McpManager";

export default function McpPage() {
  return (
    <Shell>
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">MCP Manager</h1>
        <p className="mt-2 text-slate-400">Manage server registry, refresh tools, and test gateway calls.</p>
      </div>
      <McpManager />
    </Shell>
  );
}
