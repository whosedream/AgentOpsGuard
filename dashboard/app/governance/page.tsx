import { Shell } from "../../components/Shell";
import { GovernancePanel } from "../../components/forms/GovernancePanel";

export default function GovernancePage() {
  return (
    <Shell>
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Governance Control Plane</h1>
        <p className="mt-2 text-slate-400">Manage project configuration, approval queues, policy packs, scan rules, and run suppressions.</p>
      </div>
      <GovernancePanel />
    </Shell>
  );
}
