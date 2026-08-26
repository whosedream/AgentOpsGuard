import { GovernancePanel } from "../../../components/forms/GovernancePanel";
import { CapabilityGate } from "../../../components/ui/CapabilityGate";
import { canReadGovernance } from "../../../lib/auth";
import { serverAuthContext } from "../../../lib/server-api";

export default async function GovernancePage() {
  const auth = await serverAuthContext();

  return (
    <CapabilityGate
      allowed={canReadGovernance(auth)}
      title="Governance Control Plane"
      detail="This area is reserved for security reviewers and organization administrators."
    >
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Governance Control Plane</h1>
        <p className="mt-2 text-slate-400">Manage project configuration, approval queues, policy packs, scan rules, and run suppressions.</p>
      </div>
      <GovernancePanel />
    </CapabilityGate>
  );
}
