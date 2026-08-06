import { PolicyForm } from "../../../components/forms/PolicyForm";
import { CapabilityGate } from "../../../components/ui/CapabilityGate";
import { canAccessPolicy } from "../../../lib/auth";
import { serverAuthContext } from "../../../lib/server-api";

export default async function PolicyPage() {
  const auth = await serverAuthContext();

  return (
    <CapabilityGate
      allowed={canAccessPolicy(auth)}
      title="Policy Playground"
      detail="Policy evaluation is available to developers, reviewers and administrators."
    >
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Policy Playground</h1>
        <p className="mt-2 text-slate-400">Evaluate tool access, dangerous commands, and data-boundary decisions.</p>
      </div>
      <PolicyForm />
    </CapabilityGate>
  );
}
