import { ScannerForm } from "../../../components/forms/ScannerForm";
import { CapabilityGate } from "../../../components/ui/CapabilityGate";
import { canAccessScanner } from "../../../lib/auth";
import { serverAuthContext } from "../../../lib/server-api";

export default async function ScannerPage() {
  const auth = await serverAuthContext();

  return (
    <CapabilityGate
      allowed={canAccessScanner(auth)}
      title="Scanner Playground"
      detail="Scanner access is available to developers, reviewers and administrators."
    >
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Scanner Playground</h1>
        <p className="mt-2 text-slate-400">Paste untrusted tool, web, or document content and inspect prompt-injection evidence.</p>
      </div>
      <ScannerForm />
    </CapabilityGate>
  );
}
