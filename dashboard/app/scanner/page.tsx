import { Shell } from "../../components/Shell";
import { ScannerForm } from "../../components/forms/ScannerForm";

export default function ScannerPage() {
  return (
    <Shell>
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Scanner Playground</h1>
        <p className="mt-2 text-slate-400">Paste untrusted tool, web, or document content and inspect prompt-injection evidence.</p>
      </div>
      <ScannerForm />
    </Shell>
  );
}
