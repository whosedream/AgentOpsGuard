import { Shell } from "../../components/Shell";
import { PolicyForm } from "../../components/forms/PolicyForm";

export default function PolicyPage() {
  return (
    <Shell>
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Policy Playground</h1>
        <p className="mt-2 text-slate-400">Evaluate tool access, dangerous commands, and data-boundary decisions.</p>
      </div>
      <PolicyForm />
    </Shell>
  );
}
