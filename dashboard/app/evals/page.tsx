import { Shell } from "../../components/Shell";
import { EvalStudio } from "../../components/forms/EvalStudio";

export default function EvalsPage() {
  return (
    <Shell>
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Eval Studio</h1>
        <p className="mt-2 text-slate-400">Create suites, run regression checks, and inspect pass/fail results.</p>
      </div>
      <EvalStudio />
    </Shell>
  );
}
