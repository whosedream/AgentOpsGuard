import { Shell } from "../../components/Shell";
import { ReplayStudio } from "../../components/forms/ReplayStudio";

export default function ReplaysPage() {
  return (
    <Shell>
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Replay Studio</h1>
        <p className="mt-2 text-slate-400">Create replay reports from captured runs and inspect failure suggestions.</p>
      </div>
      <ReplayStudio />
    </Shell>
  );
}
