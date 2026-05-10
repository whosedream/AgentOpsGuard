import { Shell } from "../../components/Shell";
import { SetupStatus } from "../../components/forms/SetupStatus";

export default function SetupPage() {
  return (
    <Shell>
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">System Setup</h1>
        <p className="mt-2 text-slate-400">Check API, database, gateway, and local configuration before operating agents.</p>
      </div>
      <SetupStatus />
    </Shell>
  );
}
