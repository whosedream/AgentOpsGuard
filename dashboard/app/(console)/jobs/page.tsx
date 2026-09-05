import { JobFailureQueue } from "../../../components/forms/JobFailureQueue";
import { CapabilityGate } from "../../../components/ui/CapabilityGate";
import { canReadJobs } from "../../../lib/auth";
import { serverAuthContext } from "../../../lib/server-api";

export default async function JobsPage() {
  const auth = await serverAuthContext();

  return (
    <CapabilityGate
      allowed={canReadJobs(auth)}
      title="Background Jobs"
      detail="Your current role cannot inspect background job state."
    >
      <div className="mb-8">
        <h1 className="text-4xl font-black text-white">Background Jobs</h1>
        <p className="mt-2 text-slate-400">
          Inspect retry state and jobs that stopped after the retry limit.
        </p>
      </div>
      <JobFailureQueue />
    </CapabilityGate>
  );
}
