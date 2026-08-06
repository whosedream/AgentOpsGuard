"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { CircleAlert, LockKeyhole, ShieldCheck } from "lucide-react";

type LoginRole = "admin" | "security_reviewer" | "developer" | "read_only";

const roleOptions: Array<{ id: LoginRole; label: string; detail: string }> = [
  { id: "admin", label: "Admin", detail: "Full governance and organization control." },
  { id: "security_reviewer", label: "Reviewer", detail: "Approval, audit, risk and raw content access." },
  { id: "developer", label: "Developer", detail: "Runs, replay, eval, scanner, policy, MCP test." },
  { id: "read_only", label: "Read-only", detail: "Visibility into setup, runs, risks and results." },
];

function envMode(): "prod" | "dev" {
  return process.env.NEXT_PUBLIC_AGENTOPS_ENV === "prod" ? "prod" : "dev";
}

export function LoginPanel() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@example.com");
  const [displayName, setDisplayName] = useState("AgentOps Admin");
  const [organizationName, setOrganizationName] = useState("Default Organization");
  const [role, setRole] = useState<LoginRole>("admin");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isProd = useMemo(() => envMode() === "prod", []);

  async function submit() {
    if (isProd) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/backend/v1/auth/dev-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          display_name: displayName,
          role,
          organization_name: organizationName || undefined,
        }),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      router.replace("/");
      router.refresh();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rounded-[28px] border border-white/10 bg-slate-950/80 p-7 shadow-2xl shadow-slate-950/50 backdrop-blur xl:p-8">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="text-sm font-semibold uppercase tracking-[0.22em] text-slate-500">Dashboard Session</div>
          <h2 className="mt-2 text-2xl font-black text-white">Sign in</h2>
        </div>
        <div className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] ${isProd ? "border-amber-400/30 bg-amber-400/10 text-amber-200" : "border-emerald-400/30 bg-emerald-400/10 text-emerald-200"}`}>
          {isProd ? <LockKeyhole className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
          {isProd ? "prod" : "dev stub"}
        </div>
      </div>

      {isProd ? (
        <div className="mt-6 rounded-2xl border border-amber-400/25 bg-amber-400/10 p-4 text-sm text-amber-100">
          <div className="flex items-center gap-2 font-semibold">
            <CircleAlert className="h-4 w-4" />
            OIDC not enabled
          </div>
          <p className="mt-2 leading-6 text-amber-100/80">
            Production mode does not allow stub login. Configure the OIDC provider seam before enabling dashboard sign-in.
          </p>
        </div>
      ) : null}

      <div className="mt-6 space-y-4">
        <label className="block text-sm font-semibold text-slate-300">
          Email
          <input
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            disabled={isProd || loading}
            className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-900/90 px-4 py-3 text-slate-100 outline-none transition focus:border-cyan-300/60 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </label>
        <label className="block text-sm font-semibold text-slate-300">
          Display name
          <input
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
            disabled={isProd || loading}
            className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-900/90 px-4 py-3 text-slate-100 outline-none transition focus:border-cyan-300/60 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </label>
        <label className="block text-sm font-semibold text-slate-300">
          Organization
          <input
            value={organizationName}
            onChange={(event) => setOrganizationName(event.target.value)}
            disabled={isProd || loading}
            className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-900/90 px-4 py-3 text-slate-100 outline-none transition focus:border-cyan-300/60 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </label>
      </div>

      <div className="mt-6">
        <div className="text-sm font-semibold text-slate-300">Role</div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {roleOptions.map((option) => {
            const active = option.id === role;
            return (
              <button
                key={option.id}
                type="button"
                onClick={() => setRole(option.id)}
                disabled={isProd || loading}
                className={`rounded-2xl border p-4 text-left transition ${active ? "border-cyan-300/50 bg-cyan-400/10 text-cyan-50" : "border-white/10 bg-white/[0.03] text-slate-300 hover:border-white/20 hover:bg-white/[0.05]"} disabled:cursor-not-allowed disabled:opacity-60`}
              >
                <div className="text-sm font-semibold">{option.label}</div>
                <div className="mt-2 text-sm leading-6 text-slate-400">{option.detail}</div>
              </button>
            );
          })}
        </div>
      </div>

      {error ? <div className="mt-5 rounded-2xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-100">{error}</div> : null}

      <button
        type="button"
        onClick={submit}
        disabled={isProd || loading}
        className="mt-6 w-full rounded-2xl bg-cyan-300 px-5 py-3.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {loading ? "Signing in..." : "Start session"}
      </button>
    </div>
  );
}
