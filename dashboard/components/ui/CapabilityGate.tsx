import type { AuthContext } from "../../lib/api";

export function CapabilityGate({
  allowed,
  title,
  detail,
  children,
}: {
  allowed: boolean;
  title: string;
  detail: string;
  children: React.ReactNode;
}) {
  if (allowed) return <>{children}</>;
  return (
    <section className="rounded-[24px] border border-amber-400/20 bg-amber-400/10 p-6 text-amber-50">
      <div className="text-sm font-semibold uppercase tracking-[0.22em] text-amber-200/80">Restricted</div>
      <h1 className="mt-2 text-2xl font-black text-white">{title}</h1>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-amber-50/80">{detail}</p>
    </section>
  );
}
