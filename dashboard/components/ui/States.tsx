export function LoadingState({ label = "Loading" }: { label?: string }) {
  return <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4 text-sm text-slate-300">{label}...</div>;
}

export function EmptyState({ label = "No data" }: { label?: string }) {
  return <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-500">{label}</div>;
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="rounded-2xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-100">
      <div>{message}</div>
      {onRetry ? <button onClick={onRetry} className="mt-3 rounded-xl border border-rose-200/30 px-3 py-1">Retry</button> : null}
    </div>
  );
}
