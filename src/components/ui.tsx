import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { Search, TriangleAlert } from "lucide-react";
import { FLAG_LABELS } from "../lib/api";
import { tr } from "../lib/i18n";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-2xl border border-white/8 bg-white/[0.04] backdrop-blur-sm ${className}`}>
      {children}
    </div>
  );
}

export function PageHeader({ title, subtitle, children }: { title: string; subtitle: string; children?: ReactNode }) {
  return (
    <div className="mb-5 flex items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="mt-1 text-sm text-white/50">{subtitle}</p>
      </div>
      {children}
    </div>
  );
}

export function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <label className="flex w-72 items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm focus-within:border-emerald-400/50">
      <Search size={15} className="text-white/40" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-transparent outline-none placeholder:text-white/30"
      />
    </label>
  );
}

export function Tabs<T extends string>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: { id: T; label: string }[] }) {
  return (
    <div className="flex gap-1 rounded-xl border border-white/10 bg-white/5 p-1 text-sm">
      {options.map((option) => (
        <button
          key={option.id}
          onClick={() => onChange(option.id)}
          className={`rounded-lg px-3 py-1 transition-colors ${
            value === option.id ? "bg-white/12 text-white" : "text-white/50 hover:text-white/80"
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "warn" | "accent" }) {
  const tones = {
    neutral: "bg-white/8 text-white/60",
    warn: "bg-amber-400/12 text-amber-300",
    accent: "bg-emerald-400/12 text-emerald-300",
  };
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-xs ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function FlagBadges({ flags }: { flags: string[] }) {
  return (
    <>
      {flags.map((flag) => (
        <Badge key={flag} tone="warn">
          <TriangleAlert size={11} />
          {FLAG_LABELS[flag] ?? flag}
        </Badge>
      ))}
    </>
  );
}

interface ConfirmProps {
  title: string;
  body: string;
  confirmLabel: string;
  /** Destructive actions get a red button. */
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** Modal question shown before an action that changes the system. */
export function ConfirmDialog({ title, body, confirmLabel, danger, onConfirm, onCancel }: ConfirmProps) {
  // Rendered into <body>: the animated page container would otherwise clip the overlay.
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6 backdrop-blur-sm" onClick={onCancel}>
      <div
        role="dialog"
        aria-modal="true"
        className="w-full max-w-md rounded-2xl border border-white/10 bg-[#121821] p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-base font-semibold">{title}</h2>
        <p className="mt-2 text-sm leading-relaxed text-white/60">{body}</p>
        <div className="mt-5 flex justify-end gap-2">
          <button autoFocus onClick={onCancel} className="rounded-lg bg-white/8 px-4 py-1.5 text-sm text-white/75 hover:bg-white/12">
            {tr("Отмена", "Cancel")}
          </button>
          <button
            onClick={onConfirm}
            className={`rounded-lg px-4 py-1.5 text-sm ${
              danger ? "bg-rose-500/20 text-rose-200 hover:bg-rose-500/30" : "bg-emerald-400/15 text-emerald-200 hover:bg-emerald-400/25"
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}

export function Loading() {
  return <div className="p-10 text-center text-sm text-white/40">{tr("Сбор данных…", "Collecting data…")}</div>;
}
