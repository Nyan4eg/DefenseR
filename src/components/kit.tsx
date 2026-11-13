// Building blocks shared by the list pages: program avatars, summary tiles, meters, switches
// and empty states. Motion is done in CSS (see index.css), so long lists that refresh every
// few seconds stay cheap.

import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { tr } from "../lib/i18n";

/** Names people know programs by, for the executables that are hard to recognise. */
const KNOWN_NAMES: Record<string, string> = {
  chrome: "Google Chrome",
  msedge: "Microsoft Edge",
  msedgewebview2: tr("Встроенный браузер Edge", "Edge WebView"),
  firefox: "Firefox",
  explorer: tr("Проводник Windows", "File Explorer"),
  svchost: tr("Службы Windows", "Windows services"),
  code: "Visual Studio Code",
  msmpeng: "Microsoft Defender",
  mpdefendercoreservice: "Microsoft Defender",
  searchhost: tr("Поиск Windows", "Windows Search"),
  dwm: tr("Оформление окон Windows", "Desktop Window Manager"),
  system: tr("Ядро Windows", "Windows kernel"),
  registry: tr("Реестр Windows", "Windows Registry"),
  taskmgr: tr("Диспетчер задач", "Task Manager"),
  powershell: "PowerShell",
  pwsh: "PowerShell",
  cmd: tr("Командная строка", "Command Prompt"),
  conhost: tr("Окно консоли", "Console window"),
  winword: "Microsoft Word",
  excel: "Microsoft Excel",
  outlook: "Microsoft Outlook",
  "ms-teams": "Microsoft Teams",
  onedrive: "OneDrive",
  defenser: "DefenseR",
};

/** A readable name for an executable: "chrome.exe" becomes "Google Chrome", "Foo.exe" becomes "Foo". */
export function friendlyName(file: string): string {
  const base = file.replace(/\.(exe|lnk)$/i, "");
  return KNOWN_NAMES[base.toLowerCase()] ?? base;
}

function hashOf(text: string): number {
  let hash = 0;
  for (const char of text.toLowerCase()) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return hash;
}

/** A coloured tile with the program's initial; the colour is the same for the same name everywhere. */
export function Avatar({ name, size = 36, muted = false }: { name: string; size?: number; muted?: boolean }) {
  const hue = hashOf(name) % 360;
  const letter = (friendlyName(name).match(/[\p{L}\p{N}]/u)?.[0] ?? "?").toUpperCase();
  const style: CSSProperties = {
    width: size,
    height: size,
    fontSize: size * 0.42,
    background: muted ? "rgb(255 255 255 / 0.06)" : `linear-gradient(135deg, hsl(${hue} 70% 55% / 0.9), hsl(${(hue + 40) % 360} 75% 42% / 0.9))`,
  };
  return (
    <div style={style} className={`flex shrink-0 items-center justify-center rounded-xl font-semibold ${muted ? "text-white/40" : "text-white shadow-lg shadow-black/20"}`}>
      {letter}
    </div>
  );
}

/** Counts up to `value` when it changes, so numbers settle instead of jumping. */
function useCountUp(value: number): number {
  const [shown, setShown] = useState(value);
  const from = useRef(value);
  useEffect(() => {
    const start = from.current;
    if (start === value) return;
    const began = performance.now();
    let frame = 0;
    const step = (now: number) => {
      const progress = Math.min(1, (now - began) / 450);
      const eased = 1 - (1 - progress) ** 3;
      setShown(Math.round(start + (value - start) * eased));
      if (progress < 1) frame = requestAnimationFrame(step);
      else from.current = value;
    };
    frame = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(frame);
      from.current = value;
    };
  }, [value]);
  return shown;
}

type Tone = "accent" | "warn" | "danger" | "neutral" | "info";

const TONES: Record<Tone, { text: string; glow: string; ring: string; bar: string }> = {
  accent: { text: "text-emerald-300", glow: "from-emerald-400/25", ring: "ring-emerald-400/50", bar: "from-emerald-400 to-cyan-400" },
  info: { text: "text-cyan-300", glow: "from-cyan-400/25", ring: "ring-cyan-400/50", bar: "from-cyan-400 to-sky-400" },
  warn: { text: "text-amber-300", glow: "from-amber-400/25", ring: "ring-amber-400/50", bar: "from-amber-400 to-orange-400" },
  danger: { text: "text-rose-300", glow: "from-rose-400/25", ring: "ring-rose-400/50", bar: "from-rose-400 to-pink-500" },
  neutral: { text: "text-white/70", glow: "from-white/10", ring: "ring-white/30", bar: "from-white/40 to-white/25" },
};

interface StatTileProps {
  icon: LucideIcon;
  label: string;
  value: number;
  /** Shown after the number, e.g. a unit. */
  suffix?: string;
  hint?: string;
  tone?: Tone;
  /** 0 to 1: draws a bar under the number, for values that are a share of something. */
  meter?: number;
  /** Makes the tile a button (a filter, or a way to another page); `active` marks the chosen one. */
  onClick?: () => void;
  active?: boolean;
}

/** A number with a label. As a button it filters the list below it. */
export function StatTile({ icon: Icon, label, value, suffix, hint, tone = "neutral", meter, onClick, active }: StatTileProps) {
  const shown = useCountUp(value);
  const colours = TONES[tone];
  const Element = onClick ? "button" : "div";
  return (
    <Element
      onClick={onClick}
      className={`group relative min-w-0 flex-1 overflow-hidden rounded-2xl border border-white/8 bg-white/[0.04] px-4 py-3 text-left transition duration-200 ${
        onClick ? "hover:-translate-y-0.5 hover:border-white/15 hover:bg-white/[0.06]" : ""
      } ${active ? `ring-1 ${colours.ring} bg-white/[0.07]` : ""}`}
    >
      <div className={`pointer-events-none absolute -right-6 -top-6 size-20 rounded-full bg-gradient-to-br ${colours.glow} to-transparent blur-xl transition-opacity ${active ? "opacity-100" : "opacity-60 group-hover:opacity-100"}`} />
      <div className="flex items-center gap-2 text-xs text-white/50">
        <Icon size={14} className={colours.text} />
        <span className="truncate">{label}</span>
      </div>
      <div className="mt-1.5 flex items-baseline gap-1">
        <span className="text-2xl font-semibold tabular-nums tracking-tight">{shown}</span>
        {suffix && <span className="text-sm text-white/45">{suffix}</span>}
      </div>
      {meter != null && <Meter value={meter} tone={tone} className="mb-1.5 mt-1.5" />}
      {hint && <div className="mt-0.5 truncate text-xs text-white/35">{hint}</div>}
    </Element>
  );
}

/** An icon on a softly glowing tile: the head of a card or of a row. */
export function IconTile({ icon: Icon, tone = "accent", size = 36 }: { icon: LucideIcon; tone?: Tone; size?: number }) {
  return (
    <div className="relative flex shrink-0 items-center justify-center" style={{ width: size, height: size }}>
      <div className={`absolute inset-0 rounded-full bg-gradient-to-br ${TONES[tone].glow} to-transparent blur-md`} />
      <div className="relative flex size-full items-center justify-center rounded-xl border border-white/10 bg-white/[0.05]">
        <Icon size={Math.round(size * 0.47)} className={TONES[tone].text} />
      </div>
    </div>
  );
}

/** A thin bar that fills to `value` (0 to 1) and glides when the value changes. */
export function Meter({ value, tone = "accent", className = "" }: { value: number; tone?: Tone; className?: string }) {
  return (
    <div className={`h-1.5 overflow-hidden rounded-full bg-white/8 ${className}`}>
      <div className={`h-full rounded-full bg-gradient-to-r ${TONES[tone].bar} transition-[width] duration-700 ease-out`} style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }} />
    </div>
  );
}

interface SwitchProps {
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
  /** Read by screen readers and shown as a tooltip. */
  label?: string;
}

export function Switch({ checked, onChange, disabled, label }: SwitchProps) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={(event) => {
        event.stopPropagation();
        onChange(!checked);
      }}
      className={`relative h-6 w-11 shrink-0 rounded-full transition-colors duration-200 disabled:opacity-40 ${
        checked ? "bg-gradient-to-r from-emerald-400/80 to-cyan-400/80 shadow-[0_0_12px_rgb(52_211_153/0.35)]" : "bg-white/15"
      }`}
    >
      <span className={`absolute left-0.5 top-0.5 size-5 rounded-full bg-white shadow transition-transform duration-200 ${checked ? "translate-x-5" : ""}`} />
    </button>
  );
}

/** What a list shows when it has nothing: an icon in a soft glow and a sentence or two. */
export function EmptyState({ icon: Icon, title, text, tone = "accent" }: { icon: LucideIcon; title: string; text?: string; tone?: Tone }) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <div className="relative flex size-16 items-center justify-center">
        <div className={`absolute inset-0 rounded-full bg-gradient-to-br ${TONES[tone].glow} to-transparent blur-xl`} />
        <div className="relative flex size-14 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.05]">
          <Icon size={26} className={TONES[tone].text} />
        </div>
      </div>
      <div className="mt-4 text-sm font-medium text-white/80">{title}</div>
      {text && <div className="mt-1 max-w-sm text-xs leading-relaxed text-white/45">{text}</div>}
    </div>
  );
}

/** A list row that rises into place when it first appears; rows further down follow a moment later. */
export function Rise({ index, children, className = "" }: { index: number; children: ReactNode; className?: string }) {
  return (
    <div className={`rise ${className}`} style={{ animationDelay: `${Math.min(index, 14) * 28}ms` }}>
      {children}
    </div>
  );
}

/** A small label with an optional icon; quieter than a badge, for facts rather than warnings. */
export function Chip({ icon: Icon, children, tone = "neutral", title }: { icon?: LucideIcon; children: ReactNode; tone?: Tone; title?: string }) {
  const styles: Record<Tone, string> = {
    neutral: "border-white/10 text-white/55",
    accent: "border-emerald-400/25 bg-emerald-400/[0.07] text-emerald-200",
    info: "border-cyan-400/25 bg-cyan-400/[0.07] text-cyan-200",
    warn: "border-amber-400/30 bg-amber-400/[0.08] text-amber-200",
    danger: "border-rose-400/30 bg-rose-400/[0.08] text-rose-200",
  };
  return (
    <span title={title} className={`inline-flex max-w-full items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] leading-4 ${styles[tone]}`}>
      {Icon && <Icon size={11} className="shrink-0" />}
      <span className="truncate">{children}</span>
    </span>
  );
}
