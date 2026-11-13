import { Area, AreaChart, ResponsiveContainer, Tooltip, YAxis } from "recharts";
import {
  Activity,
  ArrowRight,
  ChevronRight,
  CircleCheck,
  CircleHelp,
  Cpu,
  Flame,
  Globe,
  Lock,
  MemoryStick,
  RefreshCw,
  Rocket,
  ShieldAlert,
  ShieldCheck,
  Bug,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { IconTile, Rise, StatTile } from "../components/kit";
import { Card, PageHeader } from "../components/ui";
import { WeekCard } from "../components/WeekCard";
import { ScoreRing } from "../components/ScoreRing";
import { formatBytes, formatTime, formatUptime, type Connection, type Incident, type Overview, type ProcessInfo, type Severity, type WeekActivity } from "../lib/api";
import { tr } from "../lib/i18n";
import type { Assessment, Check } from "../lib/score";

export interface Sample {
  cpu: number;
  memory: number;
}

/** The pages the overview can send the user to. */
export type OverviewLink = "incidents" | "processes" | "network" | "autostart";

const CHECK_ICONS: Record<string, LucideIcon> = {
  realtime: ShieldCheck,
  antivirus: Bug,
  firewall: Flame,
  signatures: RefreshCw,
  tamper: Lock,
  autostart: Rocket,
  processes: Activity,
};

/** The checks that are about something DefenseR has a page for. */
const CHECK_LINKS: Record<string, OverviewLink> = { autostart: "autostart", processes: "processes" };

const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
const SEVERITY_DOT: Record<Severity, string> = { high: "bg-rose-400", medium: "bg-amber-400", low: "bg-sky-400" };

function CheckRow({ check, onNavigate }: { check: Check; onNavigate: (page: OverviewLink) => void }) {
  const link = CHECK_LINKS[check.id];
  const tone = check.status === "ok" ? "accent" : check.status === "warn" ? "warn" : "neutral";
  const StatusIcon = check.status === "ok" ? CircleCheck : check.status === "warn" ? TriangleAlert : CircleHelp;
  const statusColour = check.status === "ok" ? "text-emerald-400" : check.status === "warn" ? "text-amber-400" : "text-white/30";
  const Element = link ? "button" : "div";
  return (
    <Element
      onClick={link ? () => onNavigate(link) : undefined}
      className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left transition-colors ${link ? "hover:bg-white/[0.05]" : ""}`}
    >
      <IconTile icon={CHECK_ICONS[check.id] ?? ShieldCheck} tone={tone} size={32} />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm">{check.label}</div>
        <div className={`truncate text-xs ${check.status === "warn" ? "text-amber-300" : "text-white/45"}`}>{check.detail}</div>
      </div>
      <StatusIcon size={17} className={`shrink-0 ${statusColour}`} />
      {link ? <ChevronRight size={15} className="shrink-0 text-white/25" /> : <span className="w-[15px] shrink-0" />}
    </Element>
  );
}

/** What DefenseR itself has noticed: the first thing the page says. */
function IncidentBanner({ incidents, onOpen }: { incidents: Incident[] | null; onOpen: () => void }) {
  const active = (incidents ?? []).filter((incident) => incident.status === "active").sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.lastSeen - a.lastSeen);
  const calm = active.length === 0;
  const serious = active.some((incident) => incident.severity === "high");

  return (
    <button
      onClick={onOpen}
      className={`group relative mb-4 flex w-full items-center gap-4 overflow-hidden rounded-2xl border px-5 py-4 text-left transition duration-200 hover:-translate-y-0.5 ${
        calm ? "border-emerald-400/20 bg-emerald-400/[0.05] hover:border-emerald-400/35" : serious ? "border-rose-400/30 bg-rose-400/[0.07] hover:border-rose-400/50" : "border-amber-400/30 bg-amber-400/[0.07] hover:border-amber-400/50"
      }`}
    >
      {calm && <div className="shimmer pointer-events-none absolute inset-0 opacity-40" />}
      <div className="relative flex size-11 shrink-0 items-center justify-center">
        <span className={`ping-soft absolute inset-1 rounded-full ${calm ? "bg-emerald-400/40" : serious ? "bg-rose-400/50" : "bg-amber-400/50"}`} />
        <div className={`relative flex size-11 items-center justify-center rounded-2xl ${calm ? "bg-emerald-400/15 text-emerald-300" : serious ? "bg-rose-400/15 text-rose-300" : "bg-amber-400/15 text-amber-300"}`}>
          {calm ? <ShieldCheck size={22} /> : <ShieldAlert size={22} />}
        </div>
      </div>

      <div className="relative min-w-0 flex-1">
        <div className="text-base font-semibold">
          {!incidents
            ? tr("Проверяю компьютер…", "Checking the computer…")
            : calm
              ? tr("Всё спокойно", "All quiet")
              : tr(`Нужно ваше внимание: ${active.length}`, `Needs your attention: ${active.length}`)}
        </div>
        {calm ? (
          <div className="mt-0.5 text-sm text-white/55">
            {tr("Активных инцидентов нет. DefenseR следит за программами, сетью, автозагрузкой и новыми файлами.", "No active incidents. DefenseR is watching programs, the network, startup and new files.")}
          </div>
        ) : (
          <div className="mt-1.5 flex flex-col gap-1">
            {active.slice(0, 3).map((incident) => (
              <div key={incident.id} className="flex items-center gap-2 text-sm text-white/75">
                <span className={`size-1.5 shrink-0 rounded-full ${SEVERITY_DOT[incident.severity]}`} />
                <span className="truncate">{incident.title}</span>
                <span className="shrink-0 text-xs text-white/35">{formatTime(incident.lastSeen)}</span>
              </div>
            ))}
            {active.length > 3 && <div className="text-xs text-white/40">{tr(`…и ещё ${active.length - 3}`, `…and ${active.length - 3} more`)}</div>}
          </div>
        )}
      </div>

      <span className={`relative flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm transition-colors ${calm ? "text-white/45 group-hover:text-white/80" : "bg-white/10 text-white group-hover:bg-white/15"}`}>
        {calm ? tr("История", "History") : tr("Разобраться", "Look into it")}
        <ArrowRight size={15} className="transition-transform group-hover:translate-x-0.5" />
      </span>
    </button>
  );
}

function loadTone(percent: number): "accent" | "warn" | "danger" {
  return percent >= 90 ? "danger" : percent >= 70 ? "warn" : "accent";
}

interface Props {
  overview: Overview | null;
  processes: ProcessInfo[] | null;
  connections: Connection[] | null;
  incidents: Incident[] | null;
  assessment: Assessment;
  history: Sample[];
  activity: WeekActivity | null;
  /** How many startup entries and browser extensions are being watched. */
  watching: { autostart: number | null; extensions: number | null };
  onNavigate: (page: OverviewLink) => void;
}

export function OverviewPage({ overview, processes, connections, incidents, assessment, history, activity, watching, onNavigate }: Props) {
  const cpu = overview?.cpuUsage ?? 0;
  const memoryPercent = overview ? (overview.memoryUsed / overview.memoryTotal) * 100 : 0;
  const external = connections?.filter((c) => c.remoteIsPublic).length ?? 0;
  const problems = assessment.checks.filter((c) => c.status === "warn").length;
  const passed = assessment.checks.filter((c) => c.status === "ok").length;
  // Problems first, so they are not lost at the bottom of the list.
  const checks = [...assessment.checks].sort((a, b) => Number(b.status === "warn") - Number(a.status === "warn"));

  return (
    <>
      <PageHeader
        title={tr("Обзор", "Overview")}
        subtitle={
          overview
            ? tr(
                `${overview.hostName} · ${overview.osVersion} · работает ${formatUptime(overview.uptimeSecs)}`,
                `${overview.hostName} · ${overview.osVersion} · up for ${formatUptime(overview.uptimeSecs)}`,
              )
            : tr("Сбор данных…", "Collecting data…")
        }
      />

      <IncidentBanner incidents={incidents} onOpen={() => onNavigate("incidents")} />

      <div className="grid grid-cols-[auto_1fr] gap-4">
        <Card className="flex flex-col items-center justify-center px-9 py-7">
          <ScoreRing score={assessment.score} />
          <div className="mt-4 text-sm font-medium text-white/80">{tr("Оценка защиты", "Protection score")}</div>
          <div className={`mt-0.5 text-xs ${problems > 0 ? "text-amber-300" : "text-white/45"}`}>
            {assessment.score == null
              ? tr("Проверяем состояние защиты", "Checking the protection status")
              : problems === 0
                ? tr("Замечаний нет", "No issues")
                : tr(`Замечаний: ${problems}`, `Issues: ${problems}`)}
          </div>
        </Card>

        <Card className="p-2">
          <div className="flex items-center justify-between px-3 pb-1 pt-2 text-xs text-white/40">
            <span>{tr("Из чего складывается оценка", "What the score is made of")}</span>
            <span className="tabular-nums">{tr(`в порядке ${passed} из ${assessment.checks.length}`, `${passed} of ${assessment.checks.length} OK`)}</span>
          </div>
          {checks.map((check, index) => (
            <Rise key={check.id} index={index}>
              <CheckRow check={check} onNavigate={onNavigate} />
            </Rise>
          ))}
        </Card>
      </div>

      <div className="mt-4 flex gap-3">
        <StatTile
          icon={Cpu}
          label={tr("Процессор", "CPU")}
          value={Math.round(cpu)}
          suffix="%"
          tone={loadTone(cpu)}
          meter={cpu / 100}
          hint={tr("загрузка сейчас", "current load")}
        />
        <StatTile
          icon={MemoryStick}
          label={tr("Память", "Memory")}
          value={Math.round(memoryPercent)}
          suffix="%"
          tone={memoryPercent >= 90 ? "danger" : memoryPercent >= 80 ? "warn" : "info"}
          meter={memoryPercent / 100}
          hint={
            overview
              ? tr(`${formatBytes(overview.memoryUsed)} из ${formatBytes(overview.memoryTotal)}`, `${formatBytes(overview.memoryUsed)} of ${formatBytes(overview.memoryTotal)}`)
              : ""
          }
        />
        <StatTile
          icon={Activity}
          label={tr("Процессы", "Processes")}
          value={processes?.length ?? 0}
          hint={tr("нажмите, чтобы открыть список", "click to open the list")}
          onClick={() => onNavigate("processes")}
        />
        <StatTile
          icon={Globe}
          label={tr("Соединения с интернетом", "Internet connections")}
          value={external}
          tone="info"
          hint={connections ? tr(`всего сокетов: ${connections.length}`, `sockets in total: ${connections.length}`) : ""}
          onClick={() => onNavigate("network")}
        />
      </div>

      <WeekCard activity={activity} watching={{ ...watching, programs: processes ? new Set(processes.map((process) => (process.exe ?? process.name).toLowerCase())).size : null }} />

      <Card className="mt-4 p-4">
        <div className="mb-2 flex items-center gap-4 text-xs text-white/50">
          <span>{tr("Нагрузка за последние 2 минуты", "Load over the last 2 minutes")}</span>
          <span className="ml-auto flex items-center gap-1.5"><i className="size-2 rounded-full bg-emerald-400" />{tr("Процессор", "CPU")}</span>
          <span className="flex items-center gap-1.5"><i className="size-2 rounded-full bg-cyan-400" />{tr("Память", "Memory")}</span>
        </div>
        <div className="h-32">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={history} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="cpu-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#34d399" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#34d399" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="memory-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
              </defs>
              <YAxis domain={[0, 100]} hide />
              <Tooltip
                formatter={(value, name) => [`${Number(value).toFixed(0)}%`, name === "cpu" ? tr("Процессор", "CPU") : tr("Память", "Memory")]}
                labelFormatter={() => ""}
                contentStyle={{ background: "#11161d", border: "1px solid rgb(255 255 255 / 0.1)", borderRadius: 10, fontSize: 12 }}
              />
              <Area type="monotone" dataKey="memory" stroke="#22d3ee" strokeWidth={2} fill="url(#memory-fill)" isAnimationActive={false} />
              <Area type="monotone" dataKey="cpu" stroke="#34d399" strokeWidth={2} fill="url(#cpu-fill)" isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Card>
    </>
  );
}
