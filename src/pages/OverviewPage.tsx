import type { ReactNode } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, YAxis } from "recharts";
import { Activity, CircleCheck, CircleHelp, Cpu, Globe, MemoryStick, TriangleAlert } from "lucide-react";
import { Card, PageHeader } from "../components/ui";
import { ScoreRing } from "../components/ScoreRing";
import { formatBytes, formatUptime, type Connection, type Overview, type ProcessInfo } from "../lib/api";
import { tr } from "../lib/i18n";
import type { Assessment, CheckStatus } from "../lib/score";

export interface Sample {
  cpu: number;
  memory: number;
}

const STATUS_ICON: Record<CheckStatus, ReactNode> = {
  ok: <CircleCheck size={18} className="text-emerald-400" />,
  warn: <TriangleAlert size={18} className="text-amber-400" />,
  unknown: <CircleHelp size={18} className="text-white/30" />,
};

function StatTile({ icon, label, value, hint }: { icon: ReactNode; label: string; value: string; hint: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 text-xs text-white/50">
        {icon}
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums">{value}</div>
      <div className="mt-0.5 text-xs text-white/40">{hint}</div>
    </Card>
  );
}

interface Props {
  overview: Overview | null;
  processes: ProcessInfo[] | null;
  connections: Connection[] | null;
  assessment: Assessment;
  history: Sample[];
}

export function OverviewPage({ overview, processes, connections, assessment, history }: Props) {
  const memoryPercent = overview ? (overview.memoryUsed / overview.memoryTotal) * 100 : 0;
  const external = connections?.filter((c) => c.remoteIsPublic).length;
  const problems = assessment.checks.filter((c) => c.status === "warn").length;

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

      <div className="grid grid-cols-[auto_1fr] gap-4">
        <Card className="flex flex-col items-center justify-center px-10 py-8">
          <ScoreRing score={assessment.score} />
          <div className="mt-5 text-sm text-white/50">
            {assessment.score == null
              ? tr("Проверяем состояние защиты", "Checking the protection status")
              : problems === 0
                ? tr("Замечаний нет", "No issues")
                : tr(`Замечаний: ${problems}`, `Issues: ${problems}`)}
          </div>
        </Card>

        <Card className="p-2">
          {assessment.checks.map((check) => (
            <div key={check.id} className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/[0.04]">
              {STATUS_ICON[check.status]}
              <div className="text-sm">{check.label}</div>
              <div className={`ml-auto text-sm ${check.status === "warn" ? "text-amber-300" : "text-white/45"}`}>{check.detail}</div>
            </div>
          ))}
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-4 gap-4">
        <StatTile
          icon={<Cpu size={14} />}
          label={tr("Процессор", "CPU")}
          value={overview ? `${overview.cpuUsage.toFixed(0)}%` : "—"}
          hint={tr("Загрузка сейчас", "Current load")}
        />
        <StatTile
          icon={<MemoryStick size={14} />}
          label={tr("Память", "Memory")}
          value={overview ? `${memoryPercent.toFixed(0)}%` : "—"}
          hint={
            overview
              ? tr(
                  `${formatBytes(overview.memoryUsed)} из ${formatBytes(overview.memoryTotal)}`,
                  `${formatBytes(overview.memoryUsed)} of ${formatBytes(overview.memoryTotal)}`,
                )
              : ""
          }
        />
        <StatTile
          icon={<Activity size={14} />}
          label={tr("Процессы", "Processes")}
          value={processes ? String(processes.length) : "—"}
          hint={tr("Запущено сейчас", "Running now")}
        />
        <StatTile
          icon={<Globe size={14} />}
          label={tr("Внешние соединения", "External connections")}
          value={external != null ? String(external) : "—"}
          hint={connections ? tr(`Всего сокетов: ${connections.length}`, `Sockets in total: ${connections.length}`) : ""}
        />
      </div>

      <Card className="mt-4 p-4">
        <div className="mb-2 flex items-center gap-4 text-xs text-white/50">
          <span>{tr("Нагрузка за последние 2 минуты", "Load over the last 2 minutes")}</span>
          <span className="ml-auto flex items-center gap-1.5"><i className="size-2 rounded-full bg-emerald-400" />{tr("Процессор", "CPU")}</span>
          <span className="flex items-center gap-1.5"><i className="size-2 rounded-full bg-cyan-400" />{tr("Память", "Memory")}</span>
        </div>
        <div className="h-36">
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
