import { useMemo, useState } from "react";
import { AppWindow, BadgeCheck, ChevronDown, Cpu, Layers, SearchX, ShieldQuestion, TriangleAlert } from "lucide-react";
import { FileCheck } from "../components/FileCheck";
import { Avatar, Chip, EmptyState, friendlyName, Meter, Rise, StatTile } from "../components/kit";
import { ResponseActions } from "../components/ResponseActions";
import { Card, FlagBadges, Loading, PageHeader, SearchInput, Tabs } from "../components/ui";
import { formatBytes, type ProcessInfo } from "../lib/api";
import { tr } from "../lib/i18n";

type SortKey = "cpu" | "memory" | "name";
type Filter = "all" | "unsigned" | "flagged";

const SORT_OPTIONS: { id: SortKey; label: string }[] = [
  { id: "memory", label: tr("Память", "Memory") },
  { id: "cpu", label: tr("Процессор", "CPU") },
  { id: "name", label: tr("Имя", "Name") },
];

/** Every running copy of one program file, shown as one row. */
interface Group {
  key: string;
  name: string;
  exe: string | null;
  processes: ProcessInfo[];
  cpu: number;
  memory: number;
  flags: string[];
  signed: boolean | null;
  publisher: string | null;
}

function groupByProgram(processes: ProcessInfo[]): Group[] {
  const groups = new Map<string, Group>();
  for (const process of processes) {
    const key = (process.exe ?? `${process.name}#${process.pid}`).toLowerCase();
    let group = groups.get(key);
    if (!group) {
      group = { key, name: process.name, exe: process.exe, processes: [], cpu: 0, memory: 0, flags: [], signed: process.signed ?? null, publisher: process.publisher ?? null };
      groups.set(key, group);
    }
    group.processes.push(process);
    group.cpu += process.cpu;
    group.memory += process.memory;
    for (const flag of process.flags) if (!group.flags.includes(flag)) group.flags.push(flag);
  }
  return [...groups.values()];
}

interface RowProps {
  group: Group;
  open: boolean;
  onToggle: () => void;
  /** The largest memory use among the shown programs, for the scale of the bars. */
  maxMemory: number;
  onChanged: () => void;
}

function ProgramRow({ group, open, onToggle, maxMemory, onChanged }: RowProps) {
  const title = friendlyName(group.name);
  const many = group.processes.length > 1;
  const sorted = [...group.processes].sort((a, b) => b.memory - a.memory);

  return (
    <div className={`rounded-xl transition-colors ${open ? "bg-white/[0.05]" : "hover:bg-white/[0.035]"}`}>
      <button onClick={onToggle} className="flex w-full items-center gap-3 px-3 py-2.5 text-left">
        <Avatar name={group.name} muted={group.exe === null} path={group.exe} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{title}</span>
            {many && <span className="shrink-0 rounded-md bg-white/8 px-1.5 text-xs tabular-nums text-white/55">×{group.processes.length}</span>}
            <FlagBadges flags={group.flags} />
          </div>
          <div className="mt-1 flex min-w-0 items-center gap-1.5">
            {group.signed === true && (
              <Chip icon={BadgeCheck} tone="accent" title={tr("У файла действительная цифровая подпись", "The file has a valid digital signature")}>
                {group.publisher ?? tr("Подписан", "Signed")}
              </Chip>
            )}
            {group.signed === false && (
              <Chip
                icon={ShieldQuestion}
                tone="warn"
                title={tr("У файла нет действительной цифровой подписи. Так бывает и у обычных программ", "The file has no valid digital signature. Ordinary programs can be like this too")}
              >
                {tr("Без подписи", "Unsigned")}
              </Chip>
            )}
            {title !== group.name && <span className="truncate text-xs text-white/35">{group.name}</span>}
            {group.exe === null && <span className="truncate text-xs text-white/35">{tr("системный процесс", "system process")}</span>}
          </div>
        </div>

        <div className="w-28 shrink-0">
          <div className="mb-1 flex justify-between text-xs">
            <span className="text-white/35">{tr("ЦП", "CPU")}</span>
            <span className="tabular-nums text-white/75">{group.cpu.toFixed(1)}%</span>
          </div>
          <Meter value={group.cpu / 25} tone={group.cpu > 15 ? "warn" : "accent"} />
        </div>
        <div className="w-32 shrink-0">
          <div className="mb-1 flex justify-between text-xs">
            <span className="text-white/35">{tr("Память", "Memory")}</span>
            <span className="whitespace-nowrap tabular-nums text-white/75">{formatBytes(group.memory)}</span>
          </div>
          <Meter value={group.memory / maxMemory} tone="info" />
        </div>
        <ChevronDown size={16} className={`shrink-0 text-white/30 transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="rise mx-3 mb-3 flex flex-col gap-3 rounded-xl border border-white/8 bg-black/20 px-4 py-3">
          {group.exe ? (
            <div className="select-text break-all font-mono text-xs text-white/55">{group.exe}</div>
          ) : (
            <div className="text-xs leading-relaxed text-white/45">
              {tr(
                "Windows не показывает путь к файлу этого процесса — обычно так бывает у системных и защищённых процессов. Доступно только завершение.",
                "Windows does not show the path to this process's file — this is usual for system and protected processes. Only ending it is available.",
              )}
            </div>
          )}

          {group.exe && (
            <>
              <ResponseActions target={{ pid: null, path: group.exe }} name={group.name} onDone={onChanged} />
              <FileCheck path={group.exe} canTrust onDone={onChanged} />
            </>
          )}

          <div>
            <div className="mb-1.5 text-xs text-white/40">
              {many ? tr(`Запущено копий: ${group.processes.length}`, `Running copies: ${group.processes.length}`) : tr("Процесс", "Process")}
            </div>
            <div className="flex flex-col gap-1">
              {sorted.slice(0, 12).map((process) => (
                <div key={process.pid} className="flex items-center gap-3 rounded-lg bg-white/[0.03] px-3 py-1.5 text-xs">
                  <span className="w-20 shrink-0 tabular-nums text-white/45">PID {process.pid}</span>
                  <span className="w-14 shrink-0 text-right tabular-nums text-white/70">{process.cpu.toFixed(1)}%</span>
                  <span className="w-16 shrink-0 whitespace-nowrap text-right tabular-nums text-white/70">{formatBytes(process.memory)}</span>
                  <span className="flex-1" />
                  <ResponseActions target={{ pid: process.pid, path: process.exe }} name={process.name} onDone={onChanged} only={["kill"]} />
                </div>
              ))}
              {sorted.length > 12 && <div className="px-3 py-1 text-xs text-white/35">{tr(`…и ещё ${sorted.length - 12}`, `…and ${sorted.length - 12} more`)}</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

interface Props {
  processes: ProcessInfo[] | null;
  /** Called after a response action, so lists elsewhere refresh. */
  onChanged: () => void;
}

export function ProcessesPage({ processes, onChanged }: Props) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortKey>("memory");
  const [filter, setFilter] = useState<Filter>("all");
  /** The program whose row is expanded. */
  const [open, setOpen] = useState<string | null>(null);

  const groups = useMemo(() => groupByProgram(processes ?? []), [processes]);
  const unsigned = groups.filter((group) => group.signed === false).length;
  const flagged = groups.filter((group) => group.flags.length > 0).length;
  const totalCpu = groups.reduce((sum, group) => sum + group.cpu, 0);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return groups
      .filter((group) => filter === "all" || (filter === "unsigned" ? group.signed === false : group.flags.length > 0))
      .filter(
        (group) =>
          !q ||
          group.name.toLowerCase().includes(q) ||
          friendlyName(group.name).toLowerCase().includes(q) ||
          group.exe?.toLowerCase().includes(q) ||
          group.publisher?.toLowerCase().includes(q) ||
          group.processes.some((process) => String(process.pid) === q),
      )
      .sort((a, b) => {
        // Flagged programs always stay on top.
        const byFlags = b.flags.length - a.flags.length;
        if (byFlags !== 0) return byFlags;
        return sort === "name" ? friendlyName(a.name).localeCompare(friendlyName(b.name)) : b[sort] - a[sort];
      });
  }, [groups, query, sort, filter]);

  const maxMemory = Math.max(1, ...rows.map((group) => group.memory));
  const toggle = (next: Filter) => setFilter(filter === next ? "all" : next);

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title={tr("Процессы", "Processes")}
        subtitle={tr("Что сейчас работает на компьютере. Нажмите на программу, чтобы увидеть подробности и действия", "What is running on this computer right now. Click a program for details and actions")}
      />

      <div className="mb-4 flex gap-3">
        <StatTile icon={AppWindow} label={tr("Программ", "Programs")} value={groups.length} tone="accent" onClick={() => setFilter("all")} active={filter === "all"} />
        <StatTile icon={Layers} label={tr("Процессов", "Processes")} value={processes?.length ?? 0} hint={tr("у одной программы их бывает много", "one program can have many")} />
        <StatTile icon={Cpu} label={tr("Загрузка процессора", "CPU load")} value={Math.round(totalCpu)} suffix="%" tone="info" />
        <StatTile
          icon={ShieldQuestion}
          label={tr("Без подписи", "Unsigned")}
          value={unsigned}
          tone="warn"
          hint={tr("нажмите, чтобы показать", "click to show")}
          onClick={() => toggle("unsigned")}
          active={filter === "unsigned"}
        />
        <StatTile
          icon={TriangleAlert}
          label={tr("Требуют внимания", "Need attention")}
          value={flagged}
          tone={flagged > 0 ? "danger" : "neutral"}
          hint={tr("нажмите, чтобы показать", "click to show")}
          onClick={() => toggle("flagged")}
          active={filter === "flagged"}
        />
      </div>

      <div className="mb-3 flex items-center gap-3">
        <SearchInput value={query} onChange={setQuery} placeholder={tr("Название, издатель, путь или PID", "Name, publisher, path or PID")} />
        <span className="flex-1" />
        <span className="whitespace-nowrap text-xs text-white/40">{tr("Сначала", "Sort by")}</span>
        <Tabs value={sort} onChange={setSort} options={SORT_OPTIONS} />
      </div>

      <Card className="min-h-0 flex-1 overflow-auto p-2">
        {!processes ? (
          <Loading />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={SearchX}
            tone="neutral"
            title={tr("Ничего не нашлось", "Nothing found")}
            text={tr("Попробуйте другой запрос или снимите фильтр.", "Try another search or clear the filter.")}
          />
        ) : (
          rows.map((group, index) => (
            <Rise key={group.key} index={index}>
              <ProgramRow group={group} open={open === group.key} onToggle={() => setOpen(open === group.key ? null : group.key)} maxMemory={maxMemory} onChanged={onChanged} />
            </Rise>
          ))
        )}
      </Card>
    </div>
  );
}
