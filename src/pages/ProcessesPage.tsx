import { Fragment, useMemo, useState } from "react";
import { ChevronDown } from "lucide-react";
import { ProcessActions } from "../components/ProcessActions";
import { Card, FlagBadges, Loading, PageHeader, SearchInput, Tabs } from "../components/ui";
import { formatBytes, type ProcessInfo } from "../lib/api";
import { tr } from "../lib/i18n";

type SortKey = "cpu" | "memory" | "name";

const SORT_OPTIONS: { id: SortKey; label: string }[] = [
  { id: "cpu", label: tr("По процессору", "By CPU") },
  { id: "memory", label: tr("По памяти", "By memory") },
  { id: "name", label: tr("По имени", "By name") },
];

interface Props {
  processes: ProcessInfo[] | null;
  /** Called after a response action, so lists elsewhere refresh. */
  onChanged: () => void;
}

export function ProcessesPage({ processes, onChanged }: Props) {
  const [query, setQuery] = useState("");
  /** The process whose row is expanded. */
  const [open, setOpen] = useState<number | null>(null);
  const [sort, setSort] = useState<SortKey>("cpu");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = (processes ?? []).filter(
      (p) => !q || p.name.toLowerCase().includes(q) || p.exe?.toLowerCase().includes(q) || String(p.pid) === q,
    );
    return filtered.sort((a, b) => {
      // Flagged processes always stay on top.
      const byFlags = b.flags.length - a.flags.length;
      if (byFlags !== 0) return byFlags;
      return sort === "name" ? a.name.localeCompare(b.name) : b[sort] - a[sort];
    });
  }, [processes, query, sort]);

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title={tr("Процессы", "Processes")}
        subtitle={
          processes
            ? tr(
                `Запущено: ${processes.length} · нажмите на строку, чтобы увидеть действия`,
                `Running: ${processes.length} · click a row to see the actions`,
              )
            : tr("Сбор данных…", "Collecting data…")
        }
      >
        <div className="flex gap-3">
          <Tabs value={sort} onChange={setSort} options={SORT_OPTIONS} />
          <SearchInput value={query} onChange={setQuery} placeholder={tr("Имя, путь или PID", "Name, path or PID")} />
        </div>
      </PageHeader>

      <Card className="min-h-0 flex-1 overflow-auto">
        {!processes ? (
          <Loading />
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-[#10151c] text-left text-xs text-white/45">
              <tr>
                <th className="px-4 py-2.5 font-medium">{tr("Процесс", "Process")}</th>
                <th className="px-3 py-2.5 font-medium">PID</th>
                <th className="px-3 py-2.5 text-right font-medium">{tr("ЦП", "CPU")}</th>
                <th className="px-3 py-2.5 text-right font-medium">{tr("Память", "Memory")}</th>
                <th className="px-4 py-2.5 font-medium">{tr("Путь", "Path")}</th>
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <Fragment key={p.pid}>
                  <tr
                    onClick={() => setOpen(open === p.pid ? null : p.pid)}
                    className={`cursor-pointer border-t border-white/5 hover:bg-white/[0.04] ${open === p.pid ? "bg-white/[0.04]" : ""}`}
                  >
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{p.name}</span>
                        <FlagBadges flags={p.flags} />
                      </div>
                    </td>
                    <td className="px-3 py-2 tabular-nums text-white/50">{p.pid}</td>
                    <td className="px-3 py-2 text-right tabular-nums">{p.cpu.toFixed(1)}%</td>
                    <td className="px-3 py-2 text-right tabular-nums">{formatBytes(p.memory)}</td>
                    <td className="max-w-0 w-1/2 truncate px-4 py-2 text-white/45" title={p.exe ?? ""}>
                      {p.exe ?? tr("нет доступа", "no access")}
                    </td>
                    <td className="py-2 pr-3">
                      <ChevronDown size={15} className={`text-white/30 transition-transform ${open === p.pid ? "rotate-180" : ""}`} />
                    </td>
                  </tr>
                  {open === p.pid && (
                    <tr>
                      <td colSpan={6} className="px-4 pb-3">
                        <ProcessActions pid={p.pid} path={p.exe} name={p.name} onDone={onChanged} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
