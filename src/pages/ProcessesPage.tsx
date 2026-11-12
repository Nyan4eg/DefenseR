import { useMemo, useState } from "react";
import { Card, FlagBadges, Loading, PageHeader, SearchInput, Tabs } from "../components/ui";
import { formatBytes, type ProcessInfo } from "../lib/api";

type SortKey = "cpu" | "memory" | "name";

const SORT_OPTIONS: { id: SortKey; label: string }[] = [
  { id: "cpu", label: "По процессору" },
  { id: "memory", label: "По памяти" },
  { id: "name", label: "По имени" },
];

export function ProcessesPage({ processes }: { processes: ProcessInfo[] | null }) {
  const [query, setQuery] = useState("");
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
      <PageHeader title="Процессы" subtitle={processes ? `Запущено: ${processes.length}` : "Сбор данных…"}>
        <div className="flex gap-3">
          <Tabs value={sort} onChange={setSort} options={SORT_OPTIONS} />
          <SearchInput value={query} onChange={setQuery} placeholder="Имя, путь или PID" />
        </div>
      </PageHeader>

      <Card className="min-h-0 flex-1 overflow-auto">
        {!processes ? (
          <Loading />
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-[#10151c] text-left text-xs text-white/45">
              <tr>
                <th className="px-4 py-2.5 font-medium">Процесс</th>
                <th className="px-3 py-2.5 font-medium">PID</th>
                <th className="px-3 py-2.5 text-right font-medium">ЦП</th>
                <th className="px-3 py-2.5 text-right font-medium">Память</th>
                <th className="px-4 py-2.5 font-medium">Путь</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr key={p.pid} className="border-t border-white/5 hover:bg-white/[0.04]">
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
                    {p.exe ?? "нет доступа"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
