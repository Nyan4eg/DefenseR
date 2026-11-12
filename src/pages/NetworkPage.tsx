import { useMemo, useState } from "react";
import { Badge, Card, Loading, PageHeader, Tabs } from "../components/ui";
import type { Connection, ProcessInfo } from "../lib/api";

type Filter = "external" | "listening" | "all";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "external", label: "Внешние" },
  { id: "listening", label: "Открытые порты" },
  { id: "all", label: "Все" },
];

const STATE_LABELS: Record<string, string> = {
  ESTABLISHED: "Установлено",
  LISTEN: "Ожидает подключений",
};

function isListening(c: Connection): boolean {
  return c.state === "LISTEN" || c.protocol === "UDP";
}

function endpoint(addr: string, port: number): string {
  return addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`;
}

export function NetworkPage({ connections, processes }: { connections: Connection[] | null; processes: ProcessInfo[] | null }) {
  const [filter, setFilter] = useState<Filter>("external");

  const names = useMemo(() => new Map((processes ?? []).map((p) => [p.pid, p.name])), [processes]);

  const rows = useMemo(() => {
    const list = connections ?? [];
    if (filter === "external") return list.filter((c) => c.remoteIsPublic);
    if (filter === "listening") return list.filter(isListening);
    return list;
  }, [connections, filter]);

  const external = connections?.filter((c) => c.remoteIsPublic).length ?? 0;

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Сеть"
        subtitle={connections ? `Соединений с интернетом: ${external} · всего сокетов: ${connections.length}` : "Сбор данных…"}
      >
        <Tabs value={filter} onChange={setFilter} options={FILTERS} />
      </PageHeader>

      <Card className="min-h-0 flex-1 overflow-auto">
        {!connections ? (
          <Loading />
        ) : rows.length === 0 ? (
          <div className="p-10 text-center text-sm text-white/40">Соединений нет</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-[#10151c] text-left text-xs text-white/45">
              <tr>
                <th className="px-4 py-2.5 font-medium">Процесс</th>
                <th className="px-3 py-2.5 font-medium">Протокол</th>
                <th className="px-3 py-2.5 font-medium">Локальный адрес</th>
                <th className="px-3 py-2.5 font-medium">Удалённый адрес</th>
                <th className="px-4 py-2.5 font-medium">Состояние</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c, i) => (
                <tr key={i} className="border-t border-white/5 hover:bg-white/[0.04]">
                  <td className="px-4 py-2">
                    <span className="font-medium">{(c.pid != null && names.get(c.pid)) || "—"}</span>
                    {c.pid != null && <span className="ml-2 text-xs tabular-nums text-white/35">{c.pid}</span>}
                  </td>
                  <td className="px-3 py-2">
                    <Badge>{c.protocol}</Badge>
                  </td>
                  <td className="px-3 py-2 tabular-nums text-white/60">{endpoint(c.localAddr, c.localPort)}</td>
                  <td className="px-3 py-2 tabular-nums">
                    {c.remoteAddr && c.remotePort ? (
                      <span className={c.remoteIsPublic ? "text-cyan-300" : "text-white/60"}>{endpoint(c.remoteAddr, c.remotePort)}</span>
                    ) : (
                      <span className="text-white/30">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-white/50">{c.state ? (STATE_LABELS[c.state] ?? c.state) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
