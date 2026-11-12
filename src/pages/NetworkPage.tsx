import { Fragment, useMemo, useState } from "react";
import { ChevronDown } from "lucide-react";
import { ProcessActions } from "../components/ProcessActions";
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

/** Identifies a socket across refreshes of the list. */
function keyOf(c: Connection): string {
  return `${c.protocol}|${c.localAddr}|${c.localPort}|${c.remoteAddr}|${c.remotePort}|${c.pid}`;
}

interface Props {
  connections: Connection[] | null;
  processes: ProcessInfo[] | null;
  /** Called after a response action, so lists elsewhere refresh. */
  onChanged: () => void;
}

export function NetworkPage({ connections, processes, onChanged }: Props) {
  const [filter, setFilter] = useState<Filter>("external");
  /** The connection whose row is expanded. */
  const [open, setOpen] = useState<string | null>(null);

  const owners = useMemo(() => new Map((processes ?? []).map((p) => [p.pid, p])), [processes]);

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
        subtitle={connections ? `Соединений с интернетом: ${external} · всего сокетов: ${connections.length} · нажмите на строку, чтобы увидеть действия` : "Сбор данных…"}
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
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => {
                const key = keyOf(c);
                const owner = c.pid != null ? owners.get(c.pid) : undefined;
                return (
                <Fragment key={key}>
                <tr
                  onClick={() => owner && setOpen(open === key ? null : key)}
                  className={`border-t border-white/5 hover:bg-white/[0.04] ${owner ? "cursor-pointer" : ""} ${open === key ? "bg-white/[0.04]" : ""}`}
                >
                  <td className="px-4 py-2">
                    <span className="font-medium">{owner?.name ?? "—"}</span>
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
                  <td className="py-2 pr-3">
                    {owner && <ChevronDown size={15} className={`text-white/30 transition-transform ${open === key ? "rotate-180" : ""}`} />}
                  </td>
                </tr>
                {open === key && owner && (
                  <tr>
                    <td colSpan={6} className="px-4 pb-3">
                      <ProcessActions pid={owner.pid} path={owner.exe} name={owner.name} onDone={onChanged} />
                    </td>
                  </tr>
                )}
                </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
