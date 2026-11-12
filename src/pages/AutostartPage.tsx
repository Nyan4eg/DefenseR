import { Badge, Card, FlagBadges, Loading, PageHeader } from "../components/ui";
import type { AutostartEntry } from "../lib/api";

export function AutostartPage({ autostart }: { autostart: AutostartEntry[] | null }) {
  const sorted = [...(autostart ?? [])].sort((a, b) => b.flags.length - a.flags.length || a.name.localeCompare(b.name));
  const flagged = sorted.filter((e) => e.flags.length > 0).length;

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Автозагрузка"
        subtitle={autostart ? `Записей: ${autostart.length} · требуют внимания: ${flagged}` : "Сбор данных…"}
      />

      <Card className="min-h-0 flex-1 overflow-auto p-2">
        {!autostart ? (
          <Loading />
        ) : sorted.length === 0 ? (
          <div className="p-10 text-center text-sm text-white/40">Записей автозагрузки нет</div>
        ) : (
          sorted.map((entry) => (
            <div key={`${entry.source}\\${entry.name}`} className="rounded-xl px-3 py-3 hover:bg-white/[0.04]">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{entry.name}</span>
                <Badge tone={entry.scope === "machine" ? "accent" : "neutral"}>
                  {entry.scope === "machine" ? "Все пользователи" : "Текущий пользователь"}
                </Badge>
                <FlagBadges flags={entry.flags} />
              </div>
              <div className="mt-1 truncate font-mono text-xs text-white/55" title={entry.command}>{entry.command}</div>
              <div className="mt-0.5 truncate text-xs text-white/30" title={entry.source}>{entry.source}</div>
            </div>
          ))
        )}
      </Card>
    </div>
  );
}
