import { useState } from "react";
import { autostartDialog } from "../components/ResponseActions";
import { Badge, Card, ConfirmDialog, FlagBadges, Loading, PageHeader } from "../components/ui";
import { call, type AutostartEntry } from "../lib/api";

interface Props {
  autostart: AutostartEntry[] | null;
  /** Called after an entry is turned off, so the lists refresh. */
  onChanged: () => void;
}

export function AutostartPage({ autostart, onChanged }: Props) {
  const [asking, setAsking] = useState<AutostartEntry | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sorted = [...(autostart ?? [])].sort((a, b) => b.flags.length - a.flags.length || a.name.localeCompare(b.name));
  const flagged = sorted.filter((e) => e.flags.length > 0).length;

  const disable = async ({ source, name }: AutostartEntry) => {
    setAsking(null);
    setError(null);
    try {
      await call("disable_autostart", { source, name });
    } catch (e) {
      setError(String(e));
    }
    onChanged();
  };

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Автозагрузка"
        subtitle={autostart ? `Записей: ${autostart.length} · требуют внимания: ${flagged}` : "Сбор данных…"}
      />
      {error && <div className="mb-4 rounded-xl border border-rose-400/25 bg-rose-400/10 px-4 py-2.5 text-sm text-rose-200">{error}</div>}

      <Card className="min-h-0 flex-1 overflow-auto p-2">
        {!autostart ? (
          <Loading />
        ) : sorted.length === 0 ? (
          <div className="p-10 text-center text-sm text-white/40">Записей автозагрузки нет</div>
        ) : (
          sorted.map((entry) => (
            <div key={`${entry.source}\\${entry.name}`} className="flex items-center gap-3 rounded-xl px-3 py-3 hover:bg-white/[0.04]">
              <div className="min-w-0 flex-1">
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
              <button
                onClick={() => setAsking(entry)}
                className="shrink-0 rounded-lg border border-white/10 px-2.5 py-1.5 text-xs text-white/65 hover:border-rose-400/40 hover:bg-rose-400/10 hover:text-rose-200"
              >
                Отключить
              </button>
            </div>
          ))
        )}
      </Card>

      {asking && (
        <ConfirmDialog {...autostartDialog(asking.name, asking.scope)} danger onConfirm={() => disable(asking)} onCancel={() => setAsking(null)} />
      )}
    </div>
  );
}
