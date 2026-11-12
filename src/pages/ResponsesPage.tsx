import { useState, type ReactNode } from "react";
import { Ban, History, Lock, Rocket } from "lucide-react";
import { Card, ConfirmDialog, Loading, PageHeader } from "../components/ui";
import { call, formatBytes, formatTime, type ResponseLogEntry, type ResponsesState } from "../lib/api";

const ACTION_LABELS: Record<ResponseLogEntry["action"], string> = {
  kill: "Процесс завершён",
  quarantine: "Файл помещён в карантин",
  restore: "Файл возвращён из карантина",
  delete: "Файл удалён из карантина",
  block: "Выход в сеть заблокирован",
  unblock: "Блокировка сети снята",
  "autostart-disable": "Запись убрана из автозагрузки",
  "autostart-enable": "Запись возвращена в автозагрузку",
  "autostart-forget": "Отключённая запись удалена",
};

const FAILED_LABELS: Record<ResponseLogEntry["action"], string> = {
  kill: "Не удалось завершить процесс",
  quarantine: "Не удалось поместить файл в карантин",
  restore: "Не удалось вернуть файл",
  delete: "Не удалось удалить файл",
  block: "Не удалось заблокировать выход в сеть",
  unblock: "Не удалось снять блокировку",
  "autostart-disable": "Не удалось убрать запись из автозагрузки",
  "autostart-enable": "Не удалось вернуть запись в автозагрузку",
  "autostart-forget": "Не удалось удалить отключённую запись",
};

interface Pending {
  command: string;
  id: string;
  title: string;
  body: string;
  confirmLabel: string;
  danger: boolean;
}

function Section({ icon: Icon, title, empty, children }: { icon: typeof Lock; title: string; empty: string | null; children: ReactNode }) {
  return (
    <Card className="mb-4 overflow-hidden">
      <div className="flex items-center gap-2 border-b border-white/6 px-5 py-3 text-sm font-medium">
        <Icon size={16} className="text-emerald-400" />
        {title}
      </div>
      {empty ? <div className="px-5 py-6 text-sm text-white/40">{empty}</div> : children}
    </Card>
  );
}

export function ResponsesPage({ responses, onChanged }: { responses: ResponsesState | null; onChanged: () => void }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!responses) {
    return (
      <>
        <PageHeader title="Реакции" subtitle="Карантин, блокировки сети, автозагрузка и журнал действий" />
        <Loading />
      </>
    );
  }

  const run = async ({ command, id }: Pending) => {
    setPending(null);
    setError(null);
    try {
      await call(command, { id });
    } catch (e) {
      setError(String(e));
    }
    onChanged();
  };

  const row = "flex items-center gap-3 border-b border-white/6 px-5 py-3 last:border-0";
  const button = "shrink-0 rounded-lg bg-white/8 px-3 py-1.5 text-xs text-white/70 hover:bg-white/12";

  return (
    <>
      <PageHeader title="Реакции" subtitle="Карантин, блокировки сети, отключённая автозагрузка и журнал действий. DefenseR ничего не делает сам — только по вашей команде" />
      {error && <div className="mb-4 rounded-xl border border-rose-400/25 bg-rose-400/10 px-4 py-2.5 text-sm text-rose-200">{error}</div>}

      <Section icon={Lock} title={`Карантин · ${responses.quarantine.length}`} empty={responses.quarantine.length === 0 ? "В карантине пусто" : null}>
        {responses.quarantine.map((item) => (
          <div key={item.id} className={row}>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm">{item.name}</div>
              <div className="truncate font-mono text-xs text-white/35">{item.originalPath}</div>
            </div>
            <div className="shrink-0 text-right text-xs text-white/40">
              <div>{formatBytes(item.size)}</div>
              <div>{formatTime(item.quarantinedAt)}</div>
            </div>
            <button
              className={button}
              onClick={() =>
                setPending({
                  command: "restore_file",
                  id: item.id,
                  title: `Вернуть ${item.name}?`,
                  body: `Файл вернётся в ${item.originalPath} и снова сможет запускаться.`,
                  confirmLabel: "Вернуть",
                  danger: false,
                })
              }
            >
              Вернуть
            </button>
            <button
              className={`${button} hover:bg-rose-400/15 hover:text-rose-200`}
              onClick={() =>
                setPending({
                  command: "delete_quarantined",
                  id: item.id,
                  title: `Удалить ${item.name} навсегда?`,
                  body: "Файл будет удалён без возможности восстановления.",
                  confirmLabel: "Удалить навсегда",
                  danger: true,
                })
              }
            >
              Удалить
            </button>
          </div>
        ))}
      </Section>

      <Section icon={Ban} title={`Блокировки сети · ${responses.blocks.length}`} empty={responses.blocks.length === 0 ? "Ни одна программа не заблокирована" : null}>
        {responses.blocks.map((block) => (
          <div key={block.id} className={row}>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm">{block.name}</div>
              <div className="truncate font-mono text-xs text-white/35">{block.path}</div>
            </div>
            <div className="shrink-0 text-xs text-white/40">{formatTime(block.blockedAt)}</div>
            <button
              className={button}
              onClick={() =>
                setPending({
                  command: "unblock_program",
                  id: block.id,
                  title: `Разрешить ${block.name} выход в сеть?`,
                  body: "Правило будет удалено из брандмауэра Windows. Windows попросит подтвердить действие от имени администратора.",
                  confirmLabel: "Снять блокировку",
                  danger: false,
                })
              }
            >
              Снять блокировку
            </button>
          </div>
        ))}
      </Section>

      <Section
        icon={Rocket}
        title={`Отключённая автозагрузка · ${responses.autostart.length}`}
        empty={responses.autostart.length === 0 ? "Отключённых записей нет" : null}
      >
        {responses.autostart.map((item) => (
          <div key={item.id} className={row}>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm">{item.name}</div>
              <div className="truncate font-mono text-xs text-white/35">{item.command}</div>
            </div>
            <div className="shrink-0 text-xs text-white/40">{formatTime(item.disabledAt)}</div>
            <button
              className={button}
              onClick={() =>
                setPending({
                  command: "enable_autostart",
                  id: item.id,
                  title: `Вернуть «${item.name}» в автозагрузку?`,
                  body: `Запись снова будет запускаться при входе в Windows.${
                    item.scope === "machine" ? " Windows попросит подтвердить действие от имени администратора." : ""
                  }`,
                  confirmLabel: "Вернуть",
                  danger: false,
                })
              }
            >
              Вернуть
            </button>
            <button
              className={`${button} hover:bg-rose-400/15 hover:text-rose-200`}
              onClick={() =>
                setPending({
                  command: "forget_autostart",
                  id: item.id,
                  title: `Удалить запись «${item.name}» навсегда?`,
                  body: "DefenseR забудет эту запись, и вернуть её в автозагрузку будет нельзя. Сама программа останется на месте.",
                  confirmLabel: "Удалить навсегда",
                  danger: true,
                })
              }
            >
              Удалить
            </button>
          </div>
        ))}
      </Section>

      <Section icon={History} title="Журнал действий" empty={responses.log.length === 0 ? "Действий пока не было" : null}>
        {responses.log.map((entry, i) => (
          <div key={`${entry.at}-${i}`} className={row}>
            <span className={`size-2 shrink-0 rounded-full ${entry.error ? "bg-rose-400" : "bg-emerald-400"}`} />
            <div className="min-w-0 flex-1">
              <div className="text-sm">{entry.error ? FAILED_LABELS[entry.action] : ACTION_LABELS[entry.action]}</div>
              <div className="truncate font-mono text-xs text-white/35">{entry.target}</div>
              {entry.error && <div className="mt-0.5 text-xs text-rose-300/80">{entry.error}</div>}
            </div>
            <div className="shrink-0 text-xs text-white/40">{formatTime(entry.at)}</div>
          </div>
        ))}
      </Section>

      {pending && <ConfirmDialog {...pending} onConfirm={() => run(pending)} onCancel={() => setPending(null)} />}
    </>
  );
}
