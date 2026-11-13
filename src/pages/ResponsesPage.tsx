import { useState, type ReactNode } from "react";
import { BadgeCheck, Ban, History, Lock, Rocket } from "lucide-react";
import { Card, ConfirmDialog, Loading, PageHeader } from "../components/ui";
import { call, formatBytes, formatTime, usePolling, type ResponseLogEntry, type ResponsesState, type TrustState } from "../lib/api";
import { tr } from "../lib/i18n";

const ACTION_LABELS: Record<ResponseLogEntry["action"], string> = {
  kill: tr("Процесс завершён", "Process ended"),
  quarantine: tr("Файл помещён в карантин", "File moved to quarantine"),
  restore: tr("Файл возвращён из карантина", "File restored from quarantine"),
  delete: tr("Файл удалён из карантина", "File deleted from quarantine"),
  block: tr("Выход в сеть заблокирован", "Network access blocked"),
  unblock: tr("Блокировка сети снята", "Network block removed"),
  "autostart-disable": tr("Запись убрана из автозагрузки", "Entry removed from startup"),
  "autostart-enable": tr("Запись возвращена в автозагрузку", "Entry restored to startup"),
  "autostart-forget": tr("Отключённая запись удалена", "Disabled entry deleted"),
};

const FAILED_LABELS: Record<ResponseLogEntry["action"], string> = {
  kill: tr("Не удалось завершить процесс", "Could not end the process"),
  quarantine: tr("Не удалось поместить файл в карантин", "Could not move the file to quarantine"),
  restore: tr("Не удалось вернуть файл", "Could not restore the file"),
  delete: tr("Не удалось удалить файл", "Could not delete the file"),
  block: tr("Не удалось заблокировать выход в сеть", "Could not block network access"),
  unblock: tr("Не удалось снять блокировку", "Could not remove the block"),
  "autostart-disable": tr("Не удалось убрать запись из автозагрузки", "Could not remove the entry from startup"),
  "autostart-enable": tr("Не удалось вернуть запись в автозагрузку", "Could not restore the entry to startup"),
  "autostart-forget": tr("Не удалось удалить отключённую запись", "Could not delete the disabled entry"),
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
  const [trustKey, setTrustKey] = useState(0);
  const trust = usePolling<TrustState>("get_trust", 15_000, trustKey);

  if (!responses) {
    return (
      <>
        <PageHeader title={tr("Реакции", "Responses")} subtitle={tr("Карантин, блокировки сети, автозагрузка и журнал действий", "Quarantine, network blocks, startup and the action log")} />
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
    setTrustKey((key) => key + 1);
    onChanged();
  };

  const row = "flex items-center gap-3 border-b border-white/6 px-5 py-3 last:border-0";
  const button = "shrink-0 rounded-lg bg-white/8 px-3 py-1.5 text-xs text-white/70 hover:bg-white/12";

  return (
    <>
      <PageHeader title={tr("Реакции", "Responses")} subtitle={tr("Карантин, блокировки сети, отключённая автозагрузка и журнал действий. DefenseR ничего не делает сам — только по вашей команде", "Quarantine, network blocks, disabled startup entries and the action log. DefenseR does nothing on its own — only at your command")} />
      {error && <div className="mb-4 rounded-xl border border-rose-400/25 bg-rose-400/10 px-4 py-2.5 text-sm text-rose-200">{error}</div>}

      <Section icon={Lock} title={tr(`Карантин · ${responses.quarantine.length}`, `Quarantine · ${responses.quarantine.length}`)} empty={responses.quarantine.length === 0 ? tr("В карантине пусто", "Quarantine is empty") : null}>
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
                  title: tr(`Вернуть ${item.name}?`, `Restore ${item.name}?`),
                  body: tr(`Файл вернётся в ${item.originalPath} и снова сможет запускаться.`, `The file will go back to ${item.originalPath} and will be able to run again.`),
                  confirmLabel: tr("Вернуть", "Restore"),
                  danger: false,
                })
              }
            >
              {tr("Вернуть", "Restore")}
            </button>
            <button
              className={`${button} hover:bg-rose-400/15 hover:text-rose-200`}
              onClick={() =>
                setPending({
                  command: "delete_quarantined",
                  id: item.id,
                  title: tr(`Удалить ${item.name} навсегда?`, `Delete ${item.name} permanently?`),
                  body: tr("Файл будет удалён без возможности восстановления.", "The file will be deleted and cannot be recovered."),
                  confirmLabel: tr("Удалить навсегда", "Delete permanently"),
                  danger: true,
                })
              }
            >
              {tr("Удалить", "Delete")}
            </button>
          </div>
        ))}
      </Section>

      <Section icon={Ban} title={tr(`Блокировки сети · ${responses.blocks.length}`, `Network blocks · ${responses.blocks.length}`)} empty={responses.blocks.length === 0 ? tr("Ни одна программа не заблокирована", "No programs are blocked") : null}>
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
                  title: tr(`Разрешить ${block.name} выход в сеть?`, `Allow ${block.name} to access the network?`),
                  body: tr("Правило будет удалено из брандмауэра Windows. Windows попросит подтвердить действие от имени администратора.", "The rule will be removed from Windows Firewall. Windows will ask you to confirm the action as an administrator."),
                  confirmLabel: tr("Снять блокировку", "Remove block"),
                  danger: false,
                })
              }
            >
              {tr("Снять блокировку", "Remove block")}
            </button>
          </div>
        ))}
      </Section>

      <Section
        icon={Rocket}
        title={tr(`Отключённая автозагрузка · ${responses.autostart.length}`, `Disabled startup entries · ${responses.autostart.length}`)}
        empty={responses.autostart.length === 0 ? tr("Отключённых записей нет", "No disabled entries") : null}
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
                  title: tr(`Вернуть «${item.name}» в автозагрузку?`, `Restore “${item.name}” to startup?`),
                  body:
                    tr("Запись снова будет запускаться при входе в Windows.", "The entry will run again when you sign in to Windows.") +
                    (item.scope === "machine" ? tr(" Windows попросит подтвердить действие от имени администратора.", " Windows will ask you to confirm the action as an administrator.") : ""),
                  confirmLabel: tr("Вернуть", "Restore"),
                  danger: false,
                })
              }
            >
              {tr("Вернуть", "Restore")}
            </button>
            <button
              className={`${button} hover:bg-rose-400/15 hover:text-rose-200`}
              onClick={() =>
                setPending({
                  command: "forget_autostart",
                  id: item.id,
                  title: tr(`Удалить запись «${item.name}» навсегда?`, `Delete the entry “${item.name}” permanently?`),
                  body: tr("DefenseR забудет эту запись, и вернуть её в автозагрузку будет нельзя. Сама программа останется на месте.", "DefenseR will forget this entry, and it can no longer be restored to startup. The program itself will stay where it is."),
                  confirmLabel: tr("Удалить навсегда", "Delete permanently"),
                  danger: true,
                })
              }
            >
              {tr("Удалить", "Delete")}
            </button>
          </div>
        ))}
      </Section>

      {trust && (
        <Section
          icon={BadgeCheck}
          title={tr(`Доверенные · ${trust.files.length + trust.publishers.length}`, `Trusted · ${trust.files.length + trust.publishers.length}`)}
          empty={trust.files.length + trust.publishers.length === 0 ? tr("Доверенных файлов и издателей нет", "No trusted files or publishers") : null}
        >
          {trust.publishers.map((publisher) => (
            <div key={publisher.signer} className={row}>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm">{publisher.signer}</div>
                <div className="text-xs text-white/35">{tr("Издатель: все программы с его действительной подписью", "Publisher: all programs with its valid signature")}</div>
              </div>
              <div className="shrink-0 text-xs text-white/40">{formatTime(publisher.addedAt)}</div>
              <button
                className={button}
                onClick={() =>
                  setPending({
                    command: "untrust",
                    id: publisher.signer,
                    title: tr(`Перестать доверять издателю ${publisher.signer}?`, `Stop trusting publisher ${publisher.signer}?`),
                    body: tr("DefenseR снова будет сообщать о подозрительном поведении его программ.", "DefenseR will report suspicious activity by its programs again."),
                    confirmLabel: tr("Убрать из доверенных", "Remove from trusted"),
                    danger: false,
                  })
                }
              >
                {tr("Убрать", "Remove")}
              </button>
            </div>
          ))}
          {trust.files.map((file) => (
            <div key={file.sha256} className={row}>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm">{file.name}</div>
                <div className="truncate font-mono text-xs text-white/35">{file.path}</div>
              </div>
              <div className="shrink-0 text-xs text-white/40">{formatTime(file.addedAt)}</div>
              <button
                className={button}
                onClick={() =>
                  setPending({
                    command: "untrust",
                    id: file.sha256,
                    title: tr(`Перестать доверять файлу ${file.name}?`, `Stop trusting file ${file.name}?`),
                    body: tr("DefenseR снова будет заводить инциденты об этом файле.", "DefenseR will raise incidents about this file again."),
                    confirmLabel: tr("Убрать из доверенных", "Remove from trusted"),
                    danger: false,
                  })
                }
              >
                {tr("Убрать", "Remove")}
              </button>
            </div>
          ))}
        </Section>
      )}

      <Section icon={History} title={tr("Журнал действий", "Action log")} empty={responses.log.length === 0 ? tr("Действий пока не было", "No actions yet") : null}>
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
