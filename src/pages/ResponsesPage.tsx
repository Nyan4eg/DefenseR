import { useState } from "react";
import { BadgeCheck, Ban, CircleCheck, CircleX, FileBadge, History, Lock, type LucideIcon, Puzzle } from "lucide-react";
import { Avatar, Chip, EmptyState, Rise, StatTile } from "../components/kit";
import { Card, ConfirmDialog, Loading, PageHeader } from "../components/ui";
import { call, formatBytes, formatTime, usePolling, type ResponseLogEntry, type ResponsesState, type TrustState } from "../lib/api";
import { locale, tr } from "../lib/i18n";

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

type Section = "quarantine" | "blocks" | "trusted" | "log";

interface Pending {
  command: string;
  id: string;
  title: string;
  body: string;
  confirmLabel: string;
  danger: boolean;
}

const SUBTITLE = tr(
  "Всё, что вы сделали с помощью DefenseR, и как это отменить. Сам DefenseR ничего не меняет — только по вашей команде",
  "Everything you have done with DefenseR, and how to undo it. DefenseR changes nothing on its own — only at your command",
);

/** A short explanation at the top of a section: what it is and what can be done with it. */
function About({ icon: Icon, children }: { icon: LucideIcon; children: string }) {
  return (
    <div className="mb-1 flex items-start gap-2.5 rounded-xl bg-white/[0.03] px-4 py-3 text-xs leading-relaxed text-white/50">
      <Icon size={15} className="mt-0.5 shrink-0 text-emerald-400" />
      {children}
    </div>
  );
}

/** The day a log entry belongs to, as a heading. */
function dayOf(unixSecs: number): string {
  const date = new Date(unixSecs * 1000);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86_400_000);
  if (date.toDateString() === today.toDateString()) return tr("Сегодня", "Today");
  if (date.toDateString() === yesterday.toDateString()) return tr("Вчера", "Yesterday");
  return date.toLocaleDateString(locale, { day: "numeric", month: "long" });
}

function timeOf(unixSecs: number): string {
  return new Date(unixSecs * 1000).toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
}

export function ResponsesPage({ responses, onChanged }: { responses: ResponsesState | null; onChanged: () => void }) {
  const [section, setSection] = useState<Section>("quarantine");
  const [pending, setPending] = useState<Pending | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [trustKey, setTrustKey] = useState(0);
  const trust = usePolling<TrustState>("get_trust", 15_000, trustKey);

  if (!responses) {
    return (
      <>
        <PageHeader title={tr("Реакции", "Responses")} subtitle={SUBTITLE} />
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

  const trusted = (trust?.files.length ?? 0) + (trust?.publishers.length ?? 0) + (trust?.extensions?.length ?? 0);
  const row = "flex items-center gap-3 rounded-xl px-3 py-2.5 transition-colors hover:bg-white/[0.035]";
  const button = "shrink-0 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/70 transition-colors hover:bg-white/8 hover:text-white";
  const dangerButton = `${button} hover:border-rose-400/40 hover:bg-rose-400/10 hover:text-rose-200`;

  // Log entries under the day they happened on.
  const days: { day: string; entries: ResponseLogEntry[] }[] = [];
  for (const entry of responses.log) {
    const day = dayOf(entry.at);
    if (days[days.length - 1]?.day === day) days[days.length - 1].entries.push(entry);
    else days.push({ day, entries: [entry] });
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader title={tr("Реакции", "Responses")} subtitle={SUBTITLE} />
      {error && <div className="mb-4 rounded-xl border border-rose-400/25 bg-rose-400/10 px-4 py-2.5 text-sm text-rose-200">{error}</div>}

      <div className="mb-4 flex gap-3">
        <StatTile
          icon={Lock}
          label={tr("Карантин", "Quarantine")}
          value={responses.quarantine.length}
          tone={responses.quarantine.length > 0 ? "warn" : "neutral"}
          hint={tr("файлы, убранные с глаз", "files put out of the way")}
          onClick={() => setSection("quarantine")}
          active={section === "quarantine"}
        />
        <StatTile
          icon={Ban}
          label={tr("Блокировки сети", "Network blocks")}
          value={responses.blocks.length}
          tone={responses.blocks.length > 0 ? "warn" : "neutral"}
          hint={tr("программы без интернета", "programs without internet")}
          onClick={() => setSection("blocks")}
          active={section === "blocks"}
        />
        <StatTile
          icon={BadgeCheck}
          label={tr("Доверенные", "Trusted")}
          value={trusted}
          tone="accent"
          hint={tr("о них DefenseR не сообщает", "DefenseR stays quiet about these")}
          onClick={() => setSection("trusted")}
          active={section === "trusted"}
        />
        <StatTile
          icon={History}
          label={tr("Журнал действий", "Action log")}
          value={responses.log.length}
          tone="info"
          hint={tr("что и когда было сделано", "what was done and when")}
          onClick={() => setSection("log")}
          active={section === "log"}
        />
      </div>

      <Card className="min-h-0 flex-1 overflow-auto p-2">
        {section === "quarantine" && (
          <div key="quarantine" className="rise">
            <About icon={Lock}>
              {tr(
                "Файл в карантине лежит в хранилище DefenseR под другим именем и не может запуститься. Его можно вернуть на место или удалить навсегда.",
                "A quarantined file sits in DefenseR's storage under another name and cannot run. It can be put back or deleted for good.",
              )}
            </About>
            {responses.quarantine.length === 0 ? (
              <EmptyState icon={Lock} title={tr("В карантине пусто", "Quarantine is empty")} text={tr("Кнопка «В карантин» есть в инцидентах, на страницах «Процессы», «Сеть» и в результатах проверки файлов.", "The Quarantine button is in incidents, on the Processes and Network pages, and in file scan results.")} />
            ) : (
              responses.quarantine.map((item, index) => (
                <Rise key={item.id} index={index}>
                  <div className={row}>
                    <Avatar name={item.name} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{item.name}</div>
                      <div className="truncate font-mono text-xs text-white/35" title={item.originalPath}>
                        {item.originalPath}
                      </div>
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
                      className={dangerButton}
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
                </Rise>
              ))
            )}
          </div>
        )}

        {section === "blocks" && (
          <div key="blocks" className="rise">
            <About icon={Ban}>
              {tr(
                "Для каждой программы здесь в брандмауэре Windows стоит правило, которое не пускает её в интернет. Снять блокировку можно в любой момент; Windows попросит подтверждение администратора.",
                "For each program here there is a Windows Firewall rule that keeps it off the internet. A block can be removed at any time; Windows will ask for administrator confirmation.",
              )}
            </About>
            {responses.blocks.length === 0 ? (
              <EmptyState icon={Ban} title={tr("Ни одна программа не заблокирована", "No programs are blocked")} text={tr("Кнопка «Запретить сеть» есть в инцидентах и на страницах «Процессы» и «Сеть».", "The Block network button is in incidents and on the Processes and Network pages.")} />
            ) : (
              responses.blocks.map((block, index) => (
                <Rise key={block.id} index={index}>
                  <div className={row}>
                    <Avatar name={block.name} path={block.path} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{block.name}</div>
                      <div className="truncate font-mono text-xs text-white/35" title={block.path}>
                        {block.path}
                      </div>
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
                </Rise>
              ))
            )}
          </div>
        )}

        {section === "trusted" && (
          <div key="trusted" className="rise">
            <About icon={BadgeCheck}>
              {tr(
                "О доверенных файлах и о программах доверенных издателей DefenseR не заводит инциденты. Файлу доверяют по его содержимому: если он изменится, доверие пропадёт само.",
                "DefenseR raises no incidents about trusted files or about programs from trusted publishers. A file is trusted by its contents: if it changes, the trust is gone on its own.",
              )}
            </About>
            {trusted === 0 ? (
              <EmptyState icon={BadgeCheck} title={tr("Доверенных файлов и издателей нет", "No trusted files or publishers")} text={tr("Кнопки «Доверять файлу» и «Доверять издателю» появляются в инцидентах, в раскрытых строках программ и на странице «Автозагрузка».", "The Trust file and Trust publisher buttons appear in incidents, in expanded program rows and on the Startup page.")} />
            ) : (
              <>
                {trust?.publishers.map((publisher, index) => (
                  <Rise key={publisher.signer} index={index}>
                    <div className={row}>
                      <Avatar name={publisher.signer} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-sm font-medium">{publisher.signer}</span>
                          <Chip icon={BadgeCheck} tone="accent">
                            {tr("Издатель", "Publisher")}
                          </Chip>
                        </div>
                        <div className="text-xs text-white/35">{tr("Все программы с его действительной подписью", "All programs with its valid signature")}</div>
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
                  </Rise>
                ))}
                {trust?.extensions?.map((extension, index) => (
                  <Rise key={extension.key} index={index}>
                    <div className={row}>
                      <Avatar name={extension.name} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-sm font-medium">{extension.name}</span>
                          <Chip icon={Puzzle}>{tr("Расширение", "Extension")}</Chip>
                        </div>
                        <div className="text-xs text-white/35">{extension.browser}</div>
                      </div>
                      <div className="shrink-0 text-xs text-white/40">{formatTime(extension.addedAt)}</div>
                      <button
                        className={button}
                        onClick={() =>
                          setPending({
                            command: "untrust",
                            id: extension.key,
                            title: tr(`Перестать доверять расширению ${extension.name}?`, `Stop trusting extension ${extension.name}?`),
                            body: tr("DefenseR снова заведёт о нём инцидент, пока оно установлено не из магазина.", "DefenseR will raise an incident about it again while it is installed from outside a store."),
                            confirmLabel: tr("Убрать из доверенных", "Remove from trusted"),
                            danger: false,
                          })
                        }
                      >
                        {tr("Убрать", "Remove")}
                      </button>
                    </div>
                  </Rise>
                ))}
                {trust?.files.map((file, index) => (
                  <Rise key={file.sha256} index={index + (trust?.publishers.length ?? 0)}>
                    <div className={row}>
                      <Avatar name={file.name} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-sm font-medium">{file.name}</span>
                          <Chip icon={FileBadge}>{tr("Файл", "File")}</Chip>
                        </div>
                        <div className="truncate font-mono text-xs text-white/35" title={file.path}>
                          {file.path}
                        </div>
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
                  </Rise>
                ))}
              </>
            )}
          </div>
        )}

        {section === "log" && (
          <div key="log" className="rise">
            {responses.log.length === 0 ? (
              <EmptyState icon={History} tone="info" title={tr("Действий пока не было", "No actions yet")} text={tr("Здесь появится всё, что вы сделаете через DefenseR: и удачное, и то, что не получилось.", "Everything you do through DefenseR will show up here: what worked and what did not.")} />
            ) : (
              days.map(({ day, entries }) => (
                <div key={day} className="mb-2">
                  <div className="sticky top-0 z-10 bg-[#10151c]/90 px-3 py-1.5 text-xs font-medium text-white/45 backdrop-blur">{day}</div>
                  {entries.map((entry, index) => (
                    <div key={`${entry.at}-${index}`} className="relative flex gap-3 px-3 py-2">
                      {index < entries.length - 1 && <span className="absolute left-[21px] top-8 h-full w-px bg-white/8" />}
                      {entry.error ? <CircleX size={18} className="relative mt-0.5 shrink-0 text-rose-400" /> : <CircleCheck size={18} className="relative mt-0.5 shrink-0 text-emerald-400" />}
                      <div className="min-w-0 flex-1">
                        <div className="text-sm">{entry.error ? FAILED_LABELS[entry.action] : ACTION_LABELS[entry.action]}</div>
                        <div className="truncate font-mono text-xs text-white/35" title={entry.target}>
                          {entry.target}
                        </div>
                        {entry.error && <div className="mt-0.5 text-xs text-rose-300/80">{entry.error}</div>}
                      </div>
                      <div className="shrink-0 text-xs tabular-nums text-white/40">{timeOf(entry.at)}</div>
                    </div>
                  ))}
                </div>
              ))
            )}
          </div>
        )}
      </Card>

      {pending && <ConfirmDialog {...pending} onConfirm={() => run(pending)} onCancel={() => setPending(null)} />}
    </div>
  );
}
