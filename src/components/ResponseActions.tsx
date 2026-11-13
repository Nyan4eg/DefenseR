import { useState } from "react";
import { Ban, CircleStop, LoaderCircle, Lock, Rocket } from "lucide-react";
import { ConfirmDialog } from "./ui";
import { call, type ResponseTarget } from "../lib/api";
import { tr } from "../lib/i18n";

type Action = "kill" | "quarantine" | "block" | "autostart";

interface Props {
  target: ResponseTarget;
  /** Program name for the dialog texts. */
  name: string;
  onDone: () => void;
}

const DONE: Record<Action, string> = {
  kill: tr("Процесс завершён", "Process ended"),
  quarantine: tr("Файл в карантине", "File is in quarantine"),
  block: tr("Выход в сеть заблокирован", "Network access blocked"),
  autostart: tr("Убрано из автозагрузки", "Removed from startup"),
};

/** Text of the confirmation for turning an autostart entry off. */
export function autostartDialog(name: string, scope: "user" | "machine" | null) {
  return {
    title: tr(`Убрать «${name}» из автозагрузки?`, `Remove “${name}” from startup?`),
    body:
      tr(
        "Запись перестанет запускаться при входе в Windows. Сама программа останется на месте, а запись можно вернуть на странице «Реакции».",
        "The entry will no longer run when you sign in to Windows. The program itself will stay where it is, and the entry can be restored on the Responses page.",
      ) +
      (scope === "user"
        ? ""
        : tr(
            " Если запись действует для всех пользователей, Windows попросит подтвердить действие от имени администратора.",
            " If the entry applies to all users, Windows will ask you to confirm the action as an administrator.",
          )),
    confirmLabel: tr("Убрать из автозагрузки", "Remove from startup"),
  };
}

/** Buttons for acting on a process or file. Every action asks for confirmation first. */
export function ResponseActions({ target, name, onDone }: Props) {
  const [asking, setAsking] = useState<Action | null>(null);
  const [busy, setBusy] = useState<Action | null>(null);
  const [done, setDone] = useState<Action[]>([]);
  const [error, setError] = useState<string | null>(null);

  const dialogs: Record<Action, { title: string; body: string; confirmLabel: string }> = {
    kill: {
      title: tr(`Завершить ${name}?`, `End ${name}?`),
      body: tr("Процесс будет остановлен сразу, несохранённые данные в нём пропадут. Сам файл останется на месте, и программа сможет запуститься снова.", "The process will be stopped immediately, and any unsaved data in it will be lost. The file itself will stay where it is, and the program will be able to start again."),
      confirmLabel: tr("Завершить процесс", "End process"),
    },
    quarantine: {
      title: tr(`Поместить ${name} в карантин?`, `Move ${name} to quarantine?`),
      body: tr(`Файл ${target.path} будет перемещён в хранилище DefenseR и перестанет запускаться. Вернуть его можно на странице «Реакции». Если программа сейчас работает, сначала завершите её процесс.`, `The file ${target.path} will be moved to DefenseR's storage and will no longer run. You can restore it on the Responses page. If the program is running now, end its process first.`),
      confirmLabel: tr("В карантин", "Quarantine"),
    },
    block: {
      title: tr(`Запретить ${name} выход в сеть?`, `Block network access for ${name}?`),
      body: tr("В брандмауэр Windows добавится правило, которое блокирует исходящие соединения этой программы. Windows попросит подтвердить действие от имени администратора. Снять блокировку можно на странице «Реакции».", "A rule that blocks this program's outgoing connections will be added to Windows Firewall. Windows will ask you to confirm the action as an administrator. You can remove the block on the Responses page."),
      confirmLabel: tr("Заблокировать", "Block"),
    },
    autostart: autostartDialog(target.autostart?.name ?? name, target.autostart?.source.startsWith("HKCU") ? "user" : null),
  };

  const run = async (action: Action) => {
    setAsking(null);
    setBusy(action);
    setError(null);
    try {
      if (action === "kill") await call("kill_process", { pid: target.pid, path: target.path });
      if (action === "quarantine") await call("quarantine_file", { path: target.path });
      if (action === "block") await call("block_program", { path: target.path });
      if (action === "autostart") await call("disable_autostart", { ...target.autostart });
      setDone((prev) => [...prev, action]);
      onDone();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const buttons: { action: Action; label: string; icon: typeof Ban; available: boolean }[] = [
    { action: "kill", label: tr("Завершить процесс", "End process"), icon: CircleStop, available: target.pid !== null },
    { action: "quarantine", label: tr("В карантин", "Quarantine"), icon: Lock, available: target.path !== null },
    { action: "block", label: tr("Запретить сеть", "Block network"), icon: Ban, available: target.path !== null },
    { action: "autostart", label: tr("Убрать из автозагрузки", "Remove from startup"), icon: Rocket, available: !!target.autostart },
  ];

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        {buttons
          .filter((b) => b.available)
          .map(({ action, label, icon: Icon }) =>
            done.includes(action) ? (
              <span key={action} className="px-1 text-xs text-emerald-300">
                {DONE[action]}
              </span>
            ) : (
              <button
                key={action}
                onClick={() => setAsking(action)}
                disabled={busy !== null}
                className="flex items-center gap-1.5 rounded-lg border border-white/10 px-2.5 py-1.5 text-xs text-white/65 hover:border-rose-400/40 hover:bg-rose-400/10 hover:text-rose-200 disabled:opacity-50"
              >
                {busy === action ? <LoaderCircle size={13} className="animate-spin" /> : <Icon size={13} />}
                {label}
              </button>
            ),
          )}
        {error && <span className="text-xs text-rose-300">{error}</span>}
      </div>
      {asking && <ConfirmDialog {...dialogs[asking]} danger onConfirm={() => run(asking)} onCancel={() => setAsking(null)} />}
    </>
  );
}
