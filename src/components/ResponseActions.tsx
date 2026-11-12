import { useState } from "react";
import { Ban, CircleStop, LoaderCircle, Lock } from "lucide-react";
import { ConfirmDialog } from "./ui";
import { call, type ResponseTarget } from "../lib/api";

type Action = "kill" | "quarantine" | "block";

interface Props {
  target: ResponseTarget;
  /** Program name for the dialog texts. */
  name: string;
  onDone: () => void;
}

const DONE: Record<Action, string> = {
  kill: "Процесс завершён",
  quarantine: "Файл в карантине",
  block: "Выход в сеть заблокирован",
};

/** Buttons for acting on a process or file. Every action asks for confirmation first. */
export function ResponseActions({ target, name, onDone }: Props) {
  const [asking, setAsking] = useState<Action | null>(null);
  const [busy, setBusy] = useState<Action | null>(null);
  const [done, setDone] = useState<Action[]>([]);
  const [error, setError] = useState<string | null>(null);

  const dialogs: Record<Action, { title: string; body: string; confirmLabel: string }> = {
    kill: {
      title: `Завершить ${name}?`,
      body: "Процесс будет остановлен сразу, несохранённые данные в нём пропадут. Сам файл останется на месте, и программа сможет запуститься снова.",
      confirmLabel: "Завершить процесс",
    },
    quarantine: {
      title: `Поместить ${name} в карантин?`,
      body: `Файл ${target.path} будет перемещён в хранилище DefenseR и перестанет запускаться. Вернуть его можно на странице «Реакции». Если программа сейчас работает, сначала завершите её процесс.`,
      confirmLabel: "В карантин",
    },
    block: {
      title: `Запретить ${name} выход в сеть?`,
      body: "В брандмауэр Windows добавится правило, которое блокирует исходящие соединения этой программы. Windows попросит подтвердить действие от имени администратора. Снять блокировку можно на странице «Реакции».",
      confirmLabel: "Заблокировать",
    },
  };

  const run = async (action: Action) => {
    setAsking(null);
    setBusy(action);
    setError(null);
    try {
      if (action === "kill") await call("kill_process", { pid: target.pid, path: target.path });
      if (action === "quarantine") await call("quarantine_file", { path: target.path });
      if (action === "block") await call("block_program", { path: target.path });
      setDone((prev) => [...prev, action]);
      onDone();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const buttons: { action: Action; label: string; icon: typeof Ban; available: boolean }[] = [
    { action: "kill", label: "Завершить процесс", icon: CircleStop, available: target.pid !== null },
    { action: "quarantine", label: "В карантин", icon: Lock, available: target.path !== null },
    { action: "block", label: "Запретить сеть", icon: Ban, available: target.path !== null },
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
