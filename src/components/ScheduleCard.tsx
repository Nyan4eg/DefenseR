import { useState } from "react";
import { CalendarClock, FolderPlus, LoaderCircle, Play, Square, X } from "lucide-react";
import { Chip, Switch } from "./kit";
import { Card } from "./ui";
import { call, formatTime, inTauri, usePolling, type ScheduledRun, type ScheduleState } from "../lib/api";
import { locale, tr } from "../lib/i18n";

/** Monday first, as the backend counts them. 2024-01-01 was a Monday. */
const DAYS = Array.from({ length: 7 }, (_, index) => new Date(2024, 0, 1 + index).toLocaleDateString(locale, { weekday: "long" }));

/** One line about how a run went. */
export function describeRun(run: ScheduledRun): string {
  const found = run.flagged > 0 ? tr(`похожих на вредоносные: ${run.flagged}`, `looking like malware: ${run.flagged}`) : tr("ничего опасного не нашлось", "nothing dangerous was found");
  const cut = run.stopped ? tr(", остановлена до конца", ", stopped before the end") : run.truncated ? tr(", проверены не все — программ слишком много", ", not all were checked — there are too many programs") : "";
  return tr(`${formatTime(run.finishedAt)} — программ проверено: ${run.files}, ${found}${cut}`, `${formatTime(run.finishedAt)} — programs checked: ${run.files}, ${found}${cut}`);
}

/** The weekly scan of the folders the user chose: its switch, its folders, its hour and how the last run went. */
export function ScheduleCard({ onOpenIncidents }: { onOpenIncidents?: () => void }) {
  const [refresh, setRefresh] = useState(0);
  const schedule = usePolling<ScheduleState>("get_schedule", 2000, refresh);
  const [error, setError] = useState<string | null>(null);
  if (!schedule) return null;

  const act = (work: Promise<unknown>) =>
    work
      .then(() => setError(null))
      .catch((problem) => setError(String(problem)))
      .finally(() => setRefresh((value) => value + 1));
  const change = (patch: Partial<Pick<ScheduleState, "enabled" | "folders" | "day" | "hour">>) => {
    const plan = { enabled: schedule.enabled, folders: schedule.folders, day: schedule.day, hour: schedule.hour, ...patch };
    act(call("set_schedule", { plan }));
  };
  const addFolder = async () => {
    if (!inTauri) return change({ folders: [...schedule.folders, "C:\\Users\\demo\\Documents"] });
    const { open } = await import("@tauri-apps/plugin-dialog");
    const picked = await open({ directory: true, multiple: true, title: tr("Папка для проверки по расписанию", "Folder for the scheduled scan") });
    const paths = picked === null ? [] : Array.isArray(picked) ? picked : [picked];
    const fresh = paths.filter((path) => !schedule.folders.includes(path));
    if (fresh.length > 0) change({ folders: [...schedule.folders, ...fresh] });
  };

  const running = schedule.progress;
  const share = running && running.total > 0 ? running.done / running.total : 0;
  const select = "rounded-lg border border-white/10 bg-white/[0.06] px-2.5 py-1.5 text-sm text-white/85 outline-none focus:border-emerald-400/50 disabled:opacity-40";
  const button = "flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm transition disabled:pointer-events-none disabled:opacity-40";
  const state = running
    ? running.total > 0
      ? tr(`Идёт проверка: ${running.done} из ${running.total}`, `Scanning: ${running.done} of ${running.total}`)
      : tr(`Идёт проверка: ищу программы в папках, найдено ${running.done}…`, `Scanning: looking for programs in the folders, found ${running.done}…`)
    : !schedule.enabled
      ? tr("Выключена. Раз в неделю DefenseR может сам проверять папки, которые вы выберете.", "Off. Once a week DefenseR can check the folders you choose on its own.")
      : schedule.folders.length === 0
        ? tr("Включена, но проверять нечего: добавьте хотя бы одну папку.", "On, but there is nothing to check: add at least one folder.")
        : tr(`Следующая проверка — ${formatTime(schedule.nextAt)}`, `The next scan is on ${formatTime(schedule.nextAt)}`);

  return (
    <Card className="mt-5 overflow-hidden">
      <div className="flex items-center gap-4 px-5 py-4">
        <span className={`flex size-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/[0.05] ${schedule.enabled ? "text-emerald-300" : "text-white/35"}`}>
          {running ? <LoaderCircle size={19} className="animate-spin" /> : <CalendarClock size={19} />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">{tr("Проверка по расписанию", "Scheduled scan")}</div>
          <div className="mt-0.5 text-xs leading-relaxed text-white/50">{state}</div>
        </div>
        {running ? (
          <button onClick={() => act(call("stop_schedule"))} className={`${button} bg-white/8 text-white/75 hover:bg-white/12`}>
            <Square size={13} />
            {tr("Остановить", "Stop")}
          </button>
        ) : (
          <button onClick={() => act(call("run_schedule"))} disabled={schedule.folders.length === 0} className={`${button} bg-white/8 text-white/75 hover:bg-white/12`}>
            <Play size={13} />
            {tr("Проверить сейчас", "Scan now")}
          </button>
        )}
        <Switch checked={schedule.enabled} onChange={(enabled) => change({ enabled })} label={tr("Проверка по расписанию", "Scheduled scan")} />
      </div>

      {running && (
        <div className="relative mx-5 mb-4 h-1.5 overflow-hidden rounded-full bg-white/8">
          <div className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-cyan-400 transition-[width] duration-500" style={{ width: `${share * 100}%` }} />
        </div>
      )}

      <div className="border-t border-white/6 px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          {schedule.folders.map((folder) => (
            <span key={folder} className="flex max-w-full items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] py-1 pl-2.5 pr-1 font-mono text-xs text-white/70" title={folder}>
              <span className="truncate">{folder}</span>
              <button
                onClick={() => change({ folders: schedule.folders.filter((other) => other !== folder) })}
                disabled={!!running}
                aria-label={tr(`Убрать папку ${folder}`, `Remove folder ${folder}`)}
                className="rounded p-0.5 text-white/35 hover:bg-white/10 hover:text-white/80 disabled:opacity-30"
              >
                <X size={13} />
              </button>
            </span>
          ))}
          <button onClick={addFolder} disabled={!!running} className={`${button} border border-dashed border-white/15 text-white/60 hover:border-emerald-400/40 hover:text-emerald-200`}>
            <FolderPlus size={14} />
            {tr("Добавить папку", "Add a folder")}
          </button>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-white/55">
          <span>{tr("Каждую неделю:", "Every week:")}</span>
          <select value={schedule.day} onChange={(event) => change({ day: Number(event.target.value) })} disabled={!!running} className={select} style={{ colorScheme: "dark" }} aria-label={tr("День недели", "Day of the week")}>
            {DAYS.map((name, index) => (
              <option key={index} value={index}>
                {name}
              </option>
            ))}
          </select>
          <span>{tr("в", "at")}</span>
          <select value={schedule.hour} onChange={(event) => change({ hour: Number(event.target.value) })} disabled={!!running} className={select} style={{ colorScheme: "dark" }} aria-label={tr("Час", "Hour")}>
            {Array.from({ length: 24 }, (_, hour) => (
              <option key={hour} value={hour}>
                {`${String(hour).padStart(2, "0")}:00`}
              </option>
            ))}
          </select>
        </div>

        {schedule.last && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Chip tone={schedule.last.flagged > 0 ? "warn" : "accent"}>{tr("Последняя проверка", "Last scan")}</Chip>
            <span className="text-xs text-white/55">{describeRun(schedule.last)}</span>
            {schedule.last.flagged > 0 && onOpenIncidents && (
              <button onClick={onOpenIncidents} className="text-xs text-emerald-300 hover:text-emerald-200">
                {tr("Открыть инциденты", "Open incidents")}
              </button>
            )}
          </div>
        )}

        {error && <div className="mt-3 rounded-lg border border-rose-400/25 bg-rose-400/10 px-3 py-2 text-xs text-rose-200">{error}</div>}

        <p className="mt-3 text-xs leading-relaxed text-white/40">
          {tr(
            "Проверяются программы во всех вложенных папках. Проверка идёт в фоне на одном ядре процессора и работе не мешает. Если в назначенный час компьютер был выключен, она пройдёт при следующем запуске DefenseR, через десять минут после него. Файл, похожий на вредоносный и без действительной подписи, появится в инцидентах.",
            "Programs in all subfolders are checked. The scan runs in the background on one processor core and does not get in the way of work. If the computer was off at the appointed hour, the scan runs the next time DefenseR starts, ten minutes after that. A file that looks like malware and has no valid signature appears among the incidents.",
          )}
        </p>
      </div>
    </Card>
  );
}
