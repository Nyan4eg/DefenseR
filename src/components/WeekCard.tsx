import { Activity as Pulse, FileSearch, Globe, Hand, ShieldAlert, Timer, type LucideIcon } from "lucide-react";
import { Card } from "./ui";
import type { WeekActivity } from "../lib/api";
import { locale, tr } from "../lib/i18n";

const DAY = 86_400;

interface Day {
  /** Local midnight, Unix seconds. */
  start: number;
  watched: number;
  files: number;
}

/** The last seven local days, oldest first, with the hours of the log folded into them. */
function days(activity: WeekActivity): Day[] {
  const midnight = new Date();
  midnight.setHours(0, 0, 0, 0);
  const today = Math.floor(midnight.getTime() / 1000);
  const list: Day[] = Array.from({ length: 7 }, (_, index) => ({ start: today - (6 - index) * DAY, watched: 0, files: 0 }));
  for (const hour of activity.hours) {
    const at = hour.hour * 3600;
    const day = [...list].reverse().find((candidate) => candidate.start <= at);
    if (!day) continue;
    day.watched += hour.watchedSecs;
    day.files += hour.files;
  }
  return list;
}

function Figure({ icon: Icon, value, label, tone = "text-white/45" }: { icon: LucideIcon; value: string | number; label: string; tone?: string }) {
  return (
    <div className="flex min-w-0 items-center gap-2.5">
      <Icon size={15} className={`shrink-0 ${tone}`} />
      <div className="min-w-0">
        <div className="text-base font-semibold tabular-nums leading-5">{value}</div>
        <div className="truncate text-xs text-white/40">{label}</div>
      </div>
    </div>
  );
}

interface Props {
  activity: WeekActivity | null;
  /** What is being watched right now, for the line under the title. */
  watching: { autostart: number | null; extensions: number | null; programs: number | null };
}

/** What DefenseR did over the last week: the proof of work for the days when nothing happened. */
export function WeekCard({ activity, watching }: Props) {
  if (!activity) return null;
  const week = days(activity);
  const total = (pick: (hour: WeekActivity["hours"][number]) => number) => activity.hours.reduce((sum, hour) => sum + pick(hour), 0);
  const watchedHours = total((hour) => hour.watchedSecs) / 3600;
  const longest = Math.max(1, ...week.map((day) => day.watched));
  const parts = [
    watching.programs != null ? tr(`программ: ${watching.programs}`, `programs: ${watching.programs}`) : null,
    watching.autostart != null ? tr(`записей автозагрузки: ${watching.autostart}`, `startup entries: ${watching.autostart}`) : null,
    watching.extensions != null ? tr(`расширений: ${watching.extensions}`, `extensions: ${watching.extensions}`) : null,
  ].filter(Boolean);

  return (
    <Card className="mt-4 p-4">
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <div className="text-sm font-medium">{tr("Что сделано за 7 дней", "Done over the last 7 days")}</div>
        {parts.length > 0 && <div className="text-xs text-white/40">{tr(`Сейчас под присмотром — ${parts.join(" · ")}`, `Watching now — ${parts.join(" · ")}`)}</div>}
      </div>

      <div className="flex items-stretch gap-6">
        <div className="flex w-44 shrink-0 items-end gap-1.5" aria-hidden>
          {week.map((day) => {
            const hours = day.watched / 3600;
            const name = new Date(day.start * 1000).toLocaleDateString(locale, { weekday: "short" });
            return (
              <div
                key={day.start}
                className="flex flex-1 flex-col items-center gap-1"
                title={tr(`${name}: наблюдение ${hours.toFixed(1)} ч, новых файлов ${day.files}`, `${name}: watched ${hours.toFixed(1)} h, new files ${day.files}`)}
              >
                <div className="flex h-12 w-full items-end overflow-hidden rounded-md bg-white/[0.05]">
                  <div
                    className="w-full rounded-md bg-gradient-to-t from-emerald-400/70 to-cyan-400/70 transition-[height] duration-700 ease-out"
                    style={{ height: `${day.watched > 0 ? Math.max(8, (day.watched / longest) * 100) : 0}%` }}
                  />
                </div>
                <div className="text-[10px] uppercase text-white/35">{name}</div>
              </div>
            );
          })}
        </div>

        <div className="grid min-w-0 flex-1 grid-cols-3 content-center gap-x-4 gap-y-3">
          <Figure icon={Timer} tone="text-emerald-300" value={watchedHours >= 10 ? Math.round(watchedHours) : watchedHours.toFixed(1)} label={tr("часов наблюдения", "hours of watching")} />
          <Figure icon={FileSearch} tone="text-cyan-300" value={total((hour) => hour.files)} label={tr("новых файлов проверено", "new files checked")} />
          <Figure icon={Pulse} value={total((hour) => hour.programs)} label={tr("новых программ замечено", "new programs noticed")} />
          <Figure icon={Globe} value={total((hour) => hour.online)} label={tr("программ впервые вышли в сеть", "programs went online for the first time")} />
          <Figure
            icon={ShieldAlert}
            tone={activity.incidentsActive > 0 ? "text-amber-300" : "text-white/45"}
            value={activity.incidents}
            label={
              activity.incidents === 0
                ? tr("инцидентов", "incidents")
                : activity.incidentsActive > 0
                  ? tr(`инцидентов, активных: ${activity.incidentsActive}`, `incidents, active: ${activity.incidentsActive}`)
                  : tr("инцидентов, все закрыты", "incidents, all closed")
            }
          />
          <Figure icon={Hand} value={activity.responses + activity.trusted} label={tr("ваших действий и решений", "actions and decisions of yours")} />
        </div>
      </div>
    </Card>
  );
}
