import { useMemo, useState } from "react";
import { CalendarClock, Clock, Cog, FolderOpen, KeyRound, Power, PowerOff, Rocket, Trash2, TriangleAlert, User, Users } from "lucide-react";
import { Avatar, Chip, EmptyState, friendlyName, Rise, StatTile, Switch } from "../components/kit";
import { autostartDialog } from "../components/ResponseActions";
import { Card, ConfirmDialog, FlagBadges, Loading, PageHeader, SearchInput, Tabs } from "../components/ui";
import { call, formatTime, type AutostartEntry, type DisabledAutostart, type ResponsesState } from "../lib/api";
import { tr } from "../lib/i18n";

type Filter = "all" | "on" | "off" | "flagged";
/** The three places a program can start itself from. */
type Place = "all" | "startup" | "task" | "service";

/** A startup entry, whether it is on or was turned off through DefenseR. */
interface Row {
  key: string;
  name: string;
  /** What to call the entry on screen. */
  title: string;
  place: Exclude<Place, "all">;
  trigger: string | null;
  command: string;
  source: string;
  scope: "user" | "machine";
  flags: string[];
  /** Set for entries that are on. */
  entry: AutostartEntry | null;
  /** Set for entries that were turned off. */
  disabled: DisabledAutostart | null;
}

/** Where the entry lives, in words. */
function origin(source: string, place: Row["place"]): { label: string; icon: typeof KeyRound; once: boolean } {
  if (place === "task") return { label: tr("Планировщик заданий", "Task Scheduler"), icon: CalendarClock, once: false };
  if (place === "service") return { label: tr("Служба Windows", "Windows service"), icon: Cog, once: false };
  const registry = /^HK(CU|LM)\\/i.test(source);
  return {
    label: registry ? tr("Реестр Windows", "Windows Registry") : tr("Папка автозагрузки", "Startup folder"),
    icon: registry ? KeyRound : FolderOpen,
    once: /RunOnce$/i.test(source),
  };
}

interface Props {
  autostart: AutostartEntry[] | null;
  /** The entries turned off through DefenseR live in the responses state. */
  responses: ResponsesState | null;
  /** Called after a change, so the lists refresh. */
  onChanged: () => void;
}

export function AutostartPage({ autostart, responses, onChanged }: Props) {
  const [filter, setFilter] = useState<Filter>("all");
  const [place, setPlace] = useState<Place>("all");
  const [query, setQuery] = useState("");
  const [asking, setAsking] = useState<Row | null>(null);
  const [forgetting, setForgetting] = useState<Row | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const all = useMemo(() => {
    const on: Row[] = (autostart ?? []).map((entry) => ({
      key: `on|${entry.source}|${entry.name}`,
      name: entry.name,
      title: entry.label ?? friendlyName(entry.name),
      place: entry.kind === "task" || entry.kind === "service" ? entry.kind : "startup",
      trigger: entry.trigger ?? null,
      command: entry.command,
      source: entry.source,
      scope: entry.scope,
      flags: entry.flags,
      entry,
      disabled: null,
    }));
    const off: Row[] = (responses?.autostart ?? []).map((item) => ({
      key: `off|${item.id}`,
      name: item.name,
      title: item.label ?? (item.kind === "task" ? (item.name.split("\\").pop() ?? item.name) : friendlyName(item.name)),
      place: item.kind === "task" || item.kind === "service" ? item.kind : "startup",
      trigger: null,
      command: item.command,
      source: item.source,
      scope: item.scope,
      flags: [],
      entry: null,
      disabled: item,
    }));
    return [...on, ...off];
  }, [autostart, responses]);

  const count = (which: Place) => all.filter((row) => row.place === which).length;
  const inPlace = all.filter((row) => place === "all" || row.place === place);
  const enabled = inPlace.filter((row) => row.entry).length;
  const disabled = inPlace.length - enabled;
  const flagged = inPlace.filter((row) => row.flags.length > 0).length;

  const rows = inPlace
    .filter((row) => filter === "all" || (filter === "on" ? row.entry : filter === "off" ? row.disabled : row.flags.length > 0))
    .filter((row) => {
      const q = query.trim().toLowerCase();
      return !q || row.name.toLowerCase().includes(q) || row.title.toLowerCase().includes(q) || row.command.toLowerCase().includes(q);
    })
    .sort((a, b) => b.flags.length - a.flags.length || Number(!!a.disabled) - Number(!!b.disabled) || a.title.localeCompare(b.title));

  const run = async (row: Row, command: string, args: Record<string, unknown>) => {
    setAsking(null);
    setForgetting(null);
    setError(null);
    setBusy(row.key);
    try {
      await call(command, args);
    } catch (e) {
      setError(String(e));
    }
    setBusy(null);
    onChanged();
  };

  const turnOff = (row: Row) => run(row, "disable_autostart", { source: row.source, name: row.name });
  const turnOn = (row: Row) => run(row, "enable_autostart", { id: row.disabled?.id });
  const toggle = (next: Filter) => setFilter(filter === next ? "all" : next);

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title={tr("Автозагрузка", "Startup")}
        subtitle={tr("Что запускается само: при входе в Windows, по расписанию или вместе с компьютером. Выключите лишнее — программа останется на месте, а запись можно включить обратно", "What starts on its own: when you sign in, on a schedule or with the computer. Turn off what you do not need — the program stays installed, and the entry can be turned back on")}
      />

      <div className="mb-4 flex gap-3">
        <StatTile icon={Rocket} label={tr("Всего записей", "All entries")} value={inPlace.length} onClick={() => setFilter("all")} active={filter === "all"} />
        <StatTile icon={Power} label={tr("Включено", "On")} value={enabled} tone="accent" hint={tr("запускаются сами", "start on their own")} onClick={() => toggle("on")} active={filter === "on"} />
        <StatTile icon={PowerOff} label={tr("Выключено вами", "Turned off by you")} value={disabled} tone="info" hint={tr("можно включить обратно", "can be turned back on")} onClick={() => toggle("off")} active={filter === "off"} />
        <StatTile
          icon={TriangleAlert}
          label={tr("Требуют внимания", "Need attention")}
          value={flagged}
          tone={flagged > 0 ? "danger" : "neutral"}
          hint={flagged > 0 ? tr("нажмите, чтобы показать", "click to show") : tr("всё в порядке", "all clear")}
          onClick={() => toggle("flagged")}
          active={filter === "flagged"}
        />
      </div>

      <div className="mb-3 flex items-center gap-3">
        <SearchInput value={query} onChange={setQuery} placeholder={tr("Название или команда", "Name or command")} />
        <Tabs
          value={place}
          onChange={setPlace}
          options={[
            { id: "all", label: tr(`Все · ${all.length}`, `All · ${all.length}`) },
            { id: "startup", label: tr(`Автозагрузка · ${count("startup")}`, `Startup · ${count("startup")}`) },
            { id: "task", label: tr(`Планировщик · ${count("task")}`, `Scheduler · ${count("task")}`) },
            { id: "service", label: tr(`Службы · ${count("service")}`, `Services · ${count("service")}`) },
          ]}
        />
      </div>
      {error && <div className="mb-3 rounded-xl border border-rose-400/25 bg-rose-400/10 px-4 py-2.5 text-sm text-rose-200">{error}</div>}

      <Card className="min-h-0 flex-1 overflow-auto p-2">
        {!autostart ? (
          <Loading />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={Rocket}
            tone="neutral"
            title={all.length === 0 ? tr("Записей автозагрузки нет", "No startup entries") : tr("Здесь пусто", "Nothing here")}
            text={all.length === 0 ? undefined : tr("Под этот фильтр не попала ни одна запись.", "No entry matches this filter.")}
          />
        ) : (
          rows.map((row, index) => {
            const from = origin(row.source, row.place);
            const on = row.entry !== null;
            return (
              <Rise key={row.key} index={index}>
                <div className={`flex items-center gap-3 rounded-xl px-3 py-3 transition-colors hover:bg-white/[0.035] ${on ? "" : "opacity-60 hover:opacity-100"}`}>
                  <Avatar name={row.name} muted={!on} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-sm font-medium" title={row.name}>{row.title}</span>
                      <FlagBadges flags={row.flags} />
                      {row.disabled && <Chip tone="info">{tr(`выключено ${formatTime(row.disabled.disabledAt)}`, `turned off ${formatTime(row.disabled.disabledAt)}`)}</Chip>}
                    </div>
                    <div className="mt-1 truncate font-mono text-xs text-white/45" title={row.command}>
                      {row.command}
                    </div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <Chip icon={row.scope === "machine" ? Users : User} title={row.source}>
                        {row.scope === "machine" ? tr("Для всех пользователей", "For all users") : tr("Только для вас", "Only for you")}
                      </Chip>
                      <Chip icon={from.icon} title={row.source}>
                        {from.label}
                      </Chip>
                      {row.trigger && <Chip icon={Clock}>{row.trigger}</Chip>}
                      {from.once && (
                        <Chip title={tr("Windows выполнит эту запись один раз и удалит её сама", "Windows runs this entry once and then removes it itself")}>
                          {tr("Сработает один раз", "Runs once")}
                        </Chip>
                      )}
                    </div>
                  </div>
                  {row.disabled && (
                    <button
                      onClick={() => setForgetting(row)}
                      title={row.place === "startup" ? tr("Удалить запись навсегда", "Delete the entry permanently") : tr("Убрать из списка", "Remove from the list")}
                      className="shrink-0 rounded-lg p-2 text-white/35 hover:bg-rose-400/10 hover:text-rose-300"
                    >
                      <Trash2 size={15} />
                    </button>
                  )}
                  <Switch
                    checked={on}
                    disabled={busy === row.key}
                    label={on ? tr("Выключить", "Turn off") : tr("Включить обратно", "Turn back on")}
                    onChange={() => (on ? setAsking(row) : turnOn(row))}
                  />
                </div>
              </Rise>
            );
          })
        )}
      </Card>

      {asking && <ConfirmDialog {...autostartDialog(asking.title, asking.scope, asking.source)} danger onConfirm={() => turnOff(asking)} onCancel={() => setAsking(null)} />}
      {forgetting && (
        <ConfirmDialog
          title={forgetting.place === "startup" ? tr(`Удалить запись «${forgetting.title}» навсегда?`, `Delete the entry “${forgetting.title}” permanently?`) : tr(`Убрать «${forgetting.title}» из списка?`, `Remove “${forgetting.title}” from the list?`)}
          body={
            forgetting.place === "startup"
              ? tr(
                  "DefenseR забудет эту запись, и вернуть её в автозагрузку будет нельзя. Сама программа останется на месте.",
                  "DefenseR will forget this entry, and it can no longer be restored to startup. The program itself will stay where it is.",
                )
              : tr(
                  "DefenseR перестанет её показывать. В Windows она останется отключённой; включить её потом можно будет только средствами самой Windows.",
                  "DefenseR will stop showing it. In Windows it stays turned off; later it can only be turned back on with Windows' own tools.",
                )
          }
          confirmLabel={forgetting.place === "startup" ? tr("Удалить навсегда", "Delete permanently") : tr("Убрать из списка", "Remove from the list")}
          danger
          onConfirm={() => run(forgetting, "forget_autostart", { id: forgetting.disabled?.id })}
          onCancel={() => setForgetting(null)}
        />
      )}
    </div>
  );
}
