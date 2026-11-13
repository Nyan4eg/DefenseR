import { useState } from "react";
import { AppWindow, ChevronDown, DoorOpen, EyeOff, Flame, Globe, GraduationCap, History, Info, ListTree, LoaderCircle, Radar, ShieldAlert, ShieldCheck, Sparkles, TriangleAlert } from "lucide-react";
import { FileCheck } from "../components/FileCheck";
import { Chip, EmptyState, IconTile, Meter, Rise, StatTile } from "../components/kit";
import { ResponseActions } from "../components/ResponseActions";
import { Card, Loading, PageHeader } from "../components/ui";
import { call, formatTime, type Incident, type ProfileStatus, type Severity } from "../lib/api";
import { tr } from "../lib/i18n";

type Filter = "active" | "high" | "minor" | "history";

const SEVERITY: Record<Severity, { label: string; bar: string; tone: "danger" | "warn" | "info"; glow: string; border: string }> = {
  high: { label: tr("Высокая важность", "High severity"), bar: "bg-rose-400", tone: "danger", glow: "from-rose-400/20", border: "border-rose-400/25" },
  medium: { label: tr("Средняя важность", "Medium severity"), bar: "bg-amber-400", tone: "warn", glow: "from-amber-400/15", border: "border-amber-400/25" },
  low: { label: tr("Низкая важность", "Low severity"), bar: "bg-sky-400", tone: "info", glow: "from-sky-400/15", border: "border-sky-400/20" },
};

const SEVERITY_ICON = { high: Flame, medium: TriangleAlert, low: Info };

const STATUS_LABELS = {
  active: tr("Активен", "Active"),
  resolved: tr("Прекратился сам", "Stopped on its own"),
  dismissed: tr("Скрыт", "Hidden"),
};

interface CardProps {
  incident: Incident;
  hasKey: boolean;
  open: boolean;
  onToggle: () => void;
  onChanged: () => void;
  onOpenSettings: () => void;
}

function IncidentCard({ incident, hasKey, open, onToggle, onChanged, onOpenSettings }: CardProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const severity = SEVERITY[incident.severity];
  const path = incident.target?.path ?? null;
  const sha256 = incident.evidence.find((item) => item.label === "SHA-256")?.value || null;
  const label = "mb-1.5 text-xs text-white/40";

  const explain = async () => {
    setBusy(true);
    setError(null);
    try {
      await call("explain_incident", { id: incident.id });
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const dismiss = async () => {
    await call("dismiss_incident", { id: incident.id });
    onChanged();
  };

  return (
    <div className={`relative overflow-hidden rounded-2xl border bg-white/[0.04] backdrop-blur-sm transition-colors ${open ? severity.border : "border-white/8 hover:border-white/15"}`}>
      <div className={`absolute inset-y-0 left-0 w-1 ${severity.bar}`} />
      <div className={`pointer-events-none absolute -left-10 -top-10 size-40 rounded-full bg-gradient-to-br ${severity.glow} to-transparent blur-2xl`} />

      <div
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={onToggle}
        onKeyDown={(e) => {
          if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) onToggle();
        }}
        className="relative flex cursor-pointer items-start gap-3.5 py-4 pl-6 pr-4"
      >
        <IconTile icon={SEVERITY_ICON[incident.severity]} tone={severity.tone} size={40} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <Chip tone={severity.tone}>{severity.label}</Chip>
            {incident.status !== "active" && <Chip>{STATUS_LABELS[incident.status]}</Chip>}
            {incident.timeline && incident.timeline.length > 0 && (
              <Chip icon={ListTree}>{tr(`Цепочка событий: ${incident.timeline.length}`, `Chain of events: ${incident.timeline.length}`)}</Chip>
            )}
            {incident.explanation && (
              <Chip icon={Sparkles} tone="accent">
                {tr("Есть объяснение", "Explained")}
              </Chip>
            )}
            <span className="ml-1 text-xs text-white/35">
              {formatTime(incident.firstSeen)}
              {incident.lastSeen - incident.firstSeen > 60 && ` — ${formatTime(incident.lastSeen)}`}
            </span>
          </div>
          <h2 className="mt-1.5 text-base font-semibold">{incident.title}</h2>
          <p className={`mt-0.5 text-sm text-white/60 ${open ? "" : "truncate"}`}>{incident.summary}</p>
        </div>

        {incident.status === "active" && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              dismiss();
            }}
            title={tr("Скрыть: инцидент больше не будет показываться", "Hide: the incident will no longer be shown")}
            className="flex shrink-0 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-white/45 hover:bg-white/8 hover:text-white/80"
          >
            <EyeOff size={14} />
            {tr("Скрыть", "Hide")}
          </button>
        )}
        <ChevronDown size={17} className={`mt-1.5 shrink-0 text-white/30 transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </div>

      {open && (
        <div className="rise relative flex flex-col gap-4 pb-5 pl-6 pr-5">
          {incident.timeline && incident.timeline.length > 0 && (
            <div>
              <div className={label}>{tr("Как это происходило", "How it happened")}</div>
              <ol className="rounded-xl border border-white/8 bg-black/15 px-4 py-3">
                {incident.timeline.map((event, index) => (
                  <li key={index} className="relative flex gap-3 pb-3 text-sm last:pb-0">
                    {index < incident.timeline!.length - 1 && <span className="absolute left-[3px] top-3 h-full w-px bg-white/12" />}
                    <span className={`relative mt-1.5 size-[7px] shrink-0 rounded-full ${severity.bar}`} />
                    <span className="w-28 shrink-0 text-xs leading-5 text-white/40">{formatTime(event.at)}</span>
                    <span className="min-w-0 flex-1 break-words text-white/80">{event.text}</span>
                  </li>
                ))}
                <li className="mt-2 text-xs text-white/35">
                  {tr(
                    "Время — когда DefenseR заметил событие; само оно могло случиться на несколько секунд раньше.",
                    "The time is when DefenseR noticed the event; the event itself may have happened a few seconds earlier.",
                  )}
                </li>
              </ol>
            </div>
          )}

          <div>
            <div className={label}>{tr("Подробности", "Details")}</div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 rounded-xl bg-black/20 px-3 py-2.5 text-xs">
              {incident.evidence.map((item) => (
                <div key={item.label} className="contents">
                  <dt className="text-white/40">{item.label}</dt>
                  <dd className="select-text break-all font-mono text-white/75">{item.value}</dd>
                </div>
              ))}
            </dl>
          </div>

          {incident.status === "active" && incident.target && (
            <div>
              <div className={label}>{tr("Что можно сделать", "What you can do")}</div>
              <ResponseActions target={incident.target} name={incident.target.path?.split("\\").pop() ?? incident.target.autostart?.name ?? tr("процесс", "process")} onDone={onChanged} />
            </div>
          )}

          {(path || sha256 || incident.reputation) && (
            <FileCheck path={path} sha256={sha256} incidentId={incident.id} reputation={incident.reputation} canTrust={incident.status === "active"} onDone={onChanged} />
          )}

          {incident.explanation ? (
            <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/[0.06] px-4 py-3">
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-emerald-300">
                <Sparkles size={13} />
                {tr("Объяснение Claude", "Explanation from Claude")}
              </div>
              <p className="select-text whitespace-pre-wrap text-sm leading-relaxed text-white/80">{incident.explanation}</p>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-3">
              {hasKey ? (
                <button
                  onClick={explain}
                  disabled={busy}
                  className="relative flex items-center gap-2 overflow-hidden rounded-lg bg-emerald-400/15 px-3 py-1.5 text-sm text-emerald-200 hover:bg-emerald-400/25 disabled:opacity-60"
                >
                  {busy && <span className="shimmer pointer-events-none absolute inset-0" />}
                  {busy ? <LoaderCircle size={15} className="animate-spin" /> : <Sparkles size={15} />}
                  {busy ? tr("Claude анализирует…", "Claude is analysing…") : tr("Объяснить с помощью ИИ", "Explain with AI")}
                </button>
              ) : (
                <button onClick={onOpenSettings} className="flex items-center gap-2 rounded-lg bg-white/8 px-3 py-1.5 text-sm text-white/70 hover:bg-white/12">
                  <Sparkles size={15} />
                  {tr("Добавить ключ API для объяснений", "Add an API key for explanations")}
                </button>
              )}
              {hasKey && !busy && !error && (
                <span className="text-xs text-white/35">
                  {tr(
                    "В Anthropic уйдут заголовок, описание и детали выше; путь к вашему профилю заменяется на %USERPROFILE%.",
                    "The title, summary and details above will be sent to Anthropic; the path to your profile is replaced with %USERPROFILE%.",
                  )}
                </span>
              )}
              {error && <span className="text-xs text-rose-300">{error}</span>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** What the behavioural profile knows so far, and whether it is still learning. */
function ProfileCard({ profile }: { profile: ProfileStatus }) {
  const minutesLeft = Math.max(1, Math.ceil((profile.learningSecs - profile.observedSecs) / 60));
  return (
    <Card className="mb-4 flex items-center gap-4 px-5 py-3.5">
      <div className="relative shrink-0">
        <IconTile icon={profile.learning ? GraduationCap : Radar} tone="accent" size={40} />
        <span className="absolute -right-0.5 -top-0.5 flex size-2.5">
          <span className="ping-soft absolute inset-0 rounded-full bg-emerald-400" />
          <span className="relative size-2.5 rounded-full bg-emerald-400" />
        </span>
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">
          {profile.learning ? tr("Изучаю, как обычно ведёт себя компьютер", "Learning how this computer normally behaves") : tr("Слежу за необычным поведением", "Watching for unusual behaviour")}
        </div>
        <div className="mt-0.5 text-xs leading-relaxed text-white/50">
          {profile.learning
            ? tr(
                `Запоминаю, какие программы здесь работают и какие из них пользуются сетью. Осталось около ${minutesLeft} мин работы приложения — после этого начну сообщать о новом поведении.`,
                `Learning which programs run here and which of them use the network. About ${minutesLeft} min of app running time left — after that I will start reporting new behaviour.`,
              )
            : tr(
                "Сообщаю, когда в интернет выходит новая программа, когда знакомая программа делает это впервые или начинает принимать подключения.",
                "I report when a new program goes online, when a familiar program does so for the first time, or when it starts accepting connections.",
              )}
        </div>
        {profile.learning && <Meter value={profile.observedSecs / profile.learningSecs} className="mt-2" />}
        <div className="mt-2 flex flex-wrap gap-1.5">
          <Chip icon={AppWindow}>{tr(`Знакомых программ: ${profile.programs}`, `Known programs: ${profile.programs}`)}</Chip>
          <Chip icon={Globe}>{tr(`Выходят в интернет: ${profile.networkPrograms}`, `Go online: ${profile.networkPrograms}`)}</Chip>
          <Chip icon={DoorOpen}>{tr(`Принимают подключения: ${profile.listeningPrograms}`, `Accept connections: ${profile.listeningPrograms}`)}</Chip>
        </div>
      </div>
    </Card>
  );
}

interface Props {
  incidents: Incident[] | null;
  profile: ProfileStatus | null;
  hasKey: boolean;
  onChanged: () => void;
  onOpenSettings: () => void;
}

const ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 };

export function IncidentsPage({ incidents, profile, hasKey, onChanged, onOpenSettings }: Props) {
  const [filter, setFilter] = useState<Filter>("active");
  /** Cards the user opened or closed by hand; the rest follow the default. */
  const [toggled, setToggled] = useState<Record<string, boolean>>({});

  const active = (incidents?.filter((i) => i.status === "active") ?? []).sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || b.lastSeen - a.lastSeen);
  const high = active.filter((i) => i.severity === "high");
  const minor = active.filter((i) => i.severity !== "high");
  const history = (incidents?.filter((i) => i.status !== "active") ?? []).sort((a, b) => b.lastSeen - a.lastSeen);
  const shown = filter === "active" ? active : filter === "high" ? high : filter === "minor" ? minor : history;
  const toggle = (next: Filter) => setFilter(filter === next ? "active" : next);

  return (
    <>
      <PageHeader
        title={tr("Инциденты", "Incidents")}
        subtitle={tr(
          "То, что DefenseR счёл достойным вашего внимания: что случилось и что с этим можно сделать",
          "What DefenseR thought deserves your attention: what happened and what you can do about it",
        )}
      />

      <div className="mb-4 flex gap-3">
        <StatTile
          icon={ShieldAlert}
          label={tr("Активные", "Active")}
          value={active.length}
          tone={active.length > 0 ? "warn" : "accent"}
          hint={active.length > 0 ? tr("ждут вашего решения", "waiting for your decision") : tr("всё спокойно", "all quiet")}
          onClick={() => setFilter("active")}
          active={filter === "active"}
        />
        <StatTile
          icon={Flame}
          label={tr("Высокая важность", "High severity")}
          value={high.length}
          tone={high.length > 0 ? "danger" : "neutral"}
          hint={tr("стоит посмотреть первыми", "worth looking at first")}
          onClick={() => toggle("high")}
          active={filter === "high"}
        />
        <StatTile
          icon={TriangleAlert}
          label={tr("Средняя и низкая", "Medium and low")}
          value={minor.length}
          tone={minor.length > 0 ? "warn" : "neutral"}
          hint={tr("необычное, но не срочное", "unusual, but not urgent")}
          onClick={() => toggle("minor")}
          active={filter === "minor"}
        />
        <StatTile
          icon={History}
          label={tr("История", "History")}
          value={history.length}
          hint={tr("скрытые и прекратившиеся", "hidden and stopped")}
          onClick={() => toggle("history")}
          active={filter === "history"}
        />
      </div>

      {profile && <ProfileCard profile={profile} />}

      {!incidents ? (
        <Loading />
      ) : shown.length === 0 ? (
        <Card>
          <EmptyState
            icon={filter === "history" ? History : ShieldCheck}
            tone={filter === "history" ? "neutral" : "accent"}
            title={
              filter === "history" ? tr("История пуста", "History is empty") : filter === "active" ? tr("Активных инцидентов нет", "No active incidents") : tr("Таких инцидентов нет", "No such incidents")
            }
            text={
              filter === "history"
                ? undefined
                : tr("DefenseR проверяет систему каждые 10 секунд и сообщит, если что-то изменится.", "DefenseR checks the system every 10 seconds and will tell you if anything changes.")
            }
          />
        </Card>
      ) : (
        <div className="flex flex-col gap-3">
          {shown.map((incident, index) => {
            // Open by default while there are few; in a long list only the first, so the list stays readable.
            const byDefault = incident.status === "active" && (shown.length <= 3 || index === 0);
            const open = toggled[incident.id] ?? byDefault;
            return (
              <Rise key={incident.id} index={index}>
                <IncidentCard
                  incident={incident}
                  hasKey={hasKey}
                  open={open}
                  onToggle={() => setToggled((prev) => ({ ...prev, [incident.id]: !open }))}
                  onChanged={onChanged}
                  onOpenSettings={onOpenSettings}
                />
              </Rise>
            );
          })}
        </div>
      )}
    </>
  );
}
