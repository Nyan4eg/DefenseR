import { useState } from "react";
import { EyeOff, GraduationCap, LoaderCircle, Radar, ShieldCheck, Sparkles } from "lucide-react";
import { FileCheck } from "../components/FileCheck";
import { ResponseActions } from "../components/ResponseActions";
import { Badge, Card, Loading, PageHeader, Tabs } from "../components/ui";
import { call, formatTime, type Incident, type ProfileStatus, type Severity } from "../lib/api";

type Filter = "active" | "history";

const SEVERITY: Record<Severity, { label: string; bar: string; text: string }> = {
  high: { label: "Высокая", bar: "bg-rose-400", text: "text-rose-300" },
  medium: { label: "Средняя", bar: "bg-amber-400", text: "text-amber-300" },
  low: { label: "Низкая", bar: "bg-sky-400", text: "text-sky-300" },
};

const STATUS_LABELS = { active: "Активен", resolved: "Прекратился сам", dismissed: "Скрыт" };

interface CardProps {
  incident: Incident;
  hasKey: boolean;
  onChanged: () => void;
  onOpenSettings: () => void;
}

function IncidentCard({ incident, hasKey, onChanged, onOpenSettings }: CardProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const severity = SEVERITY[incident.severity];
  const path = incident.target?.path ?? null;
  const sha256 = incident.evidence.find((item) => item.label === "SHA-256")?.value || null;

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
    <Card className="relative overflow-hidden p-5 pl-6">
      <div className={`absolute inset-y-0 left-0 w-1 ${severity.bar}`} />

      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className={`font-medium ${severity.text}`}>{severity.label} важность</span>
            {incident.status !== "active" && <Badge>{STATUS_LABELS[incident.status]}</Badge>}
            <span className="text-white/35">
              {formatTime(incident.firstSeen)}
              {incident.lastSeen - incident.firstSeen > 60 && ` — ${formatTime(incident.lastSeen)}`}
            </span>
          </div>
          <h2 className="mt-1.5 text-base font-semibold">{incident.title}</h2>
          <p className="mt-1 text-sm text-white/60">{incident.summary}</p>
        </div>

        {incident.status === "active" && (
          <button
            onClick={dismiss}
            title="Скрыть: инцидент больше не будет показываться"
            className="flex shrink-0 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-white/45 hover:bg-white/8 hover:text-white/80"
          >
            <EyeOff size={14} />
            Скрыть
          </button>
        )}
      </div>

      <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 rounded-xl bg-black/20 px-3 py-2.5 text-xs">
        {incident.evidence.map((item) => (
          <div key={item.label} className="contents">
            <dt className="text-white/40">{item.label}</dt>
            <dd className="select-text break-all font-mono text-white/75">{item.value}</dd>
          </div>
        ))}
      </dl>

      {incident.status === "active" && incident.target && (
        <div className="mt-3">
          <ResponseActions target={incident.target} name={incident.target.path?.split("\\").pop() ?? incident.target.autostart?.name ?? "процесс"} onDone={onChanged} />
        </div>
      )}

      {(path || sha256 || incident.reputation) && (
        <div className="mt-3">
          <FileCheck
            path={path}
            sha256={sha256}
            incidentId={incident.id}
            reputation={incident.reputation}
            canTrust={incident.status === "active"}
            onDone={onChanged}
          />
        </div>
      )}

      {incident.explanation ? (
        <div className="mt-3 rounded-xl border border-emerald-400/20 bg-emerald-400/[0.06] px-4 py-3">
          <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-emerald-300">
            <Sparkles size={13} />
            Объяснение Claude
          </div>
          <p className="select-text whitespace-pre-wrap text-sm leading-relaxed text-white/80">{incident.explanation}</p>
        </div>
      ) : (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          {hasKey ? (
            <button
              onClick={explain}
              disabled={busy}
              className="flex items-center gap-2 rounded-lg bg-emerald-400/15 px-3 py-1.5 text-sm text-emerald-200 hover:bg-emerald-400/25 disabled:opacity-60"
            >
              {busy ? <LoaderCircle size={15} className="animate-spin" /> : <Sparkles size={15} />}
              {busy ? "Claude анализирует…" : "Объяснить с помощью ИИ"}
            </button>
          ) : (
            <button onClick={onOpenSettings} className="flex items-center gap-2 rounded-lg bg-white/8 px-3 py-1.5 text-sm text-white/70 hover:bg-white/12">
              <Sparkles size={15} />
              Добавить ключ API для объяснений
            </button>
          )}
          {hasKey && !busy && !error && (
            <span className="text-xs text-white/35">В Anthropic уйдут заголовок, описание и детали выше; путь к вашему профилю заменяется на %USERPROFILE%.</span>
          )}
          {error && <span className="text-xs text-rose-300">{error}</span>}
        </div>
      )}
    </Card>
  );
}

/** What the behavioural profile knows so far, and whether it is still learning. */
function ProfileCard({ profile }: { profile: ProfileStatus }) {
  const minutesLeft = Math.max(1, Math.ceil((profile.learningSecs - profile.observedSecs) / 60));
  const Icon = profile.learning ? GraduationCap : Radar;
  return (
    <Card className="mb-4 flex items-center gap-4 px-5 py-3.5">
      <Icon size={20} className="shrink-0 text-emerald-400" />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{profile.learning ? "Профиль поведения: изучаю компьютер" : "Профиль поведения активен"}</div>
        <div className="mt-0.5 text-xs text-white/50">
          {profile.learning
            ? `Запоминаю, какие программы здесь работают и какие из них пользуются сетью. Осталось около ${minutesLeft} мин работы приложения — после этого начну сообщать о новом поведении.`
            : "Сообщаю, когда в интернет выходит новая программа, когда знакомая программа делает это впервые или начинает принимать подключения."}
        </div>
        {profile.learning && (
          <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/8">
            <div className="h-full rounded-full bg-emerald-400" style={{ width: `${Math.min(100, (profile.observedSecs / profile.learningSecs) * 100)}%` }} />
          </div>
        )}
      </div>
      <div className="shrink-0 text-right text-xs text-white/45">
        <div>Программ: {profile.programs}</div>
        <div>Выходят в интернет: {profile.networkPrograms}</div>
        <div>Принимают подключения: {profile.listeningPrograms}</div>
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

export function IncidentsPage({ incidents, profile, hasKey, onChanged, onOpenSettings }: Props) {
  const [filter, setFilter] = useState<Filter>("active");

  const active = incidents?.filter((i) => i.status === "active") ?? [];
  const history = incidents?.filter((i) => i.status !== "active") ?? [];
  const shown = filter === "active" ? active : history;

  return (
    <>
      <PageHeader title="Инциденты" subtitle={incidents ? `Активных: ${active.length} · в истории: ${history.length}` : "Сбор данных…"}>
        <Tabs
          value={filter}
          onChange={setFilter}
          options={[
            { id: "active", label: "Активные" },
            { id: "history", label: "История" },
          ]}
        />
      </PageHeader>

      {profile && <ProfileCard profile={profile} />}

      {!incidents ? (
        <Loading />
      ) : shown.length === 0 ? (
        <Card className="flex flex-col items-center px-6 py-14 text-center">
          <ShieldCheck size={36} className="text-emerald-400" />
          <div className="mt-3 text-sm text-white/70">{filter === "active" ? "Активных инцидентов нет" : "История пуста"}</div>
          {filter === "active" && <div className="mt-1 text-xs text-white/40">Правила проверяют систему каждые 10 секунд</div>}
        </Card>
      ) : (
        <div className="flex flex-col gap-3">
          {shown.map((incident) => (
            <IncidentCard key={incident.id} incident={incident} hasKey={hasKey} onChanged={onChanged} onOpenSettings={onOpenSettings} />
          ))}
        </div>
      )}
    </>
  );
}
