import { useEffect, useState } from "react";
import { CircleCheck, FileSearch, KeyRound, Languages, LoaderCircle, MonitorCog, RefreshCw } from "lucide-react";
import { applyLang, lang, type Lang } from "../lib/i18n";
import { Card, PageHeader } from "../components/ui";
import { call, formatTime, inTauri, usePolling, type AiStatus, type AppSettings, type UpdateStatus } from "../lib/api";

function Toggle({ checked, disabled, onChange }: { checked: boolean; disabled?: boolean; onChange: (value: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-40 ${checked ? "bg-emerald-400/70" : "bg-white/15"}`}
    >
      <span className={`absolute left-0.5 top-0.5 size-5 rounded-full bg-white transition-transform ${checked ? "translate-x-5" : ""}`} />
    </button>
  );
}

/** Start with Windows and incident notifications. */
function BackgroundCard() {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [autostart, setAutostart] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    call<AppSettings>("get_settings").then(setSettings).catch((e) => setError(String(e)));
    if (inTauri) {
      import("@tauri-apps/plugin-autostart").then(({ isEnabled }) => isEnabled()).then(setAutostart).catch((e) => setError(String(e)));
    }
  }, []);

  const changeAutostart = async (enabled: boolean) => {
    setError(null);
    try {
      if (inTauri) {
        const { enable, disable } = await import("@tauri-apps/plugin-autostart");
        await (enabled ? enable() : disable());
      }
      setAutostart(enabled);
    } catch (e) {
      setError(String(e));
    }
  };

  const changeNotifications = async (enabled: boolean) => {
    setError(null);
    try {
      await call("set_notifications", { enabled });
      setSettings((prev) => prev && { ...prev, notifications: enabled });
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <Card className="mt-4 max-w-2xl p-5">
      <div className="flex items-center gap-2 text-sm font-medium">
        <MonitorCog size={16} className="text-emerald-400" />
        Работа в фоне
      </div>
      <p className="mt-2 text-sm text-white/55">
        Когда вы закрываете окно, DefenseR остаётся в области уведомлений и продолжает следить за компьютером. Полностью выйти можно через
        значок там же.
      </p>

      <div className="mt-4 flex items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm">Запускать вместе с Windows</div>
          <div className="mt-0.5 text-xs text-white/45">
            {settings?.devBuild
              ? "Недоступно в сборке для разработки: установите DefenseR через установщик."
              : "DefenseR будет стартовать при входе в систему, сразу свёрнутым в область уведомлений."}
          </div>
        </div>
        <Toggle checked={autostart} disabled={!settings || settings.devBuild} onChange={changeAutostart} />
      </div>

      <div className="mt-4 flex items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm">Уведомления о новых инцидентах</div>
          <div className="mt-0.5 text-xs text-white/45">Только средней и высокой важности. Инциденты низкой важности видны в окне.</div>
        </div>
        <Toggle checked={settings?.notifications ?? false} disabled={!settings} onChange={changeNotifications} />
      </div>
      {error && <div className="mt-3 text-sm text-rose-300">{error}</div>}
    </Card>
  );
}

type FileOption = "watchDownloads" | "watchTemp" | "watchRemovable" | "autoVirustotal";

const FILE_OPTIONS: { key: FileOption; title: string; description: string }[] = [
  {
    key: "watchDownloads",
    title: "«Загрузки» и рабочий стол",
    description: "Программы, которые появляются в этих папках, сразу оцениваются моделью и проверяются на подпись. Архивы не распаковываются.",
  },
  {
    key: "watchTemp",
    title: "Временная папка",
    description: "Сюда распаковываются установщики и сюда же часто кладут свои файлы вредоносные программы. Об этой папке сообщается только при уверенной оценке модели или нарушенной подписи.",
  },
  {
    key: "watchRemovable",
    title: "Флешки и другие съёмные диски",
    description: "При подключении диска проверяются все программы на нём, затем — новые.",
  },
  {
    key: "autoVirustotal",
    title: "Спрашивать VirusTotal автоматически",
    description: "Когда модель считает файл вредоносным, DefenseR сам отправит его SHA-256 в VirusTotal и поднимет важность инцидента, если антивирусы согласны. Нужен ключ VirusTotal. Выключено, пока вы не включите: отпечатки файлов будут уходить без вашего нажатия.",
  },
];

/** Which places are watched for new programs, and whether VirusTotal is asked on its own. */
function FilesCard({ hasVtKey }: { hasVtKey: boolean }) {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    call<AppSettings>("get_settings").then(setSettings).catch((e) => setError(String(e)));
  }, []);

  const change = async (key: FileOption, enabled: boolean) => {
    setError(null);
    try {
      await (key === "watchDownloads" ? call("set_watch_downloads", { enabled }) : call("set_option", { name: key, enabled }));
      setSettings((prev) => prev && { ...prev, [key]: enabled });
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <Card className="mt-4 max-w-2xl p-5">
      <div className="flex items-center gap-2 text-sm font-medium">
        <FileSearch size={16} className="text-emerald-400" />
        Проверка новых файлов
      </div>
      {FILE_OPTIONS.map(({ key, title, description }) => (
        <div key={key} className="mt-4 flex items-center gap-4">
          <div className="min-w-0 flex-1">
            <div className="text-sm">{title}</div>
            <div className="mt-0.5 text-xs text-white/45">{description}</div>
            {key === "autoVirustotal" && settings?.autoVirustotal && !hasVtKey && (
              <div className="mt-1 text-xs text-amber-300">Ключ VirusTotal не добавлен, поэтому запросы не отправляются.</div>
            )}
          </div>
          <Toggle checked={settings?.[key] ?? false} disabled={!settings} onChange={(enabled) => change(key, enabled)} />
        </div>
      ))}
      {error && <div className="mt-3 text-sm text-rose-300">{error}</div>}
    </Card>
  );
}

/** The installed version, checking for a newer one and installing it. */
function UpdatesCard() {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [automatic, setAutomatic] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = () => call<UpdateStatus>("get_update_status").then(setStatus).catch((e) => setError(String(e)));
    load();
    call<AppSettings>("get_settings").then((settings) => setAutomatic(settings.autoUpdate)).catch((e) => setError(String(e)));
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  const run = async (command: "check_update" | "install_update") => {
    setError(null);
    setStatus((prev) => prev && { ...prev, checking: command === "check_update", installing: command === "install_update", error: null });
    try {
      const result = await call<UpdateStatus | null>(command);
      if (result) setStatus(result);
    } catch (e) {
      setError(String(e));
      call<UpdateStatus>("get_update_status").then(setStatus).catch(() => {});
    }
  };

  const changeAutomatic = async (enabled: boolean) => {
    setError(null);
    try {
      await call("set_auto_update", { enabled });
      setAutomatic(enabled);
    } catch (e) {
      setError(String(e));
    }
  };

  const busy = !status || status.checking || status.installing;
  const state = !status
    ? "Загрузка…"
    : status.installing
      ? `Устанавливается версия ${status.available ?? ""}. DefenseR перезапустится сам.`
      : status.checking
        ? "Проверка…"
        : status.available
          ? `Доступна версия ${status.available}`
          : status.checkedAt
            ? `Установлена последняя версия · проверено ${formatTime(status.checkedAt)}`
            : "Обновления ещё не проверялись";
  const button = "flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm disabled:opacity-40";

  return (
    <Card className="mt-4 max-w-2xl p-5">
      <div className="flex items-center gap-2 text-sm font-medium">
        <RefreshCw size={16} className="text-emerald-400" />
        Обновления
      </div>
      <div className="mt-3 flex items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm">DefenseR {status?.current}</div>
          <div className={`mt-0.5 text-xs ${status?.available ? "text-emerald-300" : "text-white/45"}`}>{state}</div>
        </div>
        {status?.available && !status.devBuild && (
          <button onClick={() => run("install_update")} disabled={busy} className={`${button} bg-emerald-400/15 text-emerald-200 hover:bg-emerald-400/25`}>
            {status.installing && <LoaderCircle size={14} className="animate-spin" />}
            Установить
          </button>
        )}
        <button onClick={() => run("check_update")} disabled={busy} className={`${button} bg-white/8 text-white/70 hover:bg-white/12`}>
          {status?.checking && <LoaderCircle size={14} className="animate-spin" />}
          Проверить
        </button>
      </div>
      {status?.available && status.notes && <p className="mt-3 whitespace-pre-line rounded-xl bg-black/20 px-3 py-2.5 text-xs text-white/60">{status.notes}</p>}
      {status?.devBuild && <p className="mt-3 text-xs text-white/45">Это сборка для разработки: она проверяет обновления, но не устанавливает их.</p>}

      <div className="mt-4 flex items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm">Устанавливать обновления автоматически</div>
          <div className="mt-0.5 text-xs text-white/45">
            Новая версия ставится сама, когда окно свёрнуто в область уведомлений. Обновления берутся из выпусков проекта на GitHub и
            принимаются только с подписью разработчика.
          </div>
        </div>
        <Toggle checked={automatic ?? false} disabled={automatic === null} onChange={changeAutomatic} />
      </div>
      {(error ?? status?.error) && <div className="mt-3 text-sm text-rose-300">{error ?? status?.error}</div>}
    </Card>
  );
}

/** Switches the interface language; the window reloads to apply it. */
function LanguageCard() {
  const choose = async (next: Lang) => {
    if (next === lang) return;
    await call("set_language", { language: next }).catch(() => {});
    applyLang(next);
  };

  return (
    <Card className="mb-4 flex max-w-2xl items-center gap-4 p-5">
      <Languages size={16} className="shrink-0 text-emerald-400" />
      <div className="min-w-0 flex-1 text-sm font-medium">Язык · Language</div>
      <div className="flex gap-1 rounded-lg bg-white/5 p-1">
        {(["ru", "en"] as const).map((code) => (
          <button
            key={code}
            onClick={() => choose(code)}
            className={`rounded-md px-3 py-1 text-sm ${code === lang ? "bg-white/12 text-white" : "text-white/55 hover:text-white/85"}`}
          >
            {code === "ru" ? "Русский" : "English"}
          </button>
        ))}
      </div>
    </Card>
  );
}

interface KeyCardProps {
  title: string;
  description: string;
  placeholder: string;
  hasKey: boolean;
  setCommand: string;
  clearCommand: string;
  onChanged: () => void;
  className?: string;
}

/** Entering and removing an API key. The key itself is never shown again. */
function KeyCard({ title, description, placeholder, hasKey, setCommand, clearCommand, onChanged, className = "" }: KeyCardProps) {
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);

  const run = async (command: string, args?: Record<string, unknown>) => {
    setError(null);
    try {
      await call(command, args);
      setKey("");
      onChanged();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <Card className={`max-w-2xl p-5 ${className}`}>
      <div className="flex items-center gap-2 text-sm font-medium">
        <KeyRound size={16} className="text-emerald-400" />
        {title}
      </div>
      <p className="mt-2 text-sm text-white/55">{description}</p>

      {hasKey ? (
        <div className="mt-4 flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-sm text-emerald-300">
            <CircleCheck size={16} />
            Ключ сохранён
          </span>
          <button onClick={() => run(clearCommand)} className="rounded-lg bg-white/8 px-3 py-1.5 text-sm text-white/70 hover:bg-white/12">
            Удалить ключ
          </button>
        </div>
      ) : (
        <form
          className="mt-4 flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            run(setCommand, { key });
          }}
        >
          <input
            type="password"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder={placeholder}
            autoComplete="off"
            className="min-w-0 flex-1 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-sm outline-none placeholder:text-white/30 focus:border-emerald-400/50"
          />
          <button
            type="submit"
            disabled={!key.trim()}
            className="rounded-lg bg-emerald-400/15 px-4 py-1.5 text-sm text-emerald-200 hover:bg-emerald-400/25 disabled:opacity-40"
          >
            Сохранить
          </button>
        </form>
      )}
      {error && <div className="mt-3 text-sm text-rose-300">{error}</div>}
    </Card>
  );
}

export function SettingsPage({ hasKey, onChanged }: { hasKey: boolean; onChanged: () => void }) {
  const [vtKey, setVtKey] = useState(0);
  const vt = usePolling<AiStatus>("get_vt_status", 60_000, vtKey);

  return (
    <>
      <PageHeader title="Настройки" subtitle="Ключи, работа в фоне и обновления" />

      <LanguageCard />
      <KeyCard
        title="Ключ Anthropic API"
        description="Ключ нужен, чтобы Claude объяснял инциденты простым языком. Он хранится в диспетчере учётных данных Windows, а не в файлах приложения. Получить ключ можно в консоли Anthropic; запросы оплачиваются с вашего аккаунта."
        placeholder="sk-ant-…"
        hasKey={hasKey}
        setCommand="set_api_key"
        clearCommand="clear_api_key"
        onChanged={onChanged}
      />
      <KeyCard
        className="mt-4"
        title="Ключ VirusTotal"
        description="С ключом можно узнать, что о файле думают десятки антивирусов: кнопка «Проверить на VirusTotal» есть в инцидентах и в результатах проверки файлов. Бесплатный ключ выдаётся в профиле на virustotal.com и даёт 4 проверки в минуту, 500 в день. Хранится там же, в диспетчере учётных данных Windows."
        placeholder="64 символа"
        hasKey={vt?.hasKey ?? false}
        setCommand="set_vt_key"
        clearCommand="clear_vt_key"
        onChanged={() => setVtKey((key) => key + 1)}
      />

      <FilesCard hasVtKey={vt?.hasKey ?? false} />
      <BackgroundCard />
      <UpdatesCard />

      <Card className="mt-4 max-w-2xl p-5 text-sm text-white/55">
        <div className="font-medium text-white/85">Что покидает компьютер</div>
        <p className="mt-2">
          В Anthropic — ничего, пока вы не нажмёте «Объяснить с помощью ИИ» в карточке инцидента. Тогда уходят заголовок, описание и детали
          именно этого инцидента: имена процессов, пути и команды. Путь к папке вашего профиля заменяется на %USERPROFILE%.
        </p>
        <p className="mt-2">
          В VirusTotal — только SHA-256 файла (его цифровой отпечаток): по кнопке «Проверить на VirusTotal», а если вы включили автоматическую
          проверку — ещё и для файлов, которые модель сочла вредоносными. Сам файл, его имя и путь не отправляются.
        </p>
        <p className="mt-2">Список процессов, сетевые соединения и остальные данные компьютер не покидают.</p>
      </Card>
    </>
  );
}
