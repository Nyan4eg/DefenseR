import { useEffect, useState } from "react";
import { CircleCheck, FileSearch, KeyRound, Languages, LoaderCircle, MonitorCog, RefreshCw } from "lucide-react";
import { applyLang, lang, tr, type Lang } from "../lib/i18n";
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
        {tr("Работа в фоне", "Running in the background")}
      </div>
      <p className="mt-2 text-sm text-white/55">
        {tr("Когда вы закрываете окно, DefenseR остаётся в области уведомлений и продолжает следить за компьютером. Полностью выйти можно через значок там же.", "When you close the window, DefenseR stays in the notification area and keeps watching the computer. To quit completely, use its icon there.")}
      </p>

      <div className="mt-4 flex items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm">{tr("Запускать вместе с Windows", "Start with Windows")}</div>
          <div className="mt-0.5 text-xs text-white/45">
            {settings?.devBuild
              ? tr("Недоступно в сборке для разработки: установите DefenseR через установщик.", "Not available in a development build: install DefenseR with the installer.")
              : tr("DefenseR будет стартовать при входе в систему, сразу свёрнутым в область уведомлений.", "DefenseR will start when you sign in, minimised to the notification area straight away.")}
          </div>
        </div>
        <Toggle checked={autostart} disabled={!settings || settings.devBuild} onChange={changeAutostart} />
      </div>

      <div className="mt-4 flex items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm">{tr("Уведомления о новых инцидентах", "Notifications about new incidents")}</div>
          <div className="mt-0.5 text-xs text-white/45">{tr("Только средней и высокой важности. Инциденты низкой важности видны в окне.", "Medium and high severity only. Low-severity incidents are shown in the window.")}</div>
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
    title: tr("«Загрузки» и рабочий стол", "Downloads and the desktop"),
    description: tr("Программы, которые появляются в этих папках, сразу оцениваются моделью и проверяются на подпись. Архивы не распаковываются.", "Programs that appear in these folders are scored by the model and checked for a signature straight away. Archives are not unpacked."),
  },
  {
    key: "watchTemp",
    title: tr("Временная папка", "Temp folder"),
    description: tr("Сюда распаковываются установщики и сюда же часто кладут свои файлы вредоносные программы. Об этой папке сообщается только при уверенной оценке модели или нарушенной подписи.", "Installers unpack here, and malware often puts its files here too. This folder is only reported when the model is confident or a signature is broken."),
  },
  {
    key: "watchRemovable",
    title: tr("Флешки и другие съёмные диски", "USB sticks and other removable drives"),
    description: tr("При подключении диска проверяются все программы на нём, затем — новые.", "When a drive is connected, all programs on it are checked, and then any new ones."),
  },
  {
    key: "autoVirustotal",
    title: tr("Спрашивать VirusTotal автоматически", "Ask VirusTotal automatically"),
    description: tr("Когда модель считает файл вредоносным, DefenseR сам отправит его SHA-256 в VirusTotal и поднимет важность инцидента, если антивирусы согласны. Нужен ключ VirusTotal. Выключено, пока вы не включите: отпечатки файлов будут уходить без вашего нажатия.", "When the model considers a file malicious, DefenseR will send its SHA-256 to VirusTotal on its own and raise the incident's severity if antivirus engines agree. Requires a VirusTotal key. Off until you turn it on: file fingerprints will be sent without you clicking anything."),
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
        {tr("Проверка новых файлов", "Checking new files")}
      </div>
      {FILE_OPTIONS.map(({ key, title, description }) => (
        <div key={key} className="mt-4 flex items-center gap-4">
          <div className="min-w-0 flex-1">
            <div className="text-sm">{title}</div>
            <div className="mt-0.5 text-xs text-white/45">{description}</div>
            {key === "autoVirustotal" && settings?.autoVirustotal && !hasVtKey && (
              <div className="mt-1 text-xs text-amber-300">{tr("Ключ VirusTotal не добавлен, поэтому запросы не отправляются.", "No VirusTotal key has been added, so no requests are sent.")}</div>
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
    ? tr("Загрузка…", "Loading…")
    : status.installing
      ? tr(`Устанавливается версия ${status.available ?? ""}. DefenseR перезапустится сам.`, `Installing version ${status.available ?? ""}. DefenseR will restart on its own.`)
      : status.checking
        ? tr("Проверка…", "Checking…")
        : status.available
          ? tr(`Доступна версия ${status.available}`, `Version ${status.available} is available`)
          : status.checkedAt
            ? tr(`Установлена последняя версия · проверено ${formatTime(status.checkedAt)}`, `The latest version is installed · checked ${formatTime(status.checkedAt)}`)
            : tr("Обновления ещё не проверялись", "Updates have not been checked yet");
  const button = "flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm disabled:opacity-40";

  return (
    <Card className="mt-4 max-w-2xl p-5">
      <div className="flex items-center gap-2 text-sm font-medium">
        <RefreshCw size={16} className="text-emerald-400" />
        {tr("Обновления", "Updates")}
      </div>
      <div className="mt-3 flex items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm">DefenseR {status?.current}</div>
          <div className={`mt-0.5 text-xs ${status?.available ? "text-emerald-300" : "text-white/45"}`}>{state}</div>
        </div>
        {status?.available && !status.devBuild && (
          <button onClick={() => run("install_update")} disabled={busy} className={`${button} bg-emerald-400/15 text-emerald-200 hover:bg-emerald-400/25`}>
            {status.installing && <LoaderCircle size={14} className="animate-spin" />}
            {tr("Установить", "Install")}
          </button>
        )}
        <button onClick={() => run("check_update")} disabled={busy} className={`${button} bg-white/8 text-white/70 hover:bg-white/12`}>
          {status?.checking && <LoaderCircle size={14} className="animate-spin" />}
          {tr("Проверить", "Check")}
        </button>
      </div>
      {status?.available && status.notes && <p className="mt-3 whitespace-pre-line rounded-xl bg-black/20 px-3 py-2.5 text-xs text-white/60">{status.notes}</p>}
      {status?.devBuild && <p className="mt-3 text-xs text-white/45">{tr("Это сборка для разработки: она проверяет обновления, но не устанавливает их.", "This is a development build: it checks for updates but does not install them.")}</p>}

      <div className="mt-4 flex items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm">{tr("Устанавливать обновления автоматически", "Install updates automatically")}</div>
          <div className="mt-0.5 text-xs text-white/45">
            {tr("Новая версия ставится сама, когда окно свёрнуто в область уведомлений. Обновления берутся из выпусков проекта на GitHub и принимаются только с подписью разработчика.", "A new version installs itself when the window is minimised to the notification area. Updates come from the project's releases on GitHub and are accepted only with the developer's signature.")}
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
            {tr("Ключ сохранён", "Key saved")}
          </span>
          <button onClick={() => run(clearCommand)} className="rounded-lg bg-white/8 px-3 py-1.5 text-sm text-white/70 hover:bg-white/12">
            {tr("Удалить ключ", "Remove key")}
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
            {tr("Сохранить", "Save")}
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
      <PageHeader title={tr("Настройки", "Settings")} subtitle={tr("Ключи, работа в фоне и обновления", "Keys, running in the background and updates")} />

      <LanguageCard />
      <KeyCard
        title={tr("Ключ Anthropic API", "Anthropic API key")}
        description={tr("Ключ нужен, чтобы Claude объяснял инциденты простым языком. Он хранится в диспетчере учётных данных Windows, а не в файлах приложения. Получить ключ можно в консоли Anthropic; запросы оплачиваются с вашего аккаунта.", "The key lets Claude explain incidents in plain language. It is stored in Windows Credential Manager, not in the app's files. You can get a key in the Anthropic console; requests are billed to your account.")}
        placeholder="sk-ant-…"
        hasKey={hasKey}
        setCommand="set_api_key"
        clearCommand="clear_api_key"
        onChanged={onChanged}
      />
      <KeyCard
        className="mt-4"
        title={tr("Ключ VirusTotal", "VirusTotal key")}
        description={tr("С ключом можно узнать, что о файле думают десятки антивирусов: кнопка «Проверить на VirusTotal» есть в инцидентах и в результатах проверки файлов. Бесплатный ключ выдаётся в профиле на virustotal.com и даёт 4 проверки в минуту, 500 в день. Хранится там же, в диспетчере учётных данных Windows.", "With a key you can find out what dozens of antivirus engines think of a file: the “Check on VirusTotal” button is in incidents and in file scan results. A free key is issued in your profile on virustotal.com and allows 4 lookups a minute, 500 a day. It is stored in the same place, Windows Credential Manager.")}
        placeholder={tr("64 символа", "64 characters")}
        hasKey={vt?.hasKey ?? false}
        setCommand="set_vt_key"
        clearCommand="clear_vt_key"
        onChanged={() => setVtKey((key) => key + 1)}
      />

      <FilesCard hasVtKey={vt?.hasKey ?? false} />
      <BackgroundCard />
      <UpdatesCard />

      <Card className="mt-4 max-w-2xl p-5 text-sm text-white/55">
        <div className="font-medium text-white/85">{tr("Что покидает компьютер", "What leaves the computer")}</div>
        <p className="mt-2">
          {tr("В Anthropic — ничего, пока вы не нажмёте «Объяснить с помощью ИИ» в карточке инцидента. Тогда уходят заголовок, описание и детали именно этого инцидента: имена процессов, пути и команды. Путь к папке вашего профиля заменяется на %USERPROFILE%.", "To Anthropic — nothing, until you click “Explain with AI” on an incident card. Then the title, description and details of that one incident are sent: process names, paths and commands. The path to your profile folder is replaced with %USERPROFILE%.")}
        </p>
        <p className="mt-2">
          {tr("В VirusTotal — только SHA-256 файла (его цифровой отпечаток): по кнопке «Проверить на VirusTotal», а если вы включили автоматическую проверку — ещё и для файлов, которые модель сочла вредоносными. Сам файл, его имя и путь не отправляются.", "To VirusTotal — only the file's SHA-256 (its digital fingerprint): when you click “Check on VirusTotal” and, if you turned on automatic checking, also for files the model considered malicious. The file itself, its name and its path are not sent.")}
        </p>
        <p className="mt-2">{tr("Список процессов, сетевые соединения и остальные данные компьютер не покидают.", "The process list, network connections and all other data never leave the computer.")}</p>
      </Card>
    </>
  );
}
