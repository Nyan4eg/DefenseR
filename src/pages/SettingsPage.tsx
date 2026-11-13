import { useEffect, useState, type ReactNode } from "react";
import {
  Bell,
  CircleCheck,
  Clock,
  Download,
  FileSearch,
  Fingerprint,
  HardDrive,
  KeyRound,
  Languages,
  LoaderCircle,
  Lock,
  MonitorCog,
  Power,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Usb,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { Chip, IconTile, Switch } from "../components/kit";
import { applyLang, lang, tr, type Lang } from "../lib/i18n";
import { Card, PageHeader } from "../components/ui";
import { call, formatTime, inTauri, usePolling, type AiStatus, type AppSettings, type UpdateStatus } from "../lib/api";

type Tone = "accent" | "info" | "warn" | "neutral";

/** A card of the page: an icon, a title, a sentence about what it is for, and its rows. */
function Section({ id, icon, title, text, tone = "accent", aside, children }: { id?: string; icon: LucideIcon; title: string; text?: string; tone?: Tone; aside?: ReactNode; children?: ReactNode }) {
  return (
    <Card className="scroll-mt-4 p-5">
      <div id={id} className="flex items-start gap-3.5">
        <IconTile icon={icon} tone={tone} size={38} />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">{title}</div>
          {text && <p className="mt-0.5 text-xs leading-relaxed text-white/50">{text}</p>}
        </div>
        {aside}
      </div>
      {children}
    </Card>
  );
}

/** One setting: what it is, what it does, and its switch. */
function Row({ icon: Icon, title, text, note, children }: { icon: LucideIcon; title: string; text: string; note?: ReactNode; children: ReactNode }) {
  return (
    <div className="mt-4 flex items-center gap-3.5 border-t border-white/6 pt-4">
      <div className="flex w-[38px] shrink-0 justify-center">
        <Icon size={17} className="text-white/40" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-sm">{title}</div>
        <div className="mt-0.5 text-xs leading-relaxed text-white/45">{text}</div>
        {note}
      </div>
      {children}
    </div>
  );
}

function ErrorLine({ error }: { error: string | null | undefined }) {
  return error ? <div className="mt-3 rounded-lg border border-rose-400/25 bg-rose-400/10 px-3 py-2 text-xs text-rose-200">{error}</div> : null;
}

interface Shared {
  settings: AppSettings | null;
  /** Applies a change the backend has accepted. */
  patch: (change: Partial<AppSettings>) => void;
}

/** Start with Windows and incident notifications. */
function BackgroundCard({ settings, patch }: Shared) {
  const [autostart, setAutostart] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
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
      patch({ notifications: enabled });
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <Section
      icon={MonitorCog}
      title={tr("Работа в фоне", "Running in the background")}
      text={tr(
        "Когда вы закрываете окно, DefenseR остаётся в области уведомлений и продолжает следить за компьютером. Полностью выйти можно через значок там же.",
        "When you close the window, DefenseR stays in the notification area and keeps watching the computer. To quit completely, use its icon there.",
      )}
    >
      <Row
        icon={Power}
        title={tr("Запускать вместе с Windows", "Start with Windows")}
        text={
          settings?.devBuild
            ? tr("Недоступно в сборке для разработки: установите DefenseR через установщик.", "Not available in a development build: install DefenseR with the installer.")
            : tr("DefenseR будет стартовать при входе в систему, сразу свёрнутым в область уведомлений.", "DefenseR will start when you sign in, minimised to the notification area straight away.")
        }
      >
        <Switch checked={autostart} disabled={!settings || settings.devBuild} onChange={changeAutostart} label={tr("Запускать вместе с Windows", "Start with Windows")} />
      </Row>
      <Row
        icon={Bell}
        title={tr("Уведомления о новых инцидентах", "Notifications about new incidents")}
        text={tr("Только средней и высокой важности. Инциденты низкой важности видны в окне.", "Medium and high severity only. Low-severity incidents are shown in the window.")}
      >
        <Switch checked={settings?.notifications ?? false} disabled={!settings} onChange={changeNotifications} label={tr("Уведомления о новых инцидентах", "Notifications about new incidents")} />
      </Row>
      <ErrorLine error={error} />
    </Section>
  );
}

type FileOption = "watchDownloads" | "watchTemp" | "watchRemovable" | "autoVirustotal";

const FILE_OPTIONS: { key: FileOption; icon: LucideIcon; title: string; description: string }[] = [
  {
    key: "watchDownloads",
    icon: Download,
    title: tr("«Загрузки» и рабочий стол", "Downloads and the desktop"),
    description: tr("Программы, которые появляются в этих папках, сразу оцениваются моделью и проверяются на подпись. Скрипты и ярлыки читаются на опасные команды, а в архивы ZIP DefenseR заглядывает, не распаковывая их на диск.", "Programs that appear in these folders are scored by the model and checked for a signature straight away. Scripts and shortcuts are read for dangerous commands, and DefenseR looks into ZIP archives without unpacking them to disk."),
  },
  {
    key: "watchTemp",
    icon: Clock,
    title: tr("Временная папка", "Temp folder"),
    description: tr("Сюда распаковываются установщики и сюда же часто кладут свои файлы вредоносные программы. Об этой папке сообщается только при уверенной оценке модели или нарушенной подписи.", "Installers unpack here, and malware often puts its files here too. This folder is only reported when the model is confident or a signature is broken."),
  },
  {
    key: "watchRemovable",
    icon: Usb,
    title: tr("Флешки и другие съёмные диски", "USB sticks and other removable drives"),
    description: tr("При подключении диска проверяются все программы на нём, затем — новые.", "When a drive is connected, all programs on it are checked, and then any new ones."),
  },
  {
    key: "autoVirustotal",
    icon: Zap,
    title: tr("Спрашивать VirusTotal автоматически", "Ask VirusTotal automatically"),
    description: tr("Когда модель считает файл вредоносным, DefenseR сам отправит его SHA-256 в VirusTotal и поднимет важность инцидента, если антивирусы согласны. Нужен ключ VirusTotal. Выключено, пока вы не включите: отпечатки файлов будут уходить без вашего нажатия.", "When the model considers a file malicious, DefenseR will send its SHA-256 to VirusTotal on its own and raise the incident's severity if antivirus engines agree. Requires a VirusTotal key. Off until you turn it on: file fingerprints will be sent without you clicking anything."),
  },
];

const WATCH_KEYS = ["watchDownloads", "watchTemp", "watchRemovable"] as const;

/** Which places are watched for new programs, and whether VirusTotal is asked on its own. */
function FilesCard({ settings, patch, hasVtKey }: Shared & { hasVtKey: boolean }) {
  const [error, setError] = useState<string | null>(null);

  const change = async (key: FileOption, enabled: boolean) => {
    setError(null);
    try {
      await (key === "watchDownloads" ? call("set_watch_downloads", { enabled }) : call("set_option", { name: key, enabled }));
      patch({ [key]: enabled });
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <Section
      id="settings-files"
      icon={FileSearch}
      title={tr("Проверка новых файлов", "Checking new files")}
      text={tr("Где DefenseR сам проверяет файлы, как только они появляются. Ничего нажимать не нужно.", "Where DefenseR checks files on its own as soon as they appear. You do not need to click anything.")}
    >
      {FILE_OPTIONS.map(({ key, icon, title, description }) => (
        <Row
          key={key}
          icon={icon}
          title={title}
          text={description}
          note={
            key === "autoVirustotal" && settings?.autoVirustotal && !hasVtKey ? (
              <div className="mt-1 text-xs text-amber-300">{tr("Ключ VirusTotal не добавлен, поэтому запросы не отправляются.", "No VirusTotal key has been added, so no requests are sent.")}</div>
            ) : undefined
          }
        >
          <Switch checked={settings?.[key] ?? false} disabled={!settings} onChange={(enabled) => change(key, enabled)} label={title} />
        </Row>
      ))}
      <ErrorLine error={error} />
    </Section>
  );
}

/** The installed version, checking for a newer one and installing it. */
function UpdatesCard({ settings, patch }: Shared) {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = () => call<UpdateStatus>("get_update_status").then(setStatus).catch((e) => setError(String(e)));
    load();
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
      patch({ autoUpdate: enabled });
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
  const button = "relative flex shrink-0 items-center gap-1.5 overflow-hidden rounded-lg px-3 py-1.5 text-sm disabled:opacity-40";

  return (
    <Section
      id="settings-updates"
      icon={RefreshCw}
      tone={status?.available ? "info" : "accent"}
      title={`DefenseR ${status?.current ?? ""}`}
      text={state}
      aside={
        <div className="flex shrink-0 gap-2">
          {status?.available && !status.devBuild && (
            <button onClick={() => run("install_update")} disabled={busy} className={`${button} bg-emerald-400/15 text-emerald-200 hover:bg-emerald-400/25`}>
              {status.installing && <span className="shimmer pointer-events-none absolute inset-0" />}
              {status.installing ? <LoaderCircle size={14} className="animate-spin" /> : <Download size={14} />}
              {tr("Установить", "Install")}
            </button>
          )}
          <button onClick={() => run("check_update")} disabled={busy} className={`${button} bg-white/8 text-white/70 hover:bg-white/12`}>
            {status?.checking ? <LoaderCircle size={14} className="animate-spin" /> : <RefreshCw size={14} />}
            {tr("Проверить", "Check")}
          </button>
        </div>
      }
    >
      {status?.available && status.notes && <p className="mt-3 whitespace-pre-line rounded-xl bg-black/20 px-3 py-2.5 text-xs text-white/60">{status.notes}</p>}
      {status?.devBuild && <p className="mt-3 text-xs text-white/45">{tr("Это сборка для разработки: она проверяет обновления, но не устанавливает их.", "This is a development build: it checks for updates but does not install them.")}</p>}

      <Row
        icon={Download}
        title={tr("Устанавливать обновления автоматически", "Install updates automatically")}
        text={tr("Новая версия ставится сама, когда окно свёрнуто в область уведомлений. Обновления берутся из выпусков проекта на GitHub и принимаются только с подписью разработчика.", "A new version installs itself when the window is minimised to the notification area. Updates come from the project's releases on GitHub and are accepted only with the developer's signature.")}
      >
        <Switch checked={settings?.autoUpdate ?? false} disabled={!settings} onChange={changeAutomatic} label={tr("Устанавливать обновления автоматически", "Install updates automatically")} />
      </Row>
      <ErrorLine error={error ?? status?.error} />
    </Section>
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
    <Section
      icon={Languages}
      tone="info"
      title="Язык · Language"
      aside={
        <div className="flex shrink-0 gap-1 self-center rounded-xl border border-white/10 bg-white/5 p-1">
          {(["ru", "en"] as const).map((code) => (
            <button
              key={code}
              onClick={() => choose(code)}
              className={`rounded-lg px-3 py-1 text-sm transition-colors ${code === lang ? "bg-white/12 text-white" : "text-white/55 hover:text-white/85"}`}
            >
              {code === "ru" ? "Русский" : "English"}
            </button>
          ))}
        </div>
      }
    />
  );
}

interface KeyCardProps {
  id: string;
  icon: LucideIcon;
  title: string;
  description: string;
  placeholder: string;
  hasKey: boolean;
  setCommand: string;
  clearCommand: string;
  onChanged: () => void;
}

/** Entering and removing an API key. The key itself is never shown again. */
function KeyCard({ id, icon, title, description, placeholder, hasKey, setCommand, clearCommand, onChanged }: KeyCardProps) {
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
    <Section
      id={id}
      icon={icon}
      tone={hasKey ? "accent" : "neutral"}
      title={title}
      text={description}
      aside={
        hasKey ? (
          <Chip icon={CircleCheck} tone="accent">
            {tr("Ключ сохранён", "Key saved")}
          </Chip>
        ) : (
          <Chip>{tr("Не добавлен", "Not added")}</Chip>
        )
      }
    >
      {hasKey ? (
        <div className="mt-4 flex items-center gap-3 border-t border-white/6 pt-4">
          <Lock size={15} className="shrink-0 text-white/35" />
          <span className="min-w-0 flex-1 text-xs text-white/45">{tr("Хранится в диспетчере учётных данных Windows. Показать его снова нельзя — только удалить и ввести заново.", "Kept in Windows Credential Manager. It cannot be shown again — only removed and entered anew.")}</span>
          <button onClick={() => run(clearCommand)} className="shrink-0 rounded-lg bg-white/8 px-3 py-1.5 text-sm text-white/70 hover:bg-rose-400/15 hover:text-rose-200">
            {tr("Удалить ключ", "Remove key")}
          </button>
        </div>
      ) : (
        <form
          className="mt-4 flex gap-2 border-t border-white/6 pt-4"
          onSubmit={(e) => {
            e.preventDefault();
            run(setCommand, { key });
          }}
        >
          <label className="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 focus-within:border-emerald-400/50">
            <KeyRound size={14} className="shrink-0 text-white/35" />
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={placeholder}
              autoComplete="off"
              className="min-w-0 flex-1 bg-transparent font-mono text-sm outline-none placeholder:text-white/30"
            />
          </label>
          <button type="submit" disabled={!key.trim()} className="rounded-lg bg-emerald-400/15 px-4 py-1.5 text-sm text-emerald-200 hover:bg-emerald-400/25 disabled:opacity-40">
            {tr("Сохранить", "Save")}
          </button>
        </form>
      )}
      <ErrorLine error={error} />
    </Section>
  );
}

/** A glance at one area of the settings; a click scrolls to it. */
function StatusTile({ icon: Icon, label, state, tone, target }: { icon: LucideIcon; label: string; state: string; tone: Tone; target: string }) {
  const colour = { accent: "text-emerald-300", info: "text-cyan-300", warn: "text-amber-300", neutral: "text-white/45" }[tone];
  const glow = { accent: "from-emerald-400/25", info: "from-cyan-400/25", warn: "from-amber-400/25", neutral: "from-white/10" }[tone];
  return (
    <button
      onClick={() => document.getElementById(target)?.scrollIntoView({ behavior: "smooth", block: "start" })}
      className="group relative min-w-0 flex-1 overflow-hidden rounded-2xl border border-white/8 bg-white/[0.04] px-4 py-3 text-left transition duration-200 hover:-translate-y-0.5 hover:border-white/15 hover:bg-white/[0.06]"
    >
      <div className={`pointer-events-none absolute -right-6 -top-6 size-20 rounded-full bg-gradient-to-br ${glow} to-transparent opacity-60 blur-xl transition-opacity group-hover:opacity-100`} />
      <div className="flex items-center gap-2 text-xs text-white/50">
        <Icon size={14} className={colour} />
        <span className="truncate">{label}</span>
      </div>
      <div className={`mt-1.5 truncate text-sm font-medium ${tone === "neutral" ? "text-white/60" : "text-white/90"}`}>{state}</div>
    </button>
  );
}

function Heading({ children }: { children: ReactNode }) {
  return <div className="mb-2 mt-6 px-1 text-xs font-medium uppercase tracking-wider text-white/35">{children}</div>;
}

/** One destination in the "what leaves the computer" card. */
function Leaves({ icon, tone, where, when, children }: { icon: LucideIcon; tone: Tone; where: string; when: string; children: ReactNode }) {
  return (
    <div className="mt-4 flex items-start gap-3.5 border-t border-white/6 pt-4">
      <IconTile icon={icon} tone={tone} size={32} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm">{where}</span>
          <Chip tone={tone}>{when}</Chip>
        </div>
        <p className="mt-1 text-xs leading-relaxed text-white/50">{children}</p>
      </div>
    </div>
  );
}

export function SettingsPage({ hasKey, onChanged }: { hasKey: boolean; onChanged: () => void }) {
  const [vtKey, setVtKey] = useState(0);
  const vt = usePolling<AiStatus>("get_vt_status", 60_000, vtKey);
  const hasVtKey = vt?.hasKey ?? false;

  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    call<AppSettings>("get_settings").then(setSettings).catch((e) => setError(String(e)));
  }, []);
  const patch = (change: Partial<AppSettings>) => setSettings((prev) => prev && { ...prev, ...change });

  const watched = settings ? WATCH_KEYS.filter((key) => settings[key]).length : 0;

  return (
    <div className="max-w-3xl">
      <PageHeader title={tr("Настройки", "Settings")} subtitle={tr("Что DefenseR проверяет сам, какие помощники подключены и что уходит с компьютера", "What DefenseR checks on its own, which helpers are connected and what leaves the computer")} />

      <div className="flex gap-3">
        <StatusTile
          icon={Sparkles}
          label={tr("Объяснения Claude", "Claude explanations")}
          state={hasKey ? tr("Подключены", "Connected") : tr("Нужен ключ", "Key needed")}
          tone={hasKey ? "accent" : "neutral"}
          target="settings-claude"
        />
        <StatusTile
          icon={Fingerprint}
          label="VirusTotal"
          state={!hasVtKey ? tr("Нужен ключ", "Key needed") : settings?.autoVirustotal ? tr("Сам, без нажатия", "On its own") : tr("По кнопке", "On request")}
          tone={hasVtKey ? "accent" : "neutral"}
          target="settings-virustotal"
        />
        <StatusTile
          icon={FileSearch}
          label={tr("Новые файлы", "New files")}
          state={!settings ? "…" : watched === 0 ? tr("Не проверяются", "Not checked") : tr(`Мест: ${watched} из 3`, `${watched} of 3 places`)}
          tone={watched === 0 ? "warn" : "accent"}
          target="settings-files"
        />
        <StatusTile
          icon={RefreshCw}
          label={tr("Обновления", "Updates")}
          state={!settings ? "…" : settings.autoUpdate ? tr("Ставятся сами", "Install themselves") : tr("Вручную", "Manual")}
          tone={settings?.autoUpdate ? "accent" : "neutral"}
          target="settings-updates"
        />
      </div>
      <ErrorLine error={error} />

      <Heading>{tr("Защита", "Protection")}</Heading>
      <FilesCard settings={settings} patch={patch} hasVtKey={hasVtKey} />

      <Heading>{tr("Помощники", "Helpers")}</Heading>
      <div className="flex flex-col gap-3">
        <KeyCard
          id="settings-claude"
          icon={Sparkles}
          title={tr("Claude объясняет инциденты", "Claude explains incidents")}
          description={tr("С ключом Anthropic API Claude расскажет простым языком, что произошло и что делать. Получить ключ можно в консоли Anthropic; запросы оплачиваются с вашего аккаунта.", "With an Anthropic API key, Claude tells you in plain language what happened and what to do. You can get a key in the Anthropic console; requests are billed to your account.")}
          placeholder="sk-ant-…"
          hasKey={hasKey}
          setCommand="set_api_key"
          clearCommand="clear_api_key"
          onChanged={onChanged}
        />
        <KeyCard
          id="settings-virustotal"
          icon={Fingerprint}
          title={tr("VirusTotal: мнение десятков антивирусов", "VirusTotal: what dozens of antivirus engines think")}
          description={tr("Кнопка «Проверить на VirusTotal» есть в инцидентах и в результатах проверки файлов. Бесплатный ключ выдаётся в профиле на virustotal.com и даёт 4 проверки в минуту, 500 в день.", "The “Check on VirusTotal” button is in incidents and in file scan results. A free key is issued in your profile on virustotal.com and allows 4 lookups a minute, 500 a day.")}
          placeholder={tr("64 символа", "64 characters")}
          hasKey={hasVtKey}
          setCommand="set_vt_key"
          clearCommand="clear_vt_key"
          onChanged={() => setVtKey((key) => key + 1)}
        />
      </div>

      <Heading>{tr("Приложение", "Application")}</Heading>
      <div className="flex flex-col gap-3">
        <BackgroundCard settings={settings} patch={patch} />
        <UpdatesCard settings={settings} patch={patch} />
        <LanguageCard />
      </div>

      <Heading>{tr("Приватность", "Privacy")}</Heading>
      <Section icon={ShieldCheck} title={tr("Что покидает компьютер", "What leaves the computer")} text={tr("Коротко: ничего, пока вы сами об этом не попросите.", "In short: nothing, until you ask for it yourself.")}>
        <Leaves icon={Sparkles} tone="info" where="Anthropic" when={tr("только по кнопке", "only when you click")}>
          {tr("Ничего, пока вы не нажмёте «Объяснить с помощью ИИ» в карточке инцидента. Тогда уходят заголовок, описание и детали именно этого инцидента: имена процессов, пути и команды. Путь к папке вашего профиля заменяется на %USERPROFILE%.", "Nothing, until you click “Explain with AI” on an incident card. Then the title, description and details of that one incident are sent: process names, paths and commands. The path to your profile folder is replaced with %USERPROFILE%.")}
        </Leaves>
        <Leaves icon={Fingerprint} tone={settings?.autoVirustotal ? "warn" : "info"} where="VirusTotal" when={settings?.autoVirustotal ? tr("по кнопке и автоматически", "on click and automatically") : tr("только по кнопке", "only when you click")}>
          {tr("Только SHA-256 файла (его цифровой отпечаток): по кнопке «Проверить на VirusTotal», а если вы включили автоматическую проверку — ещё и для файлов, которые модель сочла вредоносными. Сам файл, его имя и путь не отправляются.", "Only the file's SHA-256 (its digital fingerprint): when you click “Check on VirusTotal” and, if you turned on automatic checking, also for files the model considered malicious. The file itself, its name and its path are not sent.")}
        </Leaves>
        <Leaves icon={HardDrive} tone="accent" where={tr("Всё остальное", "Everything else")} when={tr("остаётся здесь", "stays here")}>
          {tr("Список процессов, сетевые соединения и остальные данные компьютер не покидают.", "The process list, network connections and all other data never leave the computer.")}
        </Leaves>
      </Section>
    </div>
  );
}
