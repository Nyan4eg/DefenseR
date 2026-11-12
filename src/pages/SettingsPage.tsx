import { useEffect, useState } from "react";
import { CircleCheck, KeyRound, LoaderCircle, MonitorCog, RefreshCw } from "lucide-react";
import { Card, PageHeader } from "../components/ui";
import { call, formatTime, inTauri, type AppSettings, type UpdateStatus } from "../lib/api";

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

  const changeDownloads = async (enabled: boolean) => {
    setError(null);
    try {
      await call("set_watch_downloads", { enabled });
      setSettings((prev) => prev && { ...prev, watchDownloads: enabled });
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

      <div className="mt-4 flex items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm">Проверять новые файлы в «Загрузках»</div>
          <div className="mt-0.5 text-xs text-white/45">
            Программы, которые появляются в папке загрузок, сразу оцениваются моделью и проверяются на подпись. Архивы не распаковываются.
          </div>
        </div>
        <Toggle checked={settings?.watchDownloads ?? false} disabled={!settings} onChange={changeDownloads} />
      </div>
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

export function SettingsPage({ hasKey, onChanged }: { hasKey: boolean; onChanged: () => void }) {
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
    <>
      <PageHeader title="Настройки" subtitle="ИИ-объяснения, работа в фоне и обновления" />

      <Card className="max-w-2xl p-5">
        <div className="flex items-center gap-2 text-sm font-medium">
          <KeyRound size={16} className="text-emerald-400" />
          Ключ Anthropic API
        </div>
        <p className="mt-2 text-sm text-white/55">
          Ключ нужен, чтобы Claude объяснял инциденты простым языком. Он хранится в диспетчере учётных данных Windows, а не в файлах
          приложения. Получить ключ можно в консоли Anthropic; запросы оплачиваются с вашего аккаунта.
        </p>

        {hasKey ? (
          <div className="mt-4 flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-sm text-emerald-300">
              <CircleCheck size={16} />
              Ключ сохранён
            </span>
            <button onClick={() => run("clear_api_key")} className="rounded-lg bg-white/8 px-3 py-1.5 text-sm text-white/70 hover:bg-white/12">
              Удалить ключ
            </button>
          </div>
        ) : (
          <form
            className="mt-4 flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              run("set_api_key", { key });
            }}
          >
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="sk-ant-…"
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

      <BackgroundCard />
      <UpdatesCard />

      <Card className="mt-4 max-w-2xl p-5 text-sm text-white/55">
        <div className="font-medium text-white/85">Что отправляется в Anthropic</div>
        <p className="mt-2">
          Ничего, пока вы не нажмёте «Объяснить с помощью ИИ» в карточке инцидента. Тогда уходят заголовок, описание и детали именно этого
          инцидента: имена процессов, пути и команды. Путь к папке вашего профиля заменяется на %USERPROFILE%. Список процессов, сетевые
          соединения и остальные данные компьютер не покидают.
        </p>
      </Card>
    </>
  );
}
