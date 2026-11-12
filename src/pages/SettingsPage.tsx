import { useState } from "react";
import { CircleCheck, KeyRound } from "lucide-react";
import { Card, PageHeader } from "../components/ui";
import { call } from "../lib/api";

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
      <PageHeader title="Настройки" subtitle="Подключение ИИ-объяснений" />

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
