import { useState } from "react";
import { ArrowRight, Ban, ChevronDown, Route, Waypoints } from "lucide-react";
import { Chip, IconTile } from "./kit";
import type { NetConfig } from "../lib/api";
import { tr } from "../lib/i18n";

/** The settings that decide where traffic goes: the system proxy and the hosts file. */
export function NetConfigCard({ config }: { config: NetConfig | null }) {
  const [open, setOpen] = useState(false);
  if (!config) return null;

  const redirects = config.hosts.filter((entry) => !entry.blocks);
  const blocks = config.hosts.filter((entry) => entry.blocks);
  const proxied = config.proxyEnabled && !!config.proxyServer;
  const attention = proxied || !!config.proxyScript || redirects.length > 0;
  const label = "mb-1 text-white/40";

  return (
    <div className={`mb-3 rounded-2xl border bg-white/[0.04] transition-colors ${attention ? "border-amber-400/20" : "border-white/8"}`}>
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-4 py-2.5 text-left">
        <IconTile icon={Route} tone={attention ? "warn" : "accent"} size={32} />
        <div className="min-w-0 flex-1">
          <div className="text-sm">{tr("Куда идёт трафик", "Where traffic goes")}</div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            {proxied ? (
              <Chip icon={Waypoints} tone="warn" title={tr("Запросы браузеров и программ идут через этот сервер", "Requests from browsers and programs go through this server")}>
                {tr(`Прокси: ${config.proxyServer}`, `Proxy: ${config.proxyServer}`)}
              </Chip>
            ) : (
              <Chip icon={Waypoints} tone="accent">
                {tr("Прокси выключен", "Proxy is off")}
              </Chip>
            )}
            {config.proxyScript && (
              <Chip icon={Waypoints} tone="warn">
                {tr("Сценарий настройки прокси", "Proxy setup script")}
              </Chip>
            )}
            {!config.hostsReadable ? (
              <Chip>{tr("Файл hosts прочитать не удалось", "The hosts file could not be read")}</Chip>
            ) : redirects.length > 0 ? (
              <Chip icon={ArrowRight} tone="warn" title={tr("Имена сайтов, которые файл hosts отправляет на другой адрес", "Site names the hosts file sends to another address")}>
                {tr(`hosts перенаправляет: ${redirects.length}`, `hosts redirects: ${redirects.length}`)}
              </Chip>
            ) : (
              <Chip icon={ArrowRight} tone="accent">
                {tr("hosts ничего не перенаправляет", "hosts redirects nothing")}
              </Chip>
            )}
            {blocks.length > 0 && (
              <Chip icon={Ban} title={tr("Имена сайтов, которые файл hosts отправляет в никуда — так блокируют рекламу и слежку", "Site names the hosts file sends nowhere — this is how ads and tracking are blocked")}>
                {tr(`hosts блокирует: ${blocks.length}`, `hosts blocks: ${blocks.length}`)}
              </Chip>
            )}
          </div>
        </div>
        <ChevronDown size={16} className={`shrink-0 text-white/30 transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="rise mx-4 mb-4 flex flex-col gap-3 rounded-xl border border-white/8 bg-black/20 px-4 py-3 text-xs">
          <div>
            <div className={label}>{tr("Системный прокси", "System proxy")}</div>
            <div className="leading-relaxed text-white/70">
              {proxied
                ? tr(
                    "Включён: запросы браузеров и программ идут через сервер ниже. Так работают VPN-клиенты и рабочие сети; если вы его не настраивали — отключите в «Параметры Windows → Сеть и Интернет → Прокси-сервер».",
                    "On: requests from browsers and programs go through the server below. VPN clients and work networks do this; if you did not set it up, turn it off in Windows Settings → Network & internet → Proxy.",
                  )
                : tr("Выключен: программы обращаются к сайтам напрямую.", "Off: programs reach sites directly.")}
            </div>
            {config.proxyServer && (
              <div className="mt-1.5 select-text font-mono text-white/80">
                {config.proxyServer}
                {!config.proxyEnabled && <span className="ml-2 font-sans text-white/35">{tr("(записан, но выключен)", "(stored, but turned off)")}</span>}
              </div>
            )}
            {config.proxyScript && (
              <div className="mt-1.5 select-text break-all font-mono text-white/80">
                <span className="mr-2 font-sans text-white/40">{tr("Сценарий:", "Script:")}</span>
                {config.proxyScript}
              </div>
            )}
          </div>

          <div>
            <div className={label}>{tr("Файл hosts", "The hosts file")}</div>
            <div className="leading-relaxed text-white/70">
              {tr(
                "Говорит Windows, по какому адресу искать сайт, и имеет приоритет над интернетом. Запись может незаметно отправить вас на поддельную копию сайта, поэтому о новых перенаправлениях DefenseR сообщает.",
                "Tells Windows which address to look for a site at, and takes priority over the internet. An entry can quietly send you to a fake copy of a site, so DefenseR reports new redirects.",
              )}
            </div>
            {redirects.length > 0 && (
              <div className="mt-2 flex flex-col gap-1">
                {redirects.slice(0, 20).map((entry) => (
                  <div key={`${entry.address}|${entry.name}`} className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-3 py-1.5 font-mono">
                    <span className="min-w-0 select-text truncate text-white/80">{entry.name}</span>
                    <ArrowRight size={12} className="shrink-0 text-amber-300" />
                    <span className="shrink-0 select-text text-white/60">{entry.address}</span>
                  </div>
                ))}
                {redirects.length > 20 && <div className="px-3 text-white/35">{tr(`…и ещё ${redirects.length - 20}`, `…and ${redirects.length - 20} more`)}</div>}
              </div>
            )}
            {blocks.length > 0 && (
              <div className="mt-2 text-white/45">
                {tr(`Заблокировано имён: ${blocks.length}`, `Names blocked: ${blocks.length}`)}
                <span className="ml-2 font-mono text-white/35">
                  {blocks
                    .slice(0, 4)
                    .map((entry) => entry.name)
                    .join(", ")}
                  {blocks.length > 4 ? "…" : ""}
                </span>
              </div>
            )}
            <div className="mt-2 select-text font-mono text-white/30">{config.hostsPath}</div>
          </div>
        </div>
      )}
    </div>
  );
}
