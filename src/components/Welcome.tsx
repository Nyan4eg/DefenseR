import { createPortal } from "react-dom";
import { GraduationCap, Hand, HardDrive, Radar, ShieldCheck, ShieldPlus, type LucideIcon } from "lucide-react";
import { IconTile } from "./kit";
import { call } from "../lib/api";
import { applyLang, lang, tr, type Lang } from "../lib/i18n";

function Point({ icon, tone = "accent", title, text }: { icon: LucideIcon; tone?: "accent" | "info" | "warn"; title: string; text: string }) {
  return (
    <div className="flex items-start gap-3.5">
      <IconTile icon={icon} tone={tone} size={36} />
      <div className="min-w-0">
        <div className="text-sm font-medium">{title}</div>
        <div className="mt-0.5 text-xs leading-relaxed text-white/55">{text}</div>
      </div>
    </div>
  );
}

/** Shown once, on the first start: what the program does, what it does not, and what to expect. */
export function Welcome({ onClose }: { onClose: () => void }) {
  const choose = async (next: Lang) => {
    if (next === lang) return;
    await call("set_language", { language: next }).catch(() => {});
    applyLang(next);
  };

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6 backdrop-blur-md">
      <div role="dialog" aria-modal="true" className="rise relative w-full max-w-xl overflow-hidden rounded-3xl border border-white/10 bg-[#101620] p-7 shadow-2xl">
        <div className="pointer-events-none absolute -right-16 -top-16 size-56 rounded-full bg-gradient-to-br from-emerald-400/25 to-transparent blur-3xl" />
        <div className="pointer-events-none absolute -bottom-20 -left-16 size-56 rounded-full bg-gradient-to-br from-cyan-400/15 to-transparent blur-3xl" />

        <div className="relative flex items-center gap-3">
          <div className="flex size-11 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-400 to-cyan-400 text-[#06281f]">
            <ShieldCheck size={24} strokeWidth={2.4} />
          </div>
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-semibold tracking-tight">{tr("Добро пожаловать в DefenseR", "Welcome to DefenseR")}</h1>
            <div className="text-xs text-white/45">{tr("Минута на то, чтобы понять, чего ждать", "A minute to know what to expect")}</div>
          </div>
          <div className="flex shrink-0 gap-1 rounded-xl border border-white/10 bg-white/5 p-1">
            {(["ru", "en"] as const).map((code) => (
              <button key={code} onClick={() => choose(code)} className={`rounded-lg px-2.5 py-1 text-xs transition-colors ${code === lang ? "bg-white/12 text-white" : "text-white/55 hover:text-white/85"}`}>
                {code === "ru" ? "Русский" : "English"}
              </button>
            ))}
          </div>
        </div>

        <div className="relative mt-6 flex flex-col gap-4">
          <Point
            icon={Radar}
            title={tr("Следит и объясняет", "Watches and explains")}
            text={tr(
              "За программами, сетью, автозагрузкой, расширениями браузеров и новыми файлами. Если что-то выглядит подозрительно, появляется инцидент: что случилось, почему это важно и что можно сделать.",
              "Programs, the network, startup, browser extensions and new files. When something looks suspicious, an incident appears: what happened, why it matters and what you can do.",
            )}
          />
          <Point
            icon={Hand}
            title={tr("Ничего не делает без вас", "Does nothing without you")}
            text={tr(
              "DefenseR сам ничего не удаляет и не блокирует. Любое действие — по вашей кнопке и с подтверждением, и почти всё можно вернуть на странице «Реакции».",
              "DefenseR deletes and blocks nothing on its own. Every action happens when you click and confirm, and nearly everything can be undone on the Responses page.",
            )}
          />
          <Point
            icon={ShieldPlus}
            tone="warn"
            title={tr("Не заменяет антивирус", "Does not replace an antivirus")}
            text={tr(
              "Это надстройка над Microsoft Defender, а не замена ему: Defender ловит известные угрозы, DefenseR показывает то, что тот не объясняет. Не выключайте Defender.",
              "It is a layer on top of Microsoft Defender, not a replacement: Defender catches known threats, DefenseR shows what Defender does not explain. Do not turn Defender off.",
            )}
          />
          <Point
            icon={HardDrive}
            tone="info"
            title={tr("Данные остаются на компьютере", "Your data stays on the computer")}
            text={tr(
              "Наружу ничего не уходит, пока вы сами не попросите: объяснение инцидента у Claude или проверку файла на VirusTotal. Для обоих нужен ваш ключ, оба выключены по умолчанию.",
              "Nothing leaves it until you ask: an incident explained by Claude, or a file looked up on VirusTotal. Both need a key of your own, and both are off by default.",
            )}
          />
          <Point
            icon={GraduationCap}
            title={tr("Первые два часа — знакомство", "The first two hours are for getting acquainted")}
            text={tr(
              "DefenseR запоминает, какие программы здесь обычно работают и выходят в сеть, а то, что уже стоит в автозагрузке и браузерах, принимает за известное. Сообщать о новом начнёт после этого.",
              "DefenseR learns which programs normally run and go online here, and takes what is already in startup and in the browsers as known. It starts reporting new things after that.",
            )}
          />
        </div>

        <div className="relative mt-7 flex items-center justify-between gap-4">
          <div className="text-xs text-white/35">{tr("Окно можно закрыть: DefenseR останется в области уведомлений.", "You can close the window: DefenseR stays in the notification area.")}</div>
          <button autoFocus onClick={onClose} className="shrink-0 rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-5 py-2 text-sm font-medium text-[#06281f] transition hover:brightness-110">
            {tr("Понятно, начнём", "Got it, let's start")}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
