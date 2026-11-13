import type { AutostartEntry, ProcessInfo, ProtectionStatus } from "./api";
import { tr } from "./i18n";

export type CheckStatus = "ok" | "warn" | "unknown";

export interface Check {
  id: string;
  label: string;
  detail: string;
  status: CheckStatus;
}

export interface Assessment {
  /** 0–100, or null while nothing could be evaluated yet. */
  score: number | null;
  checks: Check[];
}

const SIGNATURE_MAX_AGE_DAYS = 3;

function status(value: boolean | null | undefined): CheckStatus {
  if (value == null) return "unknown";
  return value ? "ok" : "warn";
}

/**
 * Simple weighted checklist. Checks with unknown status are left out of the score
 * instead of counting for or against it.
 */
export function assess(
  protection: ProtectionStatus | null,
  autostart: AutostartEntry[] | null,
  processes: ProcessInfo[] | null,
): Assessment {
  const firewallOn = protection?.firewall.length ? protection.firewall.every((p) => p.enabled) : null;
  const firewallOff = protection?.firewall.filter((p) => !p.enabled).map((p) => p.name) ?? [];
  const age = protection?.signatureAgeDays ?? null;
  const flaggedAutostart = autostart?.filter((e) => e.flags.length > 0).length ?? null;
  const flaggedProcesses = processes?.filter((p) => p.flags.length > 0).length ?? null;

  const noData = tr("Нет данных", "No data");

  const weighted: [number, Check][] = [
    [30, {
      id: "realtime",
      label: tr("Защита в реальном времени", "Real-time protection"),
      detail: protection?.realtime == null ? tr("Нет данных от Microsoft Defender", "No data from Microsoft Defender") : protection.realtime ? tr("Включена", "On") : tr("Отключена", "Off"),
      status: status(protection?.realtime),
    }],
    [15, {
      id: "antivirus",
      label: tr("Антивирус Microsoft Defender", "Microsoft Defender Antivirus"),
      detail: protection?.antivirus == null ? noData : protection.antivirus ? tr("Работает", "Running") : tr("Не работает", "Not running"),
      status: status(protection?.antivirus),
    }],
    [20, {
      id: "firewall",
      label: tr("Брандмауэр Windows", "Windows Firewall"),
      detail: firewallOn == null ? noData : firewallOn ? tr("Включён для всех профилей", "On for all profiles") : tr(`Отключён: ${firewallOff.join(", ")}`, `Off: ${firewallOff.join(", ")}`),
      status: status(firewallOn),
    }],
    [10, {
      id: "signatures",
      label: tr("Антивирусные базы", "Virus definitions"),
      detail: age == null ? noData : age === 0 ? tr("Обновлены сегодня", "Updated today") : tr(`Обновлены ${age} дн. назад`, `Updated ${age} ${age === 1 ? "day" : "days"} ago`),
      status: status(age == null ? null : age <= SIGNATURE_MAX_AGE_DAYS),
    }],
    [5, {
      id: "tamper",
      label: tr("Защита от подделки", "Tamper protection"),
      detail: protection?.tamper == null ? noData : protection.tamper ? tr("Включена", "On") : tr("Отключена", "Off"),
      status: status(protection?.tamper),
    }],
    [10, {
      id: "autostart",
      label: tr("Автозагрузка", "Startup"),
      detail: flaggedAutostart == null ? noData : flaggedAutostart === 0 ? tr("Подозрительных записей нет", "No suspicious entries") : tr(`Записей, требующих внимания: ${flaggedAutostart}`, `Entries that need attention: ${flaggedAutostart}`),
      status: status(flaggedAutostart == null ? null : flaggedAutostart === 0),
    }],
    [10, {
      id: "processes",
      label: tr("Запущенные процессы", "Running processes"),
      detail: flaggedProcesses == null ? noData : flaggedProcesses === 0 ? tr("Процессов из временных папок нет", "No processes from temp folders") : tr(`Процессов из временных папок: ${flaggedProcesses}`, `Processes from temp folders: ${flaggedProcesses}`),
      status: status(flaggedProcesses == null ? null : flaggedProcesses === 0),
    }],
  ];

  let total = 0;
  let earned = 0;
  for (const [weight, check] of weighted) {
    if (check.status === "unknown") continue;
    total += weight;
    if (check.status === "ok") earned += weight;
  }

  return {
    score: total === 0 ? null : Math.round((earned / total) * 100),
    checks: weighted.map(([, check]) => check),
  };
}
