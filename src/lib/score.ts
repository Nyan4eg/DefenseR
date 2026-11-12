import type { AutostartEntry, ProcessInfo, ProtectionStatus } from "./api";

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

  const weighted: [number, Check][] = [
    [30, {
      id: "realtime",
      label: "Защита в реальном времени",
      detail: protection?.realtime == null ? "Нет данных от Microsoft Defender" : protection.realtime ? "Включена" : "Отключена",
      status: status(protection?.realtime),
    }],
    [15, {
      id: "antivirus",
      label: "Антивирус Microsoft Defender",
      detail: protection?.antivirus == null ? "Нет данных" : protection.antivirus ? "Работает" : "Не работает",
      status: status(protection?.antivirus),
    }],
    [20, {
      id: "firewall",
      label: "Брандмауэр Windows",
      detail: firewallOn == null ? "Нет данных" : firewallOn ? "Включён для всех профилей" : `Отключён: ${firewallOff.join(", ")}`,
      status: status(firewallOn),
    }],
    [10, {
      id: "signatures",
      label: "Антивирусные базы",
      detail: age == null ? "Нет данных" : age === 0 ? "Обновлены сегодня" : `Обновлены ${age} дн. назад`,
      status: status(age == null ? null : age <= SIGNATURE_MAX_AGE_DAYS),
    }],
    [5, {
      id: "tamper",
      label: "Защита от подделки",
      detail: protection?.tamper == null ? "Нет данных" : protection.tamper ? "Включена" : "Отключена",
      status: status(protection?.tamper),
    }],
    [10, {
      id: "autostart",
      label: "Автозагрузка",
      detail: flaggedAutostart == null ? "Нет данных" : flaggedAutostart === 0 ? "Подозрительных записей нет" : `Записей, требующих внимания: ${flaggedAutostart}`,
      status: status(flaggedAutostart == null ? null : flaggedAutostart === 0),
    }],
    [10, {
      id: "processes",
      label: "Запущенные процессы",
      detail: flaggedProcesses == null ? "Нет данных" : flaggedProcesses === 0 ? "Процессов из временных папок нет" : `Процессов из временных папок: ${flaggedProcesses}`,
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
