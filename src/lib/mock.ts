// Sample data for working on the UI in a plain browser. Never used inside the Tauri app.
import type { AutostartEntry, Connection, Incident, ModelInfo, Overview, ProcessInfo, ProtectionStatus, ResponsesState, ScanResult } from "./api";

const GB = 1024 ** 3;
const MB = 1024 ** 2;

const processNames = ["chrome.exe", "Code.exe", "explorer.exe", "svchost.exe", "Telegram.exe", "MsMpEng.exe", "steam.exe", "node.exe"];

function overview(): Overview {
  return {
    hostName: "DEMO-PC",
    osVersion: "Windows 11 Pro (демо-данные)",
    uptimeSecs: 93_784,
    cpuUsage: 12 + Math.random() * 25,
    memoryUsed: (11 + Math.random()) * GB,
    memoryTotal: 32 * GB,
  };
}

function processes(): ProcessInfo[] {
  const list: ProcessInfo[] = processNames.map((name, i) => ({
    pid: 1000 + i * 412,
    parentPid: 4,
    name,
    exe: `C:\\Program Files\\${name.replace(".exe", "")}\\${name}`,
    cpu: Math.random() * 6,
    memory: (80 + Math.random() * 900) * MB,
    flags: [],
  }));
  list.push({
    pid: 9120,
    parentPid: 1000,
    name: "setup_tmp.exe",
    exe: "C:\\Users\\demo\\AppData\\Local\\Temp\\7zS41A\\setup_tmp.exe",
    cpu: 1.4,
    memory: 42 * MB,
    flags: ["temp-path"],
  });
  return list;
}

const connections: Connection[] = [
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51422, remoteAddr: "142.250.74.14", remotePort: 443, state: "ESTABLISHED", pid: 1000, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51437, remoteAddr: "149.154.167.51", remotePort: 443, state: "ESTABLISHED", pid: 2648, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "127.0.0.1", localPort: 1420, remoteAddr: "0.0.0.0", remotePort: 0, state: "LISTEN", pid: 3884, remoteIsPublic: false },
  { protocol: "TCP", localAddr: "0.0.0.0", localPort: 135, remoteAddr: "0.0.0.0", remotePort: 0, state: "LISTEN", pid: 2236, remoteIsPublic: false },
  { protocol: "UDP", localAddr: "0.0.0.0", localPort: 5353, remoteAddr: null, remotePort: null, state: null, pid: 1000, remoteIsPublic: false },
];

const autostart: AutostartEntry[] = [
  { name: "SecurityHealth", command: "%windir%\\system32\\SecurityHealthSystray.exe", source: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", scope: "machine", flags: [] },
  { name: "Steam", command: '"C:\\Program Files (x86)\\Steam\\steam.exe" -silent', source: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", scope: "user", flags: [] },
  { name: "OldUpdater", command: '"C:\\Program Files\\OldApp\\updater.exe"', source: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", scope: "user", flags: ["missing-file"] },
];

const protection: ProtectionStatus = {
  realtime: true,
  antivirus: true,
  tamper: true,
  signatureAgeDays: 0,
  firewall: ["Domain", "Private", "Public"].map((name) => ({ name, enabled: true })),
};

const now = Math.floor(Date.now() / 1000);

let incidents: Incident[] = [
  {
    id: "process-masquerade|demo",
    rule: "process-masquerade",
    severity: "high",
    title: "svchost.exe запущен не из папки Windows",
    summary: "Процесс носит имя системного компонента Windows, но его файл лежит в другом месте. Так вредоносные программы маскируются под системные.",
    evidence: [
      { label: "Процесс", value: "svchost.exe" },
      { label: "PID", value: "7312" },
      { label: "Путь", value: "C:\\Users\\demo\\AppData\\Roaming\\svchost.exe" },
    ],
    firstSeen: now - 540,
    lastSeen: now,
    status: "active",
    explanation: null,
    target: { pid: 7312, path: "C:\\Users\\demo\\AppData\\Roaming\\svchost.exe" },
  },
  {
    id: "process-temp-path|demo",
    rule: "process-temp-path",
    severity: "medium",
    title: "setup_tmp.exe запущен из временной папки",
    summary: "Программы редко работают из временных папок постоянно. Так ведут себя установщики и обновления, но также и вредоносные программы.",
    evidence: [
      { label: "Процесс", value: "setup_tmp.exe" },
      { label: "PID", value: "9120" },
      { label: "Путь", value: "C:\\Users\\demo\\AppData\\Local\\Temp\\7zS41A\\setup_tmp.exe" },
    ],
    firstSeen: now - 120,
    lastSeen: now,
    status: "active",
    explanation: null,
    target: { pid: 9120, path: "C:\\Users\\demo\\AppData\\Local\\Temp\\7zS41A\\setup_tmp.exe" },
  },
  {
    id: "autostart-missing-file|demo",
    rule: "autostart-missing-file",
    severity: "low",
    title: "Автозагрузка «OldUpdater» ссылается на несуществующий файл",
    summary: "Файл из записи автозагрузки не найден. Чаще всего это остаток удалённой программы.",
    evidence: [{ label: "Команда", value: '"C:\\Program Files\\OldApp\\updater.exe"' }],
    firstSeen: now - 86_400,
    lastSeen: now - 7200,
    status: "resolved",
    explanation: null,
    target: null,
  },
];

const responses: ResponsesState = {
  quarantine: [
    { id: "a1b2c3d4e5f60718", name: "crack_setup.exe", originalPath: "C:\\Users\\demo\\Downloads\\crack_setup.exe", size: 3.4 * MB, quarantinedAt: now - 3600 },
  ],
  blocks: [],
  log: [{ at: now - 3600, action: "quarantine", target: "C:\\Users\\demo\\Downloads\\crack_setup.exe", error: null }],
};

/** Demo version of a response: records it and pretends it worked. */
function respond(action: ResponsesState["log"][number]["action"], target: string) {
  responses.log = [{ at: Math.floor(Date.now() / 1000), action, target, error: null }, ...responses.log];
  return null;
}

let hasKey = false;

const DEMO_EXPLANATION =
  "Это демонстрационное объяснение: в браузере запрос к Claude не отправляется.\n\nВ приложении здесь будет разбор инцидента простым языком: что произошло, насколько это опасно и что стоит сделать.";

const modelInfo: ModelInfo = {
  dataset: "EMBER 2018",
  trained: "2026-11-12",
  trainSamples: 540_000,
  testSamples: 200_000,
  trees: 1000,
  auc: 0.995,
  suspiciousThreshold: 0.6,
  maliciousThreshold: 0.97,
  suspiciousDetection: 0.95,
  suspiciousFalsePositives: 0.01,
  maliciousDetection: 0.8,
  maliciousFalsePositives: 0.001,
};

function scanResult(name: string, folder: string, score: number | null, extra: Partial<ScanResult> = {}): ScanResult {
  return {
    path: `${folder}\\${name}`,
    name,
    size: Math.round((0.2 + Math.random() * 40) * MB),
    verdict: score === null ? "not-executable" : score >= 0.97 ? "malicious" : score >= 0.6 ? "suspicious" : "clean",
    score,
    sha256: score === null ? null : "9f2c1e0b7a4d5c6e8f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70",
    signature: score === null ? null : score < 0.3 ? { status: "valid", signer: "Demo Software LLC" } : { status: "unsigned", signer: null },
    maxSectionEntropy: score === null ? null : 5.5 + score * 2.4,
    error: null,
    ...extra,
  };
}

const scanResults: ScanResult[] = [
  scanResult("svchost.exe", "C:\\Users\\demo\\AppData\\Roaming", 0.994),
  scanResult("setup_tmp.exe", "C:\\Users\\demo\\AppData\\Local\\Temp\\7zS41A", 0.71),
  scanResult("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application", 0.012),
  scanResult("Code.exe", "C:\\Program Files\\Microsoft VS Code", 0.004),
  scanResult("Telegram.exe", "C:\\Users\\demo\\AppData\\Roaming\\Telegram Desktop", 0.021),
  scanResult("notes.txt", "C:\\Users\\demo\\Documents", null),
  scanResult("pagefile.sys", "C:\\", null, { verdict: "error", error: "Не удалось прочитать файл: отказано в доступе." }),
];

export function mock(command: string, args?: Record<string, unknown>): unknown {
  switch (command) {
    case "get_profile_status":
      return { learning: true, observedSecs: 2700, learningSecs: 7200, programs: 143, networkPrograms: 31, listeningPrograms: 6 };
    case "get_responses":
      return responses;
    case "kill_process":
      incidents = incidents.map((i) => (i.target?.pid === args?.pid ? { ...i, status: "resolved" } : i));
      return respond("kill", String(args?.path ?? `PID ${args?.pid}`));
    case "quarantine_file": {
      const path = String(args?.path);
      const item = { id: String(Date.now()), name: path.split("\\").pop() ?? path, originalPath: path, size: 2 * MB, quarantinedAt: Math.floor(Date.now() / 1000) };
      responses.quarantine = [item, ...responses.quarantine];
      return respond("quarantine", path);
    }
    case "restore_file":
    case "delete_quarantined": {
      const item = responses.quarantine.find((q) => q.id === args?.id);
      responses.quarantine = responses.quarantine.filter((q) => q.id !== args?.id);
      return respond(command === "restore_file" ? "restore" : "delete", item?.originalPath ?? "");
    }
    case "block_program": {
      const path = String(args?.path);
      responses.blocks = [{ id: `DefenseR block ${Date.now()}`, name: path.split("\\").pop() ?? path, path, blockedAt: Math.floor(Date.now() / 1000) }, ...responses.blocks];
      return respond("block", path);
    }
    case "unblock_program": {
      const block = responses.blocks.find((b) => b.id === args?.id);
      responses.blocks = responses.blocks.filter((b) => b.id !== args?.id);
      return respond("unblock", block?.path ?? "");
    }
    case "get_model_info":
      return modelInfo;
    case "scan_paths":
    case "scan_processes":
      return new Promise((resolve) => setTimeout(() => resolve(scanResults), 1200));
    case "get_incidents":
      return incidents;
    case "dismiss_incident":
      incidents = incidents.map((i) => (i.id === args?.id ? { ...i, status: "dismissed" } : i));
      return null;
    case "explain_incident":
      if (!hasKey) throw "Сначала добавьте ключ API в настройках.";
      incidents = incidents.map((i) => (i.id === args?.id ? { ...i, explanation: DEMO_EXPLANATION } : i));
      return DEMO_EXPLANATION;
    case "get_ai_status":
      return { hasKey };
    case "set_api_key":
      hasKey = true;
      return null;
    case "clear_api_key":
      hasKey = false;
      return null;
    case "get_overview":
      return overview();
    case "get_processes":
      return processes();
    case "get_connections":
      return connections;
    case "get_autostart":
      return autostart;
    case "get_protection":
      return protection;
    default:
      throw new Error(`No mock for ${command}`);
  }
}
