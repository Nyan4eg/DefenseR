// Sample data for working on the UI in a plain browser. Never used inside the Tauri app.
import { tr } from "./i18n";
import { lang } from "./i18n";
import type { AutostartEntry, Connection, Incident, ModelInfo, Overview, ProcessInfo, ProtectionStatus, ResponsesState, ScanResult, TrustState } from "./api";

const GB = 1024 ** 3;
const MB = 1024 ** 2;

const demoApps: { name: string; folder: string; publisher: string | null; count: number; memory: number }[] = [
  { name: "chrome.exe", folder: "C:\\Program Files\\Google\\Chrome\\Application", publisher: "Google LLC", count: 9, memory: 310 },
  { name: "Code.exe", folder: "C:\\Program Files\\Microsoft VS Code", publisher: "Microsoft Corporation", count: 6, memory: 260 },
  { name: "explorer.exe", folder: "C:\\Windows", publisher: "Microsoft Windows", count: 1, memory: 340 },
  { name: "svchost.exe", folder: "C:\\Windows\\System32", publisher: "Microsoft Windows", count: 14, memory: 28 },
  { name: "Telegram.exe", folder: "C:\\Users\\demo\\AppData\\Roaming\\Telegram Desktop", publisher: "Telegram FZ-LLC", count: 1, memory: 420 },
  { name: "MsMpEng.exe", folder: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform", publisher: "Microsoft Windows Publisher", count: 1, memory: 230 },
  { name: "steam.exe", folder: "C:\\Program Files (x86)\\Steam", publisher: "Valve Corp.", count: 3, memory: 120 },
  { name: "node.exe", folder: "C:\\Program Files\\nodejs", publisher: "OpenJS Foundation", count: 2, memory: 150 },
  { name: "Discord.exe", folder: "C:\\Users\\demo\\AppData\\Local\\Discord\\app-1.0", publisher: "Discord Inc.", count: 5, memory: 180 },
  { name: "obs-portable.exe", folder: "D:\\Tools\\obs", publisher: null, count: 1, memory: 510 },
];

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
  const list: ProcessInfo[] = [];
  demoApps.forEach((app, appIndex) => {
    for (let i = 0; i < app.count; i++) {
      list.push({
        pid: 1000 + appIndex * 412 + i * 8,
        parentPid: i === 0 ? 4 : 1000 + appIndex * 412,
        name: app.name,
        exe: `${app.folder}\\${app.name}`,
        cpu: Math.random() * (i === 0 ? 5 : 1.2),
        memory: app.memory * (0.5 + Math.random()) * MB,
        flags: [],
        signed: app.publisher !== null,
        publisher: app.publisher,
      });
    }
  });
  list.push({
    pid: 9120,
    parentPid: 1000,
    name: "setup_tmp.exe",
    exe: "C:\\Users\\demo\\AppData\\Local\\Temp\\7zS41A\\setup_tmp.exe",
    cpu: 1.4,
    memory: 42 * MB,
    flags: ["temp-path"],
    signed: false,
    publisher: null,
  });
  list.push({ pid: 4, parentPid: null, name: "System", exe: null, cpu: 0.3, memory: 2 * MB, flags: [], signed: null, publisher: null });
  return list;
}

const connections: Connection[] = [
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51422, remoteAddr: "142.250.74.14", remotePort: 443, state: "ESTABLISHED", pid: 1000, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51431, remoteAddr: "142.251.98.17", remotePort: 443, state: "ESTABLISHED", pid: 1008, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51440, remoteAddr: "140.82.114.26", remotePort: 443, state: "ESTABLISHED", pid: 1016, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51437, remoteAddr: "149.154.167.51", remotePort: 443, state: "ESTABLISHED", pid: 2648, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51502, remoteAddr: "162.159.130.234", remotePort: 443, state: "ESTABLISHED", pid: 4296, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51610, remoteAddr: "13.107.42.14", remotePort: 443, state: "CLOSE_WAIT", pid: 1412, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51700, remoteAddr: "203.0.113.77", remotePort: 8885, state: "ESTABLISHED", pid: 9120, remoteIsPublic: true },
  { protocol: "TCP", localAddr: "192.168.1.20", localPort: 51422, remoteAddr: "192.168.1.1", remotePort: 53, state: "ESTABLISHED", pid: 2236, remoteIsPublic: false },
  { protocol: "TCP", localAddr: "127.0.0.1", localPort: 1420, remoteAddr: "0.0.0.0", remotePort: 0, state: "LISTEN", pid: 3884, remoteIsPublic: false },
  { protocol: "TCP", localAddr: "0.0.0.0", localPort: 135, remoteAddr: "0.0.0.0", remotePort: 0, state: "LISTEN", pid: 2236, remoteIsPublic: false },
  { protocol: "TCP", localAddr: "0.0.0.0", localPort: 27036, remoteAddr: "0.0.0.0", remotePort: 0, state: "LISTEN", pid: 3472, remoteIsPublic: false },
  { protocol: "UDP", localAddr: "0.0.0.0", localPort: 5353, remoteAddr: null, remotePort: null, state: null, pid: 1000, remoteIsPublic: false },
];

let autostart: AutostartEntry[] = [
  { name: "SecurityHealth", command: "%windir%\\system32\\SecurityHealthSystray.exe", source: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", scope: "machine", flags: [] },
  { name: "Steam", command: '"C:\\Program Files (x86)\\Steam\\steam.exe" -silent', source: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", scope: "user", flags: [] },
  { name: "Discord", command: '"C:\\Users\\demo\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe', source: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", scope: "user", flags: [] },
  { name: "AnyDesk.lnk", command: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AnyDesk.lnk", source: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", scope: "machine", flags: [] },
  { name: "OldUpdater", command: '"C:\\Program Files\\OldApp\\updater.exe"', source: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", scope: "user", flags: ["missing-file"] },
  { name: "\\Demo\\Browser Update", label: "Browser Update", command: '"C:\\Program Files\\Demo Browser\\update.exe" /scheduled', source: "Task Scheduler", scope: "machine", flags: [], kind: "task", trigger: tr("по расписанию", "on a schedule") },
  { name: "\\Wake Check", label: "Wake Check", command: 'powershell.exe -File "C:\\Users\\demo\\AppData\\Local\\Temp\\check.ps1"', source: "Task Scheduler", scope: "machine", flags: ["temp-path"], kind: "task", trigger: tr("при входе в Windows", "when you sign in") },
  { name: "DemoVpnService", label: "Demo VPN Service", command: '"C:\\Program Files\\Demo VPN\\vpnservice.exe"', source: "Services", scope: "machine", flags: [], kind: "service", trigger: tr("при запуске компьютера", "when the computer starts") },
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
  blocks: [{ id: "DefenseR block 1", name: "obs-portable.exe", path: "D:\\Tools\\obs\\obs-portable.exe", blockedAt: now - 7200 }],
  autostart: [
    { id: "d1", name: "EpicGamesLauncher", command: '"C:\\Program Files (x86)\\Epic Games\\Launcher\\EpicGamesLauncher.exe" -silent', source: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", scope: "user", disabledAt: now - 86400 },
  ],
  log: [{ at: now - 3600, action: "quarantine", target: "C:\\Users\\demo\\Downloads\\crack_setup.exe", error: null }],
};

/** Demo version of a response: records it and pretends it worked. */
function respond(action: ResponsesState["log"][number]["action"], target: string) {
  responses.log = [{ at: Math.floor(Date.now() / 1000), action, target, error: null }, ...responses.log];
  return null;
}

let hasKey = false;
let hasVtKey = false;
const trust: TrustState = { files: [], publishers: [{ signer: "Demo Software LLC", addedAt: now - 86400 }] };

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
    case "disable_autostart": {
      const entry = autostart.find((e) => e.source === args?.source && e.name === args?.name);
      if (!entry) throw "Запись уже исчезла из автозагрузки.";
      autostart = autostart.filter((e) => e !== entry);
      incidents = incidents.map((i) => (i.target?.autostart?.name === entry.name ? { ...i, status: "resolved" } : i));
      responses.autostart = [{ id: String(Date.now()), name: entry.name, command: entry.command, source: entry.source, scope: entry.scope, disabledAt: Math.floor(Date.now() / 1000), kind: entry.kind === "task" || entry.kind === "service" ? entry.kind : "", label: entry.label }, ...responses.autostart];
      return respond("autostart-disable", `${entry.source}\\${entry.name}`);
    }
    case "enable_autostart":
    case "forget_autostart": {
      const item = responses.autostart.find((a) => a.id === args?.id);
      responses.autostart = responses.autostart.filter((a) => a.id !== args?.id);
      if (item && command === "enable_autostart") autostart = [...autostart, { name: item.name, command: item.command, source: item.source, scope: item.scope, flags: [], kind: item.kind === "task" || item.kind === "service" ? item.kind : undefined, label: item.label }];
      return respond(command === "enable_autostart" ? "autostart-enable" : "autostart-forget", `${item?.source}\\${item?.name}`);
    }
    case "get_vt_status":
      return { hasKey: hasVtKey };
    case "set_vt_key":
      hasVtKey = true;
      return null;
    case "clear_vt_key":
      hasVtKey = false;
      return null;
    case "check_reputation": {
      if (!hasVtKey) throw "Сначала добавьте ключ VirusTotal в настройках.";
      const bad = String(args?.path ?? "").toLowerCase().includes("roaming\\svchost");
      const reputation = { sha256: "9f2c1e0b7a4d5c6e8f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70", known: true, malicious: bad ? 47 : 0, suspicious: bad ? 2 : 0, total: 71, label: bad ? "trojan.agent/stealer" : null, analysedAt: now - 7200, checkedAt: Math.floor(Date.now() / 1000) };
      incidents = incidents.map((i) => (i.id === args?.incident ? { ...i, reputation } : i));
      return new Promise((resolve) => setTimeout(() => resolve(reputation), 700));
    }
    case "get_file_identity": {
      const path = String(args?.path);
      const signed = path.includes("Program Files");
      return { sha256: "9f2c", publisher: signed ? "Demo Software LLC" : null, trustedFile: trust.files.some((f) => f.path === path), trustedPublisher: signed };
    }
    case "trust_file": {
      const path = String(args?.path);
      if (!args?.publisher) trust.files = [{ sha256: `demo-${Date.now()}`, name: path.split("\\").pop() ?? path, path, addedAt: Math.floor(Date.now() / 1000) }, ...trust.files];
      incidents = incidents.map((i) => (i.target?.path === path ? { ...i, status: "resolved" } : i));
      return null;
    }
    case "get_trust":
      return { files: [...trust.files], publishers: [...trust.publishers] };
    case "untrust":
      trust.files = trust.files.filter((f) => f.sha256 !== args?.id);
      trust.publishers = trust.publishers.filter((p) => p.signer !== args?.id);
      return null;
    case "get_settings":
      return { notifications: true, watchDownloads: true, watchTemp: true, watchRemovable: true, autoVirustotal: false, language: lang, autoUpdate: true, devBuild: false };
    case "set_language":
      return null;
    case "get_update_status":
    case "check_update":
      return { current: "0.1.1", available: "0.2.0", notes: "Проверка файлов по VirusTotal.", checkedAt: Math.floor(Date.now() / 1000) - 600, checking: false, installing: false, error: null, devBuild: false };
    case "install_update":
      throw "В демо-режиме обновление не устанавливается.";
    case "set_auto_update":
    case "get_downloads_status":
      return {
        folders: [
          { path: "C:\\Users\\demo\\Downloads", place: "downloads" },
          { path: "C:\\Users\\demo\\Desktop", place: "desktop" },
          { path: "C:\\Users\\demo\\AppData\\Local\\Temp", place: "temp" },
          { path: "E:\\", place: "removable" },
        ],
        checked: 14,
        recent: [
          { path: "C:\\Users\\demo\\Downloads\\free-codec-pack.exe", name: "free-codec-pack.exe", verdict: "malicious", signature: "unsigned", at: Math.floor(Date.now() / 1000) - 240, place: "downloads" },
          { path: "C:\\Users\\demo\\Downloads\\VSCodeUserSetup-x64.exe", name: "VSCodeUserSetup-x64.exe", verdict: "clean", signature: "valid", at: Math.floor(Date.now() / 1000) - 5400, place: "desktop" },
          { path: "C:\\Users\\demo\\Downloads\\tool\\helper.dll", name: "helper.dll", verdict: "suspicious", signature: "unsigned", at: Math.floor(Date.now() / 1000) - 86400, place: "removable" },
        ],
      };
    case "set_option":
    case "set_watch_downloads":
    case "set_notifications":
      return null;
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
      return autostart.map((entry, index) => ({ ...entry, signed: entry.flags.length > 0 ? null : index % 4 !== 2, publisher: index % 4 !== 2 ? "Demo Software LLC" : null, interpreter: entry.command.startsWith("powershell") }));
    case "get_icons":
      return {};
    case "get_extensions":
      return [
        { browser: "Chrome", profile: "Default", id: "aaaabbbbccccddddeeeeffffgggghhhh", name: "Demo Ad Blocker", version: "5.2.1", enabled: true, source: "store", allSites: true, permissions: ["webRequest", "tabs", "scripting"], installedAt: now - 86400 * 200, manageUrl: "chrome://extensions/?id=aaaabbbbccccddddeeeeffffgggghhhh" },
        { browser: "Chrome", profile: "Default", id: "bbbbccccddddeeeeffffgggghhhhiiii", name: "Demo Password Keeper", version: "3.0", enabled: true, source: "store", allSites: true, permissions: ["nativeMessaging", "privacy"], installedAt: now - 86400 * 90, manageUrl: "chrome://extensions/?id=bbbbccccddddeeeeffffgggghhhhiiii" },
        { browser: "Chrome", profile: "Default", id: "ccccddddeeeeffffgggghhhhiiiijjjj", name: "Search Helper Toolbar", version: "1.4", enabled: true, source: "external", allSites: true, permissions: ["cookies", "history", "tabs", "webRequest"], installedAt: now - 86400 * 2, manageUrl: "chrome://extensions/?id=ccccddddeeeeffffgggghhhhiiiijjjj" },
        { browser: "Edge", profile: "Default", id: "ddddeeeeffffgggghhhhiiiijjjjkkkk", name: "Demo Video Skipper", version: "6.1", enabled: true, source: "store", allSites: false, permissions: ["scripting"], installedAt: now - 86400 * 30, manageUrl: "edge://extensions/?id=ddddeeeeffffgggghhhhiiiijjjjkkkk" },
        { browser: "Edge", profile: "Default", id: "eeeeffffgggghhhhiiiijjjjkkkkllll", name: "My Test Extension", version: "0.1", enabled: false, source: "unpacked", allSites: false, permissions: [], installedAt: null, manageUrl: "edge://extensions/?id=eeeeffffgggghhhhiiiijjjjkkkkllll" },
        { browser: "Firefox", profile: "abcd.default-release", id: "demo@example.org", name: "Demo Notes", version: "2.2", enabled: true, source: "store", allSites: false, permissions: ["tabs"], installedAt: now - 86400 * 400, manageUrl: "about:addons" },
      ];
    case "get_protection":
      return protection;
    default:
      throw new Error(`No mock for ${command}`);
  }
}
