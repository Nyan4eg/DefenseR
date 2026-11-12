import { useCallback, useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Activity, FileSearch, LayoutDashboard, Lock, Network, Rocket, Settings, ShieldAlert, ShieldCheck } from "lucide-react";
import {
  call,
  inTauri,
  usePolling,
  type AiStatus,
  type AutostartEntry,
  type Connection,
  type Incident,
  type ModelInfo,
  type Overview,
  type ProcessInfo,
  type ProfileStatus,
  type ResponsesState,
  type ProtectionStatus,
  type ScanProgress,
  type ScanResult,
} from "./lib/api";
import { ScanPage, type ScanRequest, type ScanState } from "./pages/ScanPage";
import { ResponsesPage } from "./pages/ResponsesPage";
import { assess } from "./lib/score";
import { OverviewPage, type Sample } from "./pages/OverviewPage";
import { ProcessesPage } from "./pages/ProcessesPage";
import { NetworkPage } from "./pages/NetworkPage";
import { AutostartPage } from "./pages/AutostartPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { SettingsPage } from "./pages/SettingsPage";

type PageId = "overview" | "incidents" | "scan" | "responses" | "processes" | "network" | "autostart" | "settings";

const NAV = [
  { id: "overview", label: "Обзор", icon: LayoutDashboard },
  { id: "incidents", label: "Инциденты", icon: ShieldAlert },
  { id: "scan", label: "Проверка файлов", icon: FileSearch },
  { id: "responses", label: "Реакции", icon: Lock },
  { id: "processes", label: "Процессы", icon: Activity },
  { id: "network", label: "Сеть", icon: Network },
  { id: "autostart", label: "Автозагрузка", icon: Rocket },
  { id: "settings", label: "Настройки", icon: Settings },
] as const;

const OVERVIEW_INTERVAL_MS = 2000;
/** Two minutes of load history. */
const HISTORY_LENGTH = 120_000 / OVERVIEW_INTERVAL_MS;

export default function App() {
  const [page, setPage] = useState<PageId>("overview");
  const [history, setHistory] = useState<Sample[]>([]);

  const overview = usePolling<Overview>("get_overview", OVERVIEW_INTERVAL_MS);
  const processes = usePolling<ProcessInfo[]>("get_processes", 3000);
  const connections = usePolling<Connection[]>("get_connections", 5000);
  const protection = usePolling<ProtectionStatus>("get_protection", 60_000);

  // Bumped after the user changes an incident or the API key, to re-fetch right away.
  const [refreshKey, setRefreshKey] = useState(0);
  const refresh = () => setRefreshKey((key) => key + 1);
  const incidents = usePolling<Incident[]>("get_incidents", 5000, refreshKey);
  const autostart = usePolling<AutostartEntry[]>("get_autostart", 30_000, refreshKey);
  const aiStatus = usePolling<AiStatus>("get_ai_status", 60_000, refreshKey);
  const hasKey = aiStatus?.hasKey ?? false;
  const profile = usePolling<ProfileStatus>("get_profile_status", 30_000);
  const responses = usePolling<ResponsesState>("get_responses", 15_000, refreshKey);
  const activeIncidents = incidents?.filter((i) => i.status === "active").length ?? 0;

  // Scan state lives here so a scan keeps running, and its results stay, while other pages are open.
  const [model, setModel] = useState<ModelInfo | null>(null);
  const [scan, setScan] = useState<ScanState>({ busy: false, progress: null, label: "", results: null, error: null });

  useEffect(() => {
    call<ModelInfo>("get_model_info")
      .then(setModel)
      .catch((error) => setScan((prev) => ({ ...prev, error: String(error) })));
  }, []);

  useEffect(() => {
    if (!inTauri) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    import("@tauri-apps/api/event").then(({ listen }) =>
      listen<ScanProgress>("scan-progress", (event) => setScan((prev) => ({ ...prev, progress: event.payload }))).then((stop) =>
        cancelled ? stop() : (unlisten = stop),
      ),
    );
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  const startScan = useCallback((request: ScanRequest) => {
    const label = request.kind === "processes" ? "Запущенные программы" : "Выбранные файлы";
    setScan((prev) => ({ ...prev, busy: true, progress: null, error: null }));
    const pending =
      request.kind === "processes" ? call<ScanResult[]>("scan_processes") : call<ScanResult[]>("scan_paths", { paths: request.paths });
    pending
      .then((results) => setScan({ busy: false, progress: null, label, results, error: null }))
      .catch((error) => setScan((prev) => ({ ...prev, busy: false, progress: null, error: String(error) })));
  }, []);

  useEffect(() => {
    if (!overview) return;
    const sample = { cpu: overview.cpuUsage, memory: (overview.memoryUsed / overview.memoryTotal) * 100 };
    setHistory((prev) => [...prev, sample].slice(-HISTORY_LENGTH));
  }, [overview]);

  const assessment = useMemo(() => assess(protection, autostart, processes), [protection, autostart, processes]);

  return (
    // Semi-transparent over Mica inside Tauri, solid in a plain browser.
    <div className={`flex h-full ${inTauri ? "bg-[#0a0e13]/70" : "bg-[#0a0e13]"}`}>
      <aside className="flex w-56 shrink-0 flex-col border-r border-white/8 p-4">
        <div className="flex items-center gap-2.5 px-2 py-2">
          <div className="flex size-9 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-400 text-[#06281f]">
            <ShieldCheck size={20} strokeWidth={2.4} />
          </div>
          <div className="text-lg font-semibold tracking-tight">DefenseR</div>
        </div>

        <nav className="mt-6 flex flex-col gap-1">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setPage(id)}
              className={`relative flex items-center gap-3 rounded-xl px-3 py-2 text-sm transition-colors ${
                page === id ? "text-white" : "text-white/55 hover:bg-white/5 hover:text-white/85"
              }`}
            >
              {page === id && (
                <motion.div layoutId="nav-active" className="absolute inset-0 rounded-xl bg-white/10" transition={{ type: "spring", duration: 0.4 }} />
              )}
              <Icon size={17} className="relative" />
              <span className="relative">{label}</span>
              {id === "incidents" && activeIncidents > 0 && (
                <span className="relative ml-auto rounded-full bg-amber-400/20 px-1.5 text-xs tabular-nums text-amber-300">{activeIncidents}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="mt-auto rounded-xl border border-white/8 bg-white/[0.03] px-3 py-2.5 text-xs">
          <div className="flex items-center gap-2">
            <span className={`size-2 rounded-full ${activeIncidents > 0 ? "bg-amber-400" : "bg-emerald-400"}`} />
            <span className="text-white/70">{activeIncidents > 0 ? `Инцидентов: ${activeIncidents}` : "Мониторинг активен"}</span>
          </div>
          <div className="mt-1 truncate text-white/35">{overview?.hostName ?? "…"}</div>
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.div
            key={page}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.18 }}
            className="h-full overflow-auto p-7"
          >
            {page === "overview" && (
              <OverviewPage overview={overview} processes={processes} connections={connections} assessment={assessment} history={history} />
            )}
            {page === "incidents" && (
              <IncidentsPage incidents={incidents} profile={profile} hasKey={hasKey} onChanged={refresh} onOpenSettings={() => setPage("settings")} />
            )}
            {page === "scan" && <ScanPage scan={scan} model={model} onScan={startScan} onChanged={refresh} />}
            {page === "responses" && <ResponsesPage responses={responses} onChanged={refresh} />}
            {page === "settings" && <SettingsPage hasKey={hasKey} onChanged={refresh} />}
            {page === "processes" && <ProcessesPage processes={processes} />}
            {page === "network" && <NetworkPage connections={connections} processes={processes} />}
            {page === "autostart" && <AutostartPage autostart={autostart} onChanged={refresh} />}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
