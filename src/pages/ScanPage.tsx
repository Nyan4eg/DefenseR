import { useEffect, useState } from "react";
import {
  Activity,
  BadgeCheck,
  BrainCircuit,
  ChevronDown,
  CircleCheck,
  FileArchive,
  FileCode,
  FileSearch,
  Files,
  FolderSearch,
  HardDriveDownload,
  Monitor,
  Radar,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Timer,
  Usb,
  type LucideIcon,
} from "lucide-react";
import { FileCheck } from "../components/FileCheck";
import { Avatar, Chip, EmptyState, Meter, Rise, StatTile } from "../components/kit";
import { ResponseActions } from "../components/ResponseActions";
import { Card, PageHeader } from "../components/ui";
import { formatBytes, formatTime, inTauri, usePolling, type DownloadsStatus, type ModelInfo, type ScanProgress, type ScanResult, type Signature, type Verdict, type WatchedPlace } from "../lib/api";
import { lang, tr } from "../lib/i18n";

export type ScanRequest = { kind: "processes" } | { kind: "paths"; paths: string[] };

export interface ScanState {
  busy: boolean;
  progress: ScanProgress | null;
  /** What was scanned, for the results heading. */
  label: string;
  results: ScanResult[] | null;
  error: string | null;
}

type Filter = "attention" | "malicious" | "suspicious" | "clean" | "all";

const VERDICTS: Record<Verdict, { label: string; text: string; pill: string; tone: "danger" | "warn" | "accent" | "neutral" }> = {
  malicious: { label: tr("Похож на вредоносный", "Looks malicious"), text: "text-rose-300", pill: "border-rose-400/30 bg-rose-400/10 text-rose-200", tone: "danger" },
  suspicious: { label: tr("Подозрительный", "Suspicious"), text: "text-amber-300", pill: "border-amber-400/30 bg-amber-400/10 text-amber-200", tone: "warn" },
  clean: { label: tr("Чистый", "Clean"), text: "text-emerald-300", pill: "border-emerald-400/25 bg-emerald-400/[0.08] text-emerald-200", tone: "accent" },
  "not-executable": { label: tr("Не программа", "Not a program"), text: "text-white/45", pill: "border-white/10 text-white/50", tone: "neutral" },
  error: { label: tr("Не проверен", "Not checked"), text: "text-white/45", pill: "border-white/10 text-white/50", tone: "neutral" },
};

function describeSignature(signature: Signature): string {
  const by = signature.signer ? ` (${signature.signer})` : "";
  switch (signature.status) {
    case "valid":
      return tr(`Действительна, издатель: ${signature.signer ?? "не указан"}`, `Valid, publisher: ${signature.signer ?? "not specified"}`);
    case "invalid":
      return tr(`Не сходится с содержимым: файл изменён после подписания${by}`, `Does not match the contents: the file was changed after signing${by}`);
    case "untrusted":
      return tr(`Есть, но Windows не доверяет издателю${by}`, `Present, but Windows does not trust the publisher${by}`);
    case "unsigned":
      return tr("Нет", "None");
    case "unknown":
      return tr("Windows не смогла проверить", "Windows could not verify it");
  }
}

// A decimal comma for Russian, a decimal point for English.
const decimal = (text: string) => (lang === "ru" ? text.replace(".", ",") : text);

const percent = (value: number, digits = 1) => `${decimal((value * 100).toFixed(digits))}%`;

function VerdictPill({ verdict }: { verdict: Verdict }) {
  return <span className={`shrink-0 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs ${VERDICTS[verdict].pill}`}>{VERDICTS[verdict].label}</span>;
}

function ResultRow({ result, onChanged }: { result: ScanResult; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const verdict = VERDICTS[result.verdict];

  return (
    <div className={`rounded-xl transition-colors ${open ? "bg-white/[0.05]" : "hover:bg-white/[0.035]"}`}>
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-3 py-2.5 text-left">
        <Avatar name={result.name} muted={result.score === null} path={result.score === null ? null : result.path} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{result.name}</span>
            {result.signature?.status === "valid" && (
              <Chip icon={BadgeCheck} tone="accent">
                {result.signature.signer ?? tr("Подписан", "Signed")}
              </Chip>
            )}
            {result.signature?.status === "invalid" && (
              <Chip icon={ShieldAlert} tone="danger">
                {tr("Подпись нарушена", "Signature broken")}
              </Chip>
            )}
          </div>
          <div className="mt-0.5 truncate font-mono text-xs text-white/35">{result.path}</div>
        </div>
        {result.score !== null && (
          <div className="w-32 shrink-0">
            <div className="mb-1 flex justify-between text-xs">
              <span className="text-white/35">{tr("Риск", "Risk")}</span>
              <span className={`tabular-nums ${verdict.text}`}>{Math.round(result.score * 100)}%</span>
            </div>
            <Meter value={Math.max(0.02, result.score)} tone={verdict.tone} />
          </div>
        )}
        <VerdictPill verdict={result.verdict} />
        <ChevronDown size={16} className={`shrink-0 text-white/30 transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="rise mx-3 mb-3 flex flex-col gap-3 rounded-xl border border-white/8 bg-black/20 px-4 py-3">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
            <dt className="text-white/40">{tr("Путь", "Path")}</dt>
            <dd className="select-text break-all font-mono text-white/75">{result.path}</dd>
            <dt className="text-white/40">{tr("Размер", "Size")}</dt>
            <dd className="text-white/75">{formatBytes(result.size)}</dd>
            {result.score !== null && (
              <>
                <dt className="text-white/40">{tr("Оценка модели", "Model score")}</dt>
                <dd className="text-white/75">{tr(`${percent(result.score)} — вероятность, что файл вредоносный`, `${percent(result.score)} — probability that the file is malicious`)}</dd>
              </>
            )}
            {result.maxSectionEntropy !== null && (
              <>
                <dt className="text-white/40">{tr("Энтропия", "Entropy")}</dt>
                <dd className="text-white/75">
                  {tr(`${decimal(result.maxSectionEntropy.toFixed(2))} из 8 в самой плотной секции`, `${decimal(result.maxSectionEntropy.toFixed(2))} out of 8 in the densest section`)}
                  {result.maxSectionEntropy > 7.2 && tr(" — так выглядят сжатые или зашифрованные данные", " — this is what compressed or encrypted data looks like")}
                </dd>
              </>
            )}
            {result.signature && (
              <>
                <dt className="text-white/40">{tr("Подпись", "Signature")}</dt>
                <dd className="text-white/75">{describeSignature(result.signature)}</dd>
              </>
            )}
            {result.sha256 && (
              <>
                <dt className="text-white/40">SHA-256</dt>
                <dd className="select-text break-all font-mono text-white/75">{result.sha256}</dd>
              </>
            )}
            {result.verdict === "not-executable" && (
              <>
                <dt className="text-white/40">{tr("Причина", "Reason")}</dt>
                <dd className="text-white/75">{tr("Модель оценивает только программы Windows: файлы .exe, .dll, .sys и подобные.", "The model only scores Windows programs: .exe, .dll, .sys and similar files.")}</dd>
              </>
            )}
            {result.error && (
              <>
                <dt className="text-white/40">{tr("Ошибка", "Error")}</dt>
                <dd className="text-white/75">{result.error}</dd>
              </>
            )}
          </dl>
          {result.sha256 && <FileCheck path={result.path} sha256={result.sha256} canTrust={result.score !== null} onDone={onChanged} />}
          {(result.verdict === "malicious" || result.verdict === "suspicious") && <ResponseActions target={{ pid: null, path: result.path }} name={result.name} onDone={onChanged} />}
        </div>
      )}
    </div>
  );
}

const PLACES: Record<WatchedPlace, { label: string; icon: LucideIcon }> = {
  downloads: { label: tr("Загрузки", "Downloads"), icon: HardDriveDownload },
  desktop: { label: tr("Рабочий стол", "Desktop"), icon: Monitor },
  temp: { label: tr("Временная папка", "Temp folder"), icon: Timer },
  removable: { label: tr("Съёмный диск", "Removable drive"), icon: Usb },
};

/** The icon for a checked file, by what kind of file it is. */
function kindIcon(name: string): LucideIcon | null {
  const extension = name.split(".").pop()?.toLowerCase() ?? "";
  if (extension === "zip") return FileArchive;
  if (["ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk"].includes(extension)) return FileCode;
  return null;
}

/** Files that were checked on their own as they appeared in the watched places. */
function WatchCard() {
  const status = usePolling<DownloadsStatus>("get_downloads_status", 5000);
  if (!status) return null;
  const watching = status.folders.length > 0;

  return (
    <Card className="mt-5 overflow-hidden">
      <div className="flex items-center gap-4 px-5 py-4">
        <div className="relative flex size-10 shrink-0 items-center justify-center">
          {watching && <span className="ping-soft absolute inset-1 rounded-full bg-emerald-400/40" />}
          <span className={`relative flex size-10 items-center justify-center rounded-xl border border-white/10 bg-white/[0.05] ${watching ? "text-emerald-300" : "text-white/35"}`}>
            <Radar size={19} />
          </span>
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">{watching ? tr("Слежу за новыми файлами", "Watching for new files") : tr("Слежение за новыми файлами выключено", "Watching for new files is off")}</div>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {watching ? (
              status.folders.map((folder) => (
                <Chip key={folder.path} icon={PLACES[folder.place].icon} tone="accent" title={folder.path}>
                  {folder.place === "removable" ? `${PLACES.removable.label} ${folder.path}` : PLACES[folder.place].label}
                </Chip>
              ))
            ) : (
              <span className="text-xs text-white/45">{tr("Включить можно в настройках, в разделе «Проверка новых файлов».", "You can turn it on in Settings, under “Checking new files”.")}</span>
            )}
          </div>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-2xl font-semibold tabular-nums tracking-tight">{status.checked}</div>
          <div className="text-xs text-white/40">{tr("проверено файлов", "files checked")}</div>
        </div>
      </div>

      {status.recent.length === 0 ? (
        <div className="border-t border-white/6 px-5 py-4 text-sm text-white/45">
          {tr(
            "Пока ничего не проверялось. Программа, скрипт или архив, которые появятся в одном из этих мест, будут проверены через несколько секунд — делать для этого ничего не нужно.",
            "Nothing has been checked yet. A program, script or archive that appears in one of these places will be checked within a few seconds — you do not need to do anything.",
          )}
        </div>
      ) : (
        <div className="border-t border-white/6 p-2">
          {status.recent.map((item, index) => {
            const place = PLACES[item.place];
            const Kind = kindIcon(item.name);
            return (
              <Rise key={item.path} index={index}>
                <div className="flex items-center gap-3 rounded-xl px-3 py-2 hover:bg-white/[0.035]">
                  <Avatar name={item.name} size={32} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm">{item.name}</span>
                      {Kind && <Kind size={13} className="shrink-0 text-white/35" />}
                      {item.signature === "valid" && <BadgeCheck size={13} className="shrink-0 text-emerald-400" />}
                      {item.signature === "invalid" && (
                        <Chip icon={ShieldAlert} tone="danger">
                          {tr("Подпись нарушена", "Signature broken")}
                        </Chip>
                      )}
                    </div>
                    <div className="truncate font-mono text-xs text-white/30" title={item.path}>
                      {item.path}
                    </div>
                  </div>
                  <Chip icon={place.icon}>{place.label}</Chip>
                  <VerdictPill verdict={item.verdict} />
                  <div className="w-28 shrink-0 text-right text-xs text-white/40">{formatTime(item.at)}</div>
                </div>
              </Rise>
            );
          })}
        </div>
      )}
    </Card>
  );
}

interface Props {
  scan: ScanState;
  model: ModelInfo | null;
  onScan: (request: ScanRequest) => void;
  /** Called after a response action, so lists elsewhere refresh. */
  onChanged: () => void;
}

export function ScanPage({ scan, model, onScan, onChanged }: Props) {
  const [filter, setFilter] = useState<Filter>("attention");
  const [dragging, setDragging] = useState(false);
  const [aboutModel, setAboutModel] = useState(false);

  // Files and folders dropped onto the window.
  useEffect(() => {
    if (!inTauri) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    import("@tauri-apps/api/webview").then(({ getCurrentWebview }) =>
      getCurrentWebview()
        .onDragDropEvent((event) => {
          if (event.payload.type === "drop") {
            setDragging(false);
            if (event.payload.paths.length > 0) onScan({ kind: "paths", paths: event.payload.paths });
          } else {
            setDragging(event.payload.type !== "leave");
          }
        })
        .then((stop) => (cancelled ? stop() : (unlisten = stop))),
    );
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [onScan]);

  const pick = async (directory: boolean) => {
    if (!inTauri) return onScan({ kind: "paths", paths: ["demo"] });
    const { open } = await import("@tauri-apps/plugin-dialog");
    const picked = await open({ directory, multiple: !directory, title: directory ? tr("Папка для проверки", "Folder to scan") : tr("Файлы для проверки", "Files to scan") });
    const paths = picked === null ? [] : Array.isArray(picked) ? picked : [picked];
    if (paths.length > 0) onScan({ kind: "paths", paths });
  };

  const results = scan.results ?? [];
  const count = (verdict: Verdict) => results.filter((result) => result.verdict === verdict).length;
  const attention = results.filter((result) => result.verdict === "malicious" || result.verdict === "suspicious");
  const shown = filter === "all" ? results : filter === "attention" ? attention : results.filter((result) => result.verdict === filter);
  const share = scan.progress && scan.progress.total > 0 ? scan.progress.done / scan.progress.total : 0;
  const action = "flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm transition duration-200 hover:-translate-y-0.5 disabled:pointer-events-none disabled:opacity-40";

  return (
    <>
      <PageHeader
        title={tr("Проверка файлов", "File scan")}
        subtitle={tr("Локальная модель оценивает программы, не запуская их. Файлы не покидают компьютер", "A local model scores programs without running them. Files never leave the computer")}
      />

      <div
        className={`relative overflow-hidden rounded-2xl border bg-white/[0.04] p-6 transition-colors duration-300 ${
          dragging ? "border-emerald-400/60 bg-emerald-400/[0.08]" : "border-white/8"
        }`}
      >
        <div className="pointer-events-none absolute -left-16 -top-24 size-72 rounded-full bg-emerald-400/15 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-28 right-10 size-72 rounded-full bg-cyan-400/10 blur-3xl" />
        {dragging && <div className="shimmer pointer-events-none absolute inset-0" />}

        <div className="relative flex items-center gap-6">
          {/* The scanner: rings with a sweep that speeds up while a scan is running. */}
          <div className="relative flex size-28 shrink-0 items-center justify-center">
            <div className="absolute inset-0 rounded-full border border-emerald-400/20" />
            <div className="absolute inset-4 rounded-full border border-emerald-400/15" />
            <div className="absolute inset-8 rounded-full border border-emerald-400/10" />
            <div
              className={`absolute inset-0 rounded-full ${scan.busy ? "sweep-fast" : "sweep"}`}
              style={{ background: "conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgb(52 211 153 / 0.45) 360deg)", maskImage: "radial-gradient(circle, black 68%, transparent 70%)" }}
            />
            <div className="relative flex size-11 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-400 to-cyan-400 text-[#06281f] shadow-[0_0_24px_rgb(52_211_153/0.45)]">
              {scan.busy ? <Radar size={22} /> : <ShieldCheck size={22} strokeWidth={2.4} />}
            </div>
          </div>

          <div className="min-w-0 flex-1">
            {scan.busy ? (
              <>
                <div className="text-lg font-semibold tracking-tight">
                  {scan.progress && scan.progress.total > 0
                    ? tr(`Проверено ${scan.progress.done} из ${scan.progress.total}`, `Checked ${scan.progress.done} of ${scan.progress.total}`)
                    : tr("Ищу файлы…", "Looking for files…")}
                </div>
                <div className="mt-1 text-sm text-white/50">{tr("Можно перейти на другую страницу — проверка продолжится.", "You can go to another page — the scan will carry on.")}</div>
                <div className="relative mt-4 h-2 overflow-hidden rounded-full bg-white/8">
                  <div className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-cyan-400 transition-[width] duration-300" style={{ width: `${share * 100}%` }} />
                  <div className="shimmer absolute inset-0" />
                </div>
              </>
            ) : (
              <>
                <div className="text-lg font-semibold tracking-tight">
                  {dragging ? tr("Отпустите, чтобы проверить", "Drop to scan") : tr("Перетащите сюда файл или папку", "Drag a file or a folder here")}
                </div>
                <div className="mt-1 text-sm text-white/50">
                  {tr("Или выберите, что проверить. В папке DefenseR сам найдёт все программы.", "Or choose what to scan. In a folder, DefenseR finds every program on its own.")}
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button onClick={() => onScan({ kind: "processes" })} className={`${action} bg-gradient-to-r from-emerald-400/25 to-cyan-400/20 text-emerald-100 shadow-[0_0_18px_rgb(52_211_153/0.15)] hover:from-emerald-400/35 hover:to-cyan-400/30`}>
                    <Activity size={16} />
                    {tr("Проверить запущенные программы", "Scan running programs")}
                  </button>
                  <button onClick={() => pick(false)} className={`${action} bg-white/8 text-white/80 hover:bg-white/12`}>
                    <FileSearch size={16} />
                    {tr("Выбрать файлы", "Choose files")}
                  </button>
                  <button onClick={() => pick(true)} className={`${action} bg-white/8 text-white/80 hover:bg-white/12`}>
                    <FolderSearch size={16} />
                    {tr("Выбрать папку", "Choose folder")}
                  </button>
                </div>
              </>
            )}
            {scan.error && <div className="mt-3 text-sm text-rose-300">{scan.error}</div>}
          </div>
        </div>
      </div>

      {scan.results && (
        <div className="rise mt-5">
          <div className="mb-3 flex items-baseline gap-3">
            <h2 className="text-base font-semibold">{scan.label}</h2>
            <span className="text-xs text-white/40">{tr("нажмите на плитку, чтобы отфильтровать", "click a tile to filter")}</span>
          </div>
          <div className="mb-3 flex gap-3">
            <StatTile
              icon={ShieldAlert}
              label={tr("Требуют внимания", "Need attention")}
              value={attention.length}
              tone={attention.length > 0 ? "danger" : "neutral"}
              onClick={() => setFilter("attention")}
              active={filter === "attention"}
            />
            <StatTile icon={ShieldAlert} label={VERDICTS.malicious.label} value={count("malicious")} tone="danger" onClick={() => setFilter("malicious")} active={filter === "malicious"} />
            <StatTile icon={ShieldQuestion} label={VERDICTS.suspicious.label} value={count("suspicious")} tone="warn" onClick={() => setFilter("suspicious")} active={filter === "suspicious"} />
            <StatTile icon={CircleCheck} label={VERDICTS.clean.label} value={count("clean")} tone="accent" onClick={() => setFilter("clean")} active={filter === "clean"} />
            <StatTile icon={Files} label={tr("Все файлы", "All files")} value={results.length} onClick={() => setFilter("all")} active={filter === "all"} />
          </div>
          <Card className="p-2">
            {shown.length === 0 ? (
              results.length === 0 ? (
                <EmptyState icon={FileSearch} tone="neutral" title={tr("Программ для проверки не нашлось", "No programs found to scan")} />
              ) : filter === "attention" ? (
                <EmptyState
                  icon={ShieldCheck}
                  title={tr("Модель не нашла ничего подозрительного", "The model found nothing suspicious")}
                  text={tr(`Проверено файлов: ${results.length}. Нажмите «Все файлы», чтобы посмотреть каждый.`, `Files checked: ${results.length}. Click “All files” to look at each one.`)}
                />
              ) : (
                <EmptyState icon={Files} tone="neutral" title={tr("Таких файлов нет", "No such files")} />
              )
            ) : (
              shown.map((result, index) => (
                <Rise key={result.path} index={index}>
                  <ResultRow result={result} onChanged={onChanged} />
                </Rise>
              ))
            )}
          </Card>
          {attention.length > 0 && (
            <p className="mt-3 px-1 text-xs leading-relaxed text-white/40">
              {tr(
                "Оценка модели — повод присмотреться, а не приговор: она ошибается, особенно на свежих и редких программах. Откройте строку и проверьте файл по SHA-256 на VirusTotal, прежде чем что-то удалять.",
                "The model's score is a reason to take a closer look, not a verdict: it makes mistakes, especially on new and rare programs. Open the row and check the file by its SHA-256 on VirusTotal before deleting anything.",
              )}
            </p>
          )}
        </div>
      )}

      <WatchCard />

      {model && (
        <Card className="mt-5 overflow-hidden text-sm text-white/55">
          <button onClick={() => setAboutModel(!aboutModel)} className="flex w-full items-center gap-2 px-5 py-3.5 text-left font-medium text-white/85 hover:bg-white/[0.03]">
            <BrainCircuit size={16} className="text-emerald-400" />
            <span className="flex-1">{tr("Как работает модель", "How the model works")}</span>
            <span className="text-xs font-normal text-white/40">
              {tr(`${model.trees} деревьев · ${model.dataset}`, `${model.trees} trees · ${model.dataset}`)}
            </span>
            <ChevronDown size={16} className={`text-white/30 transition-transform duration-200 ${aboutModel ? "rotate-180" : ""}`} />
          </button>
          {aboutModel && (
            <div className="rise border-t border-white/6 px-5 py-4">
              <p>
                {tr(
                  `${model.trees} решающих деревьев, обученных на ${Math.round(model.trainSamples / 1000)} тыс. программ из набора ${model.dataset}. Модель смотрит на строение файла — статистику байтов, строки, заголовки, секции, импортируемые функции — и выдаёт вероятность того, что он вредоносный.`,
                  `${model.trees} decision trees trained on ${Math.round(model.trainSamples / 1000)} thousand programs from the ${model.dataset} dataset. The model looks at the structure of the file — byte statistics, strings, headers, sections, imported functions — and gives the probability that it is malicious.`,
                )}
              </p>
              <p className="mt-2">
                {tr(
                  `На ${Math.round(model.testSamples / 1000)} тыс. проверочных программ: метка «Подозрительный» ловит ${percent(model.suspiciousDetection)} вредоносных и ошибочно ставится ${percent(model.suspiciousFalsePositives, 2)} чистых; метка «Похож на вредоносный» — ${percent(model.maliciousDetection)} и ${percent(model.maliciousFalsePositives, 2)}. Набор собран в 2018 году, поэтому на современных программах ошибок больше.`,
                  `On ${Math.round(model.testSamples / 1000)} thousand test programs: the “Suspicious” label catches ${percent(model.suspiciousDetection)} of malicious programs and is wrongly given to ${percent(model.suspiciousFalsePositives, 2)} of clean ones; the “Looks malicious” label — ${percent(model.maliciousDetection)} and ${percent(model.maliciousFalsePositives, 2)}. The dataset was collected in 2018, so there are more mistakes on modern programs.`,
                )}
              </p>
            </div>
          )}
        </Card>
      )}
    </>
  );
}
