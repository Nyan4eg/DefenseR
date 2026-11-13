import { useEffect, useState } from "react";
import { Activity, BrainCircuit, ChevronDown, Download, FileSearch, FolderSearch, LoaderCircle, Upload } from "lucide-react";
import { FileCheck } from "../components/FileCheck";
import { ResponseActions } from "../components/ResponseActions";
import { Badge, Card, PageHeader, Tabs } from "../components/ui";
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

type Filter = "attention" | "all";

const VERDICTS: Record<Verdict, { label: string; dot: string; text: string; bar: string }> = {
  malicious: { label: tr("Похож на вредоносный", "Looks malicious"), dot: "bg-rose-400", text: "text-rose-300", bar: "bg-rose-400" },
  suspicious: { label: tr("Подозрительный", "Suspicious"), dot: "bg-amber-400", text: "text-amber-300", bar: "bg-amber-400" },
  clean: { label: tr("Чистый", "Clean"), dot: "bg-emerald-400", text: "text-emerald-300", bar: "bg-emerald-400" },
  "not-executable": { label: tr("Не программа", "Not a program"), dot: "bg-white/25", text: "text-white/45", bar: "bg-white/25" },
  error: { label: tr("Не проверен", "Not checked"), dot: "bg-white/25", text: "text-white/45", bar: "bg-white/25" },
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

function ResultRow({ result, onChanged }: { result: ScanResult; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const verdict = VERDICTS[result.verdict];

  return (
    <div className="border-b border-white/6 last:border-0">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-white/[0.03]">
        <span className={`size-2 shrink-0 rounded-full ${verdict.dot}`} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm">{result.name}</div>
          <div className="truncate font-mono text-xs text-white/35">{result.path}</div>
        </div>
        {result.signature?.status === "valid" && <Badge tone="accent">{result.signature.signer ?? tr("Подписан", "Signed")}</Badge>}
        {result.signature?.status === "invalid" && <Badge tone="warn">{tr("Подпись нарушена", "Signature broken")}</Badge>}
        <div className={`w-44 shrink-0 text-right text-xs ${verdict.text}`}>{verdict.label}</div>
        <div className="w-28 shrink-0">
          {result.score !== null && (
            <div className="flex items-center gap-2">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/8">
                <div className={`h-full rounded-full ${verdict.bar}`} style={{ width: `${Math.max(2, result.score * 100)}%` }} />
              </div>
              <span className="w-9 text-right text-xs tabular-nums text-white/55">{Math.round(result.score * 100)}%</span>
            </div>
          )}
        </div>
        <ChevronDown size={15} className={`shrink-0 text-white/30 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <dl className="mx-4 mb-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 rounded-xl bg-black/20 px-3 py-2.5 text-xs">
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
      )}
      {open && result.sha256 && (
        <div className="mx-4 mb-3">
          <FileCheck path={result.path} sha256={result.sha256} canTrust={result.score !== null} onDone={onChanged} />
        </div>
      )}
      {open && (result.verdict === "malicious" || result.verdict === "suspicious") && (
        <div className="mx-4 mb-3">
          <ResponseActions target={{ pid: null, path: result.path }} name={result.name} onDone={onChanged} />
        </div>
      )}
    </div>
  );
}

const PLACES: Record<WatchedPlace, string> = {
  downloads: tr("Загрузки", "Downloads"),
  desktop: tr("Рабочий стол", "Desktop"),
  temp: tr("Временная папка", "Temp folder"),
  removable: tr("Съёмный диск", "Removable drive"),
};

/** Programs that were checked on their own as they appeared in the watched places. */
function DownloadsCard() {
  const status = usePolling<DownloadsStatus>("get_downloads_status", 5000);
  if (!status) return null;

  const watched = status.folders.map((folder) => (folder.place === "removable" ? `${PLACES.removable} ${folder.path}` : PLACES[folder.place]));
  const state =
    watched.length === 0
      ? tr("Проверка новых файлов выключена в настройках", "Checking new files is turned off in settings")
      : tr(`Слежу за: ${watched.join(", ").toLowerCase()} · проверено программ: ${status.checked}`, `Watching: ${watched.join(", ").toLowerCase()} · programs checked: ${status.checked}`);

  return (
    <Card className="mt-6 overflow-hidden">
      <div className="px-5 py-4">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Download size={16} className="text-emerald-400" />
          {tr("Новые файлы", "New files")}
        </div>
        <p className="mt-1 text-sm text-white/50">{state}</p>
      </div>
      {status.recent.length === 0 ? (
        <div className="border-t border-white/6 px-5 py-4 text-sm text-white/45">
          {tr("Пока ничего не проверялось. Программа, которая появится в одном из этих мест, будет оценена через несколько секунд.", "Nothing has been checked yet. A program that appears in one of these places will be scored within a few seconds.")}
        </div>
      ) : (
        status.recent.map((item) => {
          const verdict = VERDICTS[item.verdict];
          return (
            <div key={item.path} className="flex items-center gap-3 border-t border-white/6 px-5 py-2.5">
              <span className={`size-2 shrink-0 rounded-full ${verdict.dot}`} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm">{item.name}</div>
                <div className="truncate font-mono text-xs text-white/35">{item.path}</div>
              </div>
              <Badge>{PLACES[item.place]}</Badge>
              {item.signature === "valid" && <Badge tone="accent">{tr("Подписан", "Signed")}</Badge>}
              {item.signature === "invalid" && <Badge tone="warn">{tr("Подпись нарушена", "Signature broken")}</Badge>}
              <div className={`shrink-0 text-right text-xs ${verdict.text}`}>{verdict.label}</div>
              <div className="w-28 shrink-0 text-right text-xs text-white/40">{formatTime(item.at)}</div>
            </div>
          );
        })
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
  const count = (verdict: Verdict) => results.filter((r) => r.verdict === verdict).length;
  const attention = results.filter((r) => r.verdict === "malicious" || r.verdict === "suspicious");
  const shown = filter === "attention" ? attention : results;
  const button = "flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm disabled:opacity-40";

  return (
    <>
      <PageHeader title={tr("Проверка файлов", "File scan")} subtitle={tr("Локальная модель оценивает программы, не запуская их. Файлы не покидают компьютер", "A local model scores programs without running them. Files never leave the computer")} />

      <Card className={`p-5 transition-colors ${dragging ? "border-emerald-400/50 bg-emerald-400/[0.07]" : ""}`}>
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={() => onScan({ kind: "processes" })} disabled={scan.busy} className={`${button} bg-emerald-400/15 text-emerald-200 hover:bg-emerald-400/25`}>
            <Activity size={16} />
            {tr("Проверить запущенные программы", "Scan running programs")}
          </button>
          <button onClick={() => pick(false)} disabled={scan.busy} className={`${button} bg-white/8 text-white/80 hover:bg-white/12`}>
            <FileSearch size={16} />
            {tr("Выбрать файлы", "Choose files")}
          </button>
          <button onClick={() => pick(true)} disabled={scan.busy} className={`${button} bg-white/8 text-white/80 hover:bg-white/12`}>
            <FolderSearch size={16} />
            {tr("Выбрать папку", "Choose folder")}
          </button>
          <span className="ml-auto flex items-center gap-1.5 text-xs text-white/35">
            <Upload size={13} />
            {tr("или перетащите файлы в окно", "or drag files into the window")}
          </span>
        </div>

        {scan.busy && (
          <div className="mt-4">
            <div className="flex items-center gap-2 text-sm text-white/70">
              <LoaderCircle size={15} className="animate-spin text-emerald-300" />
              {scan.progress && scan.progress.total > 0 ? tr(`Проверено ${scan.progress.done} из ${scan.progress.total}`, `Checked ${scan.progress.done} of ${scan.progress.total}`) : tr("Поиск файлов…", "Looking for files…")}
            </div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/8">
              <div
                className="h-full rounded-full bg-emerald-400 transition-[width] duration-200"
                style={{ width: `${scan.progress && scan.progress.total > 0 ? (scan.progress.done / scan.progress.total) * 100 : 0}%` }}
              />
            </div>
          </div>
        )}
        {scan.error && <div className="mt-3 text-sm text-rose-300">{scan.error}</div>}
      </Card>

      {scan.results && (
        <>
          <div className="mb-3 mt-6 flex items-end justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold">{scan.label}</h2>
              <p className="mt-0.5 text-sm text-white/50">
                {tr(
                  `Файлов: ${results.length} · похожих на вредоносные: ${count("malicious")} · подозрительных: ${count("suspicious")} · чистых: ${count("clean")}`,
                  `Files: ${results.length} · looking malicious: ${count("malicious")} · suspicious: ${count("suspicious")} · clean: ${count("clean")}`,
                )}
              </p>
            </div>
            <Tabs
              value={filter}
              onChange={setFilter}
              options={[
                { id: "attention", label: tr(`Требуют внимания · ${attention.length}`, `Need attention · ${attention.length}`) },
                { id: "all", label: tr(`Все · ${results.length}`, `All · ${results.length}`) },
              ]}
            />
          </div>
          <Card className="overflow-hidden">
            {shown.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-white/55">
                {results.length === 0 ? tr("Программ для проверки не нашлось", "No programs found to scan") : tr("Модель не нашла ничего подозрительного", "The model found nothing suspicious")}
              </div>
            ) : (
              shown.map((result) => <ResultRow key={result.path} result={result} onChanged={onChanged} />)
            )}
          </Card>
          {attention.length > 0 && (
            <p className="mt-3 text-xs text-white/40">
              {tr("Оценка модели — повод присмотреться, а не приговор: она ошибается, особенно на свежих и редких программах. Откройте строку и проверьте файл по SHA-256 на VirusTotal, прежде чем что-то удалять.", "The model's score is a reason to take a closer look, not a verdict: it makes mistakes, especially on new and rare programs. Open the row and check the file by its SHA-256 on VirusTotal before deleting anything.")}
            </p>
          )}
        </>
      )}

      <DownloadsCard />

      {model && (
        <Card className="mt-6 p-5 text-sm text-white/55">
          <div className="flex items-center gap-2 font-medium text-white/85">
            <BrainCircuit size={16} className="text-emerald-400" />
            {tr("Как работает модель", "How the model works")}
          </div>
          <p className="mt-2">
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
        </Card>
      )}
    </>
  );
}
