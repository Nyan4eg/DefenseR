import { useEffect, useState } from "react";
import { Activity, BrainCircuit, ChevronDown, FileSearch, FolderSearch, LoaderCircle, Upload } from "lucide-react";
import { ResponseActions } from "../components/ResponseActions";
import { Badge, Card, PageHeader, Tabs } from "../components/ui";
import { formatBytes, inTauri, type ModelInfo, type ScanProgress, type ScanResult, type Signature, type Verdict } from "../lib/api";

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
  malicious: { label: "Похож на вредоносный", dot: "bg-rose-400", text: "text-rose-300", bar: "bg-rose-400" },
  suspicious: { label: "Подозрительный", dot: "bg-amber-400", text: "text-amber-300", bar: "bg-amber-400" },
  clean: { label: "Чистый", dot: "bg-emerald-400", text: "text-emerald-300", bar: "bg-emerald-400" },
  "not-executable": { label: "Не программа", dot: "bg-white/25", text: "text-white/45", bar: "bg-white/25" },
  error: { label: "Не проверен", dot: "bg-white/25", text: "text-white/45", bar: "bg-white/25" },
};

function describeSignature(signature: Signature): string {
  const by = signature.signer ? ` (${signature.signer})` : "";
  switch (signature.status) {
    case "valid":
      return `Действительна, издатель: ${signature.signer ?? "не указан"}`;
    case "invalid":
      return `Не сходится с содержимым: файл изменён после подписания${by}`;
    case "untrusted":
      return `Есть, но Windows не доверяет издателю${by}`;
    case "unsigned":
      return "Нет";
    case "unknown":
      return "Windows не смогла проверить";
  }
}

const percent = (value: number, digits = 1) => `${(value * 100).toFixed(digits).replace(".", ",")}%`;

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
        {result.signature?.status === "valid" && <Badge tone="accent">{result.signature.signer ?? "Подписан"}</Badge>}
        {result.signature?.status === "invalid" && <Badge tone="warn">Подпись нарушена</Badge>}
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
          <dt className="text-white/40">Путь</dt>
          <dd className="select-text break-all font-mono text-white/75">{result.path}</dd>
          <dt className="text-white/40">Размер</dt>
          <dd className="text-white/75">{formatBytes(result.size)}</dd>
          {result.score !== null && (
            <>
              <dt className="text-white/40">Оценка модели</dt>
              <dd className="text-white/75">{percent(result.score)} — вероятность, что файл вредоносный</dd>
            </>
          )}
          {result.maxSectionEntropy !== null && (
            <>
              <dt className="text-white/40">Энтропия</dt>
              <dd className="text-white/75">
                {result.maxSectionEntropy.toFixed(2).replace(".", ",")} из 8 в самой плотной секции
                {result.maxSectionEntropy > 7.2 && " — так выглядят сжатые или зашифрованные данные"}
              </dd>
            </>
          )}
          {result.signature && (
            <>
              <dt className="text-white/40">Подпись</dt>
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
              <dt className="text-white/40">Причина</dt>
              <dd className="text-white/75">Модель оценивает только программы Windows: файлы .exe, .dll, .sys и подобные.</dd>
            </>
          )}
          {result.error && (
            <>
              <dt className="text-white/40">Ошибка</dt>
              <dd className="text-white/75">{result.error}</dd>
            </>
          )}
        </dl>
      )}
      {open && (result.verdict === "malicious" || result.verdict === "suspicious") && (
        <div className="mx-4 mb-3">
          <ResponseActions target={{ pid: null, path: result.path }} name={result.name} onDone={onChanged} />
        </div>
      )}
    </div>
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
    const picked = await open({ directory, multiple: !directory, title: directory ? "Папка для проверки" : "Файлы для проверки" });
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
      <PageHeader title="Проверка файлов" subtitle="Локальная модель оценивает программы, не запуская их. Файлы не покидают компьютер" />

      <Card className={`p-5 transition-colors ${dragging ? "border-emerald-400/50 bg-emerald-400/[0.07]" : ""}`}>
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={() => onScan({ kind: "processes" })} disabled={scan.busy} className={`${button} bg-emerald-400/15 text-emerald-200 hover:bg-emerald-400/25`}>
            <Activity size={16} />
            Проверить запущенные программы
          </button>
          <button onClick={() => pick(false)} disabled={scan.busy} className={`${button} bg-white/8 text-white/80 hover:bg-white/12`}>
            <FileSearch size={16} />
            Выбрать файлы
          </button>
          <button onClick={() => pick(true)} disabled={scan.busy} className={`${button} bg-white/8 text-white/80 hover:bg-white/12`}>
            <FolderSearch size={16} />
            Выбрать папку
          </button>
          <span className="ml-auto flex items-center gap-1.5 text-xs text-white/35">
            <Upload size={13} />
            или перетащите файлы в окно
          </span>
        </div>

        {scan.busy && (
          <div className="mt-4">
            <div className="flex items-center gap-2 text-sm text-white/70">
              <LoaderCircle size={15} className="animate-spin text-emerald-300" />
              {scan.progress && scan.progress.total > 0 ? `Проверено ${scan.progress.done} из ${scan.progress.total}` : "Поиск файлов…"}
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
                Файлов: {results.length} · похожих на вредоносные: {count("malicious")} · подозрительных: {count("suspicious")} · чистых: {count("clean")}
              </p>
            </div>
            <Tabs
              value={filter}
              onChange={setFilter}
              options={[
                { id: "attention", label: `Требуют внимания · ${attention.length}` },
                { id: "all", label: `Все · ${results.length}` },
              ]}
            />
          </div>
          <Card className="overflow-hidden">
            {shown.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-white/55">
                {results.length === 0 ? "Программ для проверки не нашлось" : "Модель не нашла ничего подозрительного"}
              </div>
            ) : (
              shown.map((result) => <ResultRow key={result.path} result={result} onChanged={onChanged} />)
            )}
          </Card>
          {attention.length > 0 && (
            <p className="mt-3 text-xs text-white/40">
              Оценка модели — повод присмотреться, а не приговор: она ошибается, особенно на свежих и редких программах. Откройте строку и
              проверьте файл по SHA-256 на VirusTotal, прежде чем что-то удалять.
            </p>
          )}
        </>
      )}

      {model && (
        <Card className="mt-6 p-5 text-sm text-white/55">
          <div className="flex items-center gap-2 font-medium text-white/85">
            <BrainCircuit size={16} className="text-emerald-400" />
            Как работает модель
          </div>
          <p className="mt-2">
            {model.trees} решающих деревьев, обученных на {Math.round(model.trainSamples / 1000)} тыс. программ из набора {model.dataset}. Модель
            смотрит на строение файла — статистику байтов, строки, заголовки, секции, импортируемые функции — и выдаёт вероятность того, что
            он вредоносный.
          </p>
          <p className="mt-2">
            На {Math.round(model.testSamples / 1000)} тыс. проверочных программ: метка «Подозрительный» ловит {percent(model.suspiciousDetection)}{" "}
            вредоносных и ошибочно ставится {percent(model.suspiciousFalsePositives, 2)} чистых; метка «Похож на вредоносный» —{" "}
            {percent(model.maliciousDetection)} и {percent(model.maliciousFalsePositives, 2)}. Набор собран в 2018 году, поэтому на современных
            программах ошибок больше.
          </p>
        </Card>
      )}
    </>
  );
}
