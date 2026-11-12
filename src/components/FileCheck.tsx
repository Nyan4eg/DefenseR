import { useEffect, useState } from "react";
import { BadgeCheck, ExternalLink, LoaderCircle, Search } from "lucide-react";
import { ConfirmDialog } from "./ui";
import { call, formatTime, inTauri, type FileIdentity, type Reputation } from "../lib/api";

interface Props {
  /** The file, when it is still in place. */
  path: string | null;
  /** Its SHA-256 if already known; lets VirusTotal be asked about a file that is gone. */
  sha256?: string | null;
  /** The incident to store VirusTotal's answer with. */
  incidentId?: string;
  reputation?: Reputation | null;
  /** Offer to trust the file or its publisher. */
  canTrust: boolean;
  onDone: () => void;
}

function ReputationLine({ reputation }: { reputation: Reputation }) {
  const flagged = reputation.malicious + reputation.suspicious;
  const tone = !reputation.known ? "text-white/60" : reputation.malicious >= 3 ? "text-rose-300" : flagged > 0 ? "text-amber-300" : "text-emerald-300";
  const text = !reputation.known
    ? "VirusTotal не знает этот файл. Так бывает у новых и редких программ: это не говорит ни за, ни против."
    : flagged === 0
      ? `VirusTotal: ни один из ${reputation.total} антивирусов не считает файл опасным.`
      : `VirusTotal: ${flagged} из ${reputation.total} антивирусов считают файл опасным${reputation.label ? ` (${reputation.label})` : ""}.${
          reputation.malicious < 3 ? " Одно-два срабатывания часто бывают ложными." : ""
        }`;

  const open = async () => {
    const url = `https://www.virustotal.com/gui/file/${reputation.sha256}`;
    if (!inTauri) return void window.open(url, "_blank");
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(url);
  };

  return (
    <div className="rounded-xl bg-black/20 px-3 py-2.5 text-xs">
      <div className={tone}>{text}</div>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 text-white/40">
        {reputation.analysedAt && <span>Антивирусы проверяли файл {formatTime(reputation.analysedAt)}</span>}
        <span>Запрошено {formatTime(reputation.checkedAt)}</span>
        {reputation.known && (
          <button onClick={open} className="flex items-center gap-1 text-white/55 hover:text-white/85">
            <ExternalLink size={12} />
            Открыть отчёт
          </button>
        )}
      </div>
    </div>
  );
}

/** A second opinion on a file from VirusTotal, and the choice to trust the file or its publisher. */
export function FileCheck({ path, sha256, incidentId, reputation: stored, canTrust, onDone }: Props) {
  const [reputation, setReputation] = useState<Reputation | null>(stored ?? null);
  const [identity, setIdentity] = useState<FileIdentity | null>(null);
  const [busy, setBusy] = useState(false);
  const [asking, setAsking] = useState<"file" | "publisher" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!path || !canTrust) return;
    let alive = true;
    call<FileIdentity>("get_file_identity", { path })
      .then((result) => alive && setIdentity(result))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [path, canTrust]);

  const check = async () => {
    setBusy(true);
    setError(null);
    try {
      setReputation(await call<Reputation>("check_reputation", { path, sha256: sha256 ?? null, incident: incidentId ?? null }));
      if (incidentId) onDone();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const trust = async (publisher: boolean) => {
    setAsking(null);
    setError(null);
    try {
      await call("trust_file", { path, publisher });
      setIdentity((prev) => prev && { ...prev, trustedFile: prev.trustedFile || !publisher, trustedPublisher: prev.trustedPublisher || publisher });
      onDone();
    } catch (e) {
      setError(String(e));
    }
  };

  const button = "flex items-center gap-1.5 rounded-lg border border-white/10 px-2.5 py-1.5 text-xs text-white/65 hover:bg-white/8 hover:text-white/90 disabled:opacity-50";
  const name = path?.split("\\").pop() ?? "файл";
  const trusted = identity && (identity.trustedFile || identity.trustedPublisher);

  return (
    <div className="flex flex-col gap-2">
      {reputation && <ReputationLine reputation={reputation} />}
      <div className="flex flex-wrap items-center gap-2">
        {!reputation && (
          <button onClick={check} disabled={busy} className={button} title="В VirusTotal уйдёт только SHA-256 файла, не сам файл">
            {busy ? <LoaderCircle size={13} className="animate-spin" /> : <Search size={13} />}
            Проверить на VirusTotal
          </button>
        )}
        {trusted && (
          <span className="flex items-center gap-1.5 px-1 text-xs text-emerald-300">
            <BadgeCheck size={14} />
            {identity.trustedFile ? "Файл в доверенных" : `Издатель ${identity.publisher} в доверенных`}
          </span>
        )}
        {identity && !trusted && (
          <button onClick={() => setAsking("file")} className={button}>
            <BadgeCheck size={13} />
            Доверять файлу
          </button>
        )}
        {identity && !trusted && identity.publisher && (
          <button onClick={() => setAsking("publisher")} className={button}>
            <BadgeCheck size={13} />
            Доверять издателю {identity.publisher}
          </button>
        )}
        {error && <span className="text-xs text-rose-300">{error}</span>}
      </div>

      {asking === "file" && (
        <ConfirmDialog
          title={`Доверять файлу ${name}?`}
          body="DefenseR перестанет заводить инциденты об этом файле, пока его содержимое не изменится. Убрать файл из доверенных можно на странице «Реакции»."
          confirmLabel="Доверять"
          danger={false}
          onConfirm={() => trust(false)}
          onCancel={() => setAsking(null)}
        />
      )}
      {asking === "publisher" && identity?.publisher && (
        <ConfirmDialog
          title={`Доверять издателю ${identity.publisher}?`}
          body="DefenseR перестанет заводить инциденты обо всех программах с действительной подписью этого издателя — и уже установленных, и будущих. Убрать издателя из доверенных можно на странице «Реакции»."
          confirmLabel="Доверять издателю"
          danger={false}
          onConfirm={() => trust(true)}
          onCancel={() => setAsking(null)}
        />
      )}
    </div>
  );
}
