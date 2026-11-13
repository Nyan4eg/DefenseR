import { FileCheck } from "./FileCheck";
import { ResponseActions } from "./ResponseActions";
import { tr } from "../lib/i18n";

interface Props {
  pid: number;
  /** The program's file; null when Windows does not let DefenseR see it. */
  path: string | null;
  name: string;
  onDone: () => void;
}

/** Everything that can be done about a running program, for an expanded table row. */
export function ProcessActions({ pid, path, name, onDone }: Props) {
  return (
    <div className="flex flex-col gap-2 rounded-xl bg-black/20 px-3 py-3">
      {path ? (
        <div className="select-text break-all font-mono text-xs text-white/55">{path}</div>
      ) : (
        <div className="text-xs text-white/45">
          {tr("Windows не показывает путь к файлу этого процесса — обычно так бывает у системных и защищённых процессов. Доступно только завершение.", "Windows does not show the path to this process's file — this usually happens with system and protected processes. Only ending it is available.")}
        </div>
      )}
      <ResponseActions target={{ pid, path }} name={name} onDone={onDone} />
      {path && <FileCheck path={path} canTrust onDone={onDone} />}
    </div>
  );
}
