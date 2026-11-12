import { FileCheck } from "./FileCheck";
import { ResponseActions } from "./ResponseActions";

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
          Windows не показывает путь к файлу этого процесса — обычно так бывает у системных и защищённых процессов. Доступно только завершение.
        </div>
      )}
      <ResponseActions target={{ pid, path }} name={name} onDone={onDone} />
      {path && <FileCheck path={path} canTrust onDone={onDone} />}
    </div>
  );
}
