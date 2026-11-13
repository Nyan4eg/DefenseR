// The icons of program files, fetched from the backend in batches and kept for the session.
// Rows ask for an icon as they appear; until it arrives (or when a file has none of its
// own) they draw a letter instead.

import { useEffect, useSyncExternalStore } from "react";
import { call } from "./api";

/** By lower-cased path: a `data:` URL, or null for a file without an icon of its own. */
const known = new Map<string, string | null>();
const waiting = new Map<string, string>();
const listeners = new Set<() => void>();
let scheduled = false;

const BATCH = 200;

async function flush() {
  scheduled = false;
  const batch = [...waiting.entries()].slice(0, BATCH);
  if (batch.length === 0) return;
  for (const [key] of batch) waiting.delete(key);
  let found: Record<string, string> = {};
  try {
    found = await call<Record<string, string>>("get_icons", { paths: batch.map(([, path]) => path) });
  } catch {
    // Without icons the letters stay; nothing else depends on them.
  }
  for (const [key, path] of batch) known.set(key, found[path] ?? null);
  for (const listener of listeners) listener();
  if (waiting.size > 0) schedule();
}

function schedule() {
  if (scheduled) return;
  scheduled = true;
  // A list asks for hundreds of icons within one frame; they go out together.
  setTimeout(flush, 120);
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The icon of the program at `path`, or null while it is unknown or when there is none. */
export function useIcon(path: string | null | undefined): string | null {
  const key = path ? path.toLowerCase() : null;
  const icon = useSyncExternalStore(subscribe, () => (key ? (known.get(key) ?? null) : null));
  useEffect(() => {
    if (!key || !path || known.has(key) || waiting.has(key)) return;
    waiting.set(key, path);
    schedule();
  }, [key, path]);
  return icon;
}
