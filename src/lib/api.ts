import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export interface Overview {
  hostName: string;
  osVersion: string;
  uptimeSecs: number;
  cpuUsage: number;
  memoryUsed: number;
  memoryTotal: number;
}

export interface ProcessInfo {
  pid: number;
  parentPid: number | null;
  name: string;
  exe: string | null;
  cpu: number;
  memory: number;
  flags: string[];
}

export interface Connection {
  protocol: "TCP" | "UDP";
  localAddr: string;
  localPort: number;
  remoteAddr: string | null;
  remotePort: number | null;
  state: string | null;
  pid: number | null;
  remoteIsPublic: boolean;
}

export interface AutostartEntry {
  name: string;
  command: string;
  source: string;
  scope: "user" | "machine";
  flags: string[];
}

export interface ProtectionStatus {
  realtime: boolean | null;
  antivirus: boolean | null;
  tamper: boolean | null;
  signatureAgeDays: number | null;
  firewall: { name: string; enabled: boolean }[];
}

export type Severity = "low" | "medium" | "high";
export type IncidentStatus = "active" | "resolved" | "dismissed";

export interface Incident {
  id: string;
  rule: string;
  severity: Severity;
  title: string;
  summary: string;
  evidence: { label: string; value: string }[];
  /** Unix seconds. */
  firstSeen: number;
  lastSeen: number;
  status: IncidentStatus;
  explanation: string | null;
  /** The process and file the incident is about, when there is one to act on. */
  target: ResponseTarget | null;
}

export interface ResponseTarget {
  pid: number | null;
  path: string | null;
}

export interface ProfileStatus {
  learning: boolean;
  observedSecs: number;
  learningSecs: number;
  programs: number;
  networkPrograms: number;
  listeningPrograms: number;
}

export interface QuarantineItem {
  id: string;
  name: string;
  originalPath: string;
  size: number;
  quarantinedAt: number;
}

export interface FirewallBlock {
  id: string;
  name: string;
  path: string;
  blockedAt: number;
}

export interface ResponseLogEntry {
  at: number;
  action: "kill" | "quarantine" | "restore" | "delete" | "block" | "unblock";
  target: string;
  error: string | null;
}

export interface ResponsesState {
  quarantine: QuarantineItem[];
  blocks: FirewallBlock[];
  log: ResponseLogEntry[];
}

export interface AppSettings {
  notifications: boolean;
  /** Development build: start with Windows is unavailable. */
  devBuild: boolean;
}

export interface AiStatus {
  hasKey: boolean;
}

export type Verdict = "clean" | "suspicious" | "malicious" | "not-executable" | "error";

export interface ScanResult {
  path: string;
  name: string;
  size: number;
  verdict: Verdict;
  /** Model's probability, 0 to 1, that the file is malicious. Null when the model did not run. */
  score: number | null;
  sha256: string | null;
  /** Windows' verdict on the file's signature. Null when it was not verified. */
  signature: Signature | null;
  maxSectionEntropy: number | null;
  error: string | null;
}

export interface Signature {
  /** valid: signed, unchanged, trusted signer. invalid: changed after signing. */
  status: "valid" | "invalid" | "untrusted" | "unsigned" | "unknown";
  signer: string | null;
}

export interface ScanProgress {
  done: number;
  total: number;
}

export interface ModelInfo {
  dataset: string;
  trained: string;
  trainSamples: number;
  testSamples: number;
  trees: number;
  auc: number;
  suspiciousThreshold: number;
  maliciousThreshold: number;
  suspiciousDetection: number;
  suspiciousFalsePositives: number;
  maliciousDetection: number;
  maliciousFalsePositives: number;
}

/** False when the UI is opened in a plain browser (`npm run dev`), where it runs on mock data. */
export const inTauri = "__TAURI_INTERNALS__" in window;

/** Backend errors arrive as plain strings; this rejects with that string. */
export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (inTauri) return invoke<T>(command, args);
  const { mock } = await import("./mock");
  return mock(command, args) as T;
}

/**
 * Calls a backend command immediately and then every `intervalMs`. Returns null until the
 * first answer. Changing `refreshKey` forces an immediate re-fetch.
 */
export function usePolling<T>(command: string, intervalMs: number, refreshKey = 0): T | null {
  const [data, setData] = useState<T | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = () =>
      call<T>(command)
        .then((result) => alive && setData(result))
        .catch((error) => console.error(command, error));
    tick();
    const timer = setInterval(tick, intervalMs);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [command, intervalMs, refreshKey]);

  return data;
}

export const FLAG_LABELS: Record<string, string> = {
  "temp-path": "Запуск из временной папки",
  "missing-file": "Файл не найден",
};

export function formatBytes(bytes: number): string {
  const gb = bytes / 1024 ** 3;
  if (gb >= 1) return `${gb.toFixed(1)} ГБ`;
  if (bytes >= 1024 ** 2) return `${Math.round(bytes / 1024 ** 2)} МБ`;
  return `${Math.max(1, Math.round(bytes / 1024))} КБ`;
}

export function formatTime(unixSecs: number): string {
  return new Date(unixSecs * 1000).toLocaleString("ru-RU", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

export function formatUptime(secs: number): string {
  const days = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  const minutes = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days} д ${hours} ч`;
  if (hours > 0) return `${hours} ч ${minutes} мин`;
  return `${minutes} мин`;
}
