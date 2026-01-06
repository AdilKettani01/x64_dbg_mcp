import { execFile } from "node:child_process";
import process from "node:process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type SecurityConfig = {
  allowPids: number[];
  denyPids: number[];
  allowNames: string[];
  denyNames: string[];
};

export class SecurityError extends Error {
  readonly data?: unknown;

  constructor(message: string, data?: unknown) {
    super(message);
    this.name = "SecurityError";
    this.data = data;
  }
}

export const defaultSecurityConfig = (): SecurityConfig => ({
  allowPids: [],
  denyPids: [],
  allowNames: [],
  denyNames: []
});

const normalizeName = (value: string): string => value.trim().toLowerCase();

const unique = <T>(values: T[]): T[] => Array.from(new Set(values));

export const normalizeSecurityConfig = (
  config: SecurityConfig
): SecurityConfig => ({
  allowPids: unique(config.allowPids),
  denyPids: unique(config.denyPids),
  allowNames: unique(config.allowNames.map(normalizeName).filter(Boolean)),
  denyNames: unique(config.denyNames.map(normalizeName).filter(Boolean))
});

const parseTasklistLine = (line: string): string | null => {
  const trimmed = line.trim();
  if (
    trimmed.length === 0 ||
    trimmed.toLowerCase().startsWith("info:") ||
    trimmed.toLowerCase().includes("no tasks are running")
  ) {
    return null;
  }
  if (!trimmed.startsWith("\"") || !trimmed.endsWith("\"")) {
    return null;
  }
  const parts = trimmed.slice(1, -1).split("\",\"");
  if (parts.length === 0) {
    return null;
  }
  return parts[0] ?? null;
};

const getProcessNameWindows = async (pid: number): Promise<string | null> => {
  try {
    const { stdout } = await execFileAsync("tasklist", [
      "/FI",
      `PID eq ${pid}`,
      "/FO",
      "CSV",
      "/NH"
    ]);
    const lines = stdout.split(/\r?\n/).filter((entry) => entry.trim().length);
    if (lines.length === 0) {
      return null;
    }
    return parseTasklistLine(lines[0]) ?? null;
  } catch {
    return null;
  }
};

const getProcessNameUnix = async (pid: number): Promise<string | null> => {
  try {
    const { stdout } = await execFileAsync("ps", [
      "-p",
      String(pid),
      "-o",
      "comm="
    ]);
    const name = stdout.trim().split(/\r?\n/)[0]?.trim();
    return name ? name : null;
  } catch {
    return null;
  }
};

const getProcessName = async (pid: number): Promise<string | null> => {
  if (process.platform === "win32") {
    return getProcessNameWindows(pid);
  }
  return getProcessNameUnix(pid);
};

const matchesNameList = (name: string, list: string[]): boolean =>
  list.some((entry) => name.includes(entry));

export const assertAttachAllowed = async (
  pid: number,
  config: SecurityConfig
): Promise<void> => {
  if (config.denyPids.includes(pid)) {
    throw new SecurityError("Attach blocked by denylisted PID.", { pid });
  }

  if (config.allowPids.length > 0 && !config.allowPids.includes(pid)) {
    throw new SecurityError("Attach blocked by allowlist policy.", { pid });
  }

  const needsNameCheck =
    config.allowNames.length > 0 || config.denyNames.length > 0;
  if (!needsNameCheck) {
    return;
  }

  const processName = await getProcessName(pid);
  if (!processName) {
    throw new SecurityError(
      "Process name unavailable; attach blocked by policy.",
      { pid }
    );
  }

  const normalized = normalizeName(processName);
  if (matchesNameList(normalized, config.denyNames)) {
    throw new SecurityError("Attach blocked by denylisted process name.", {
      pid,
      name: processName
    });
  }

  if (config.allowNames.length > 0 && !matchesNameList(normalized, config.allowNames)) {
    throw new SecurityError("Attach blocked by allowlist policy.", {
      pid,
      name: processName
    });
  }
};
