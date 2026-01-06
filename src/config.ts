import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import {
  defaultSecurityConfig,
  normalizeSecurityConfig,
  type SecurityConfig
} from "./security.js";
import type {
  X64DbgClientConfig,
  X64DbgRetryConfig,
  X64DbgTransport
} from "./x64dbg/client.js";

export type ResolvedConfig = {
  client: X64DbgClientConfig;
  security: SecurityConfig;
  events: string[];
  eventQueueLimit: number;
  configFile?: string;
};

type ConfigFile = {
  transport?: X64DbgTransport;
  host?: string;
  port?: number;
  pipeName?: string;
  connectTimeoutMs?: number;
  requestTimeoutMs?: number;
  retry?: Partial<X64DbgRetryConfig>;
  events?: string[];
  eventQueueLimit?: number;
  security?: Partial<SecurityConfig>;
};

class ConfigError extends Error {
  readonly field: string;

  constructor(field: string, message: string) {
    super(message);
    this.field = field;
    this.name = "ConfigError";
  }
}

const DEFAULT_CONFIG_FILE = "x64dbg-mcp.config.json";
const DEFAULT_EVENT_QUEUE_LIMIT = 1000;
const DEFAULT_EVENTS = [
  "breakpoint",
  "system_breakpoint",
  "stop_debug",
  "create_process",
  "exit_process",
  "create_thread",
  "exit_thread",
  "load_dll",
  "unload_dll"
];

const parseString = (value: unknown, field: string): string | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new ConfigError(field, "Expected a string.");
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const parseNumber = (value: unknown, field: string): number | undefined => {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  throw new ConfigError(field, "Expected a number.");
};

const parseTransport = (
  value: unknown,
  field: string
): X64DbgTransport | undefined => {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new ConfigError(field, "Expected a string.");
  }
  const normalized = value.toLowerCase();
  if (normalized === "tcp" || normalized === "pipe" || normalized === "none") {
    return normalized;
  }
  throw new ConfigError(
    field,
    "Expected one of: tcp, pipe, none."
  );
};

const parseStringArray = (
  value: unknown,
  field: string
): string[] | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new ConfigError(field, "Expected an array of strings.");
  }
  return value.map((entry, index) => {
    if (typeof entry !== "string") {
      throw new ConfigError(`${field}[${index}]`, "Expected a string.");
    }
    return entry;
  });
};

const parseNumberArray = (
  value: unknown,
  field: string
): number[] | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new ConfigError(field, "Expected an array of numbers.");
  }
  return value.map((entry, index) => {
    const parsed = parseNumber(entry, `${field}[${index}]`);
    if (parsed === undefined) {
      throw new ConfigError(`${field}[${index}]`, "Expected a number.");
    }
    return parsed;
  });
};

const parseCsv = (value: string): string[] => {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return [];
  }
  return trimmed
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

const normalizeStringList = (values: string[]): string[] => {
  const normalized = values
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
  return Array.from(new Set(normalized));
};

const parseEnvStringList = (
  value: string | undefined
): string[] | undefined => {
  if (value === undefined) {
    return undefined;
  }
  return parseCsv(value);
};

const parseEnvNumberList = (
  value: string | undefined,
  field: string
): number[] | undefined => {
  if (value === undefined) {
    return undefined;
  }
  const entries = parseCsv(value);
  return entries.map((entry, index) => {
    const parsed = parseNumber(entry, `${field}[${index}]`);
    if (parsed === undefined) {
      throw new ConfigError(`${field}[${index}]`, "Expected a number.");
    }
    return parsed;
  });
};

const resolveConfigPath = (envPath?: string): string | undefined => {
  if (envPath) {
    return path.resolve(envPath);
  }
  const defaultPath = path.resolve(process.cwd(), DEFAULT_CONFIG_FILE);
  if (fs.existsSync(defaultPath)) {
    return defaultPath;
  }
  return undefined;
};

const readConfigFile = (
  configPath: string | undefined,
  required: boolean
): ConfigFile => {
  if (!configPath) {
    return {};
  }
  if (!fs.existsSync(configPath)) {
    if (required) {
      throw new ConfigError(
        "X64DBG_CONFIG",
        `Config file not found: ${configPath}`
      );
    }
    return {};
  }
  const contents = fs.readFileSync(configPath, "utf8");
  if (contents.trim().length === 0) {
    return {};
  }
  try {
    return JSON.parse(contents) as ConfigFile;
  } catch {
    throw new ConfigError(
      "configFile",
      `Invalid JSON in config file: ${configPath}`
    );
  }
};

const parseSecurityConfig = (
  env: NodeJS.ProcessEnv,
  fileConfig: ConfigFile
): SecurityConfig => {
  const fileSecurity = fileConfig.security ?? {};
  const allowPids =
    parseEnvNumberList(env.X64DBG_ALLOW_PIDS, "X64DBG_ALLOW_PIDS") ??
    parseNumberArray(fileSecurity.allowPids, "security.allowPids") ??
    [];
  const denyPids =
    parseEnvNumberList(env.X64DBG_DENY_PIDS, "X64DBG_DENY_PIDS") ??
    parseNumberArray(fileSecurity.denyPids, "security.denyPids") ??
    [];
  const allowNames =
    parseEnvStringList(env.X64DBG_ALLOW_NAMES) ??
    parseStringArray(fileSecurity.allowNames, "security.allowNames") ??
    [];
  const denyNames =
    parseEnvStringList(env.X64DBG_DENY_NAMES) ??
    parseStringArray(fileSecurity.denyNames, "security.denyNames") ??
    [];

  return normalizeSecurityConfig({
    ...defaultSecurityConfig(),
    allowPids,
    denyPids,
    allowNames,
    denyNames
  });
};

export const loadConfig = (env: NodeJS.ProcessEnv = process.env): ResolvedConfig => {
  const configPath = resolveConfigPath(env.X64DBG_CONFIG);
  const fileConfig = readConfigFile(configPath, env.X64DBG_CONFIG !== undefined);

  const host =
    parseString(env.X64DBG_HOST, "X64DBG_HOST") ??
    parseString(fileConfig.host, "host") ??
    "127.0.0.1";

  const port =
    parseNumber(env.X64DBG_PORT, "X64DBG_PORT") ??
    parseNumber(fileConfig.port, "port") ??
    0;

  const transport =
    parseTransport(env.X64DBG_TRANSPORT, "X64DBG_TRANSPORT") ??
    parseTransport(fileConfig.transport, "transport") ??
    (port > 0 ? "tcp" : "none");

  const pipeName =
    parseString(env.X64DBG_PIPE, "X64DBG_PIPE") ??
    parseString(fileConfig.pipeName, "pipeName");

  const connectTimeoutMs =
    parseNumber(env.X64DBG_CONNECT_TIMEOUT_MS, "X64DBG_CONNECT_TIMEOUT_MS") ??
    parseNumber(fileConfig.connectTimeoutMs, "connectTimeoutMs") ??
    2000;

  const requestTimeoutMs =
    parseNumber(env.X64DBG_REQUEST_TIMEOUT_MS, "X64DBG_REQUEST_TIMEOUT_MS") ??
    parseNumber(fileConfig.requestTimeoutMs, "requestTimeoutMs") ??
    3000;

  const retry: X64DbgRetryConfig = {
    retries:
      parseNumber(env.X64DBG_RETRY_COUNT, "X64DBG_RETRY_COUNT") ??
      parseNumber(fileConfig.retry?.retries, "retry.retries") ??
      2,
    backoffMs:
      parseNumber(env.X64DBG_RETRY_BACKOFF_MS, "X64DBG_RETRY_BACKOFF_MS") ??
      parseNumber(fileConfig.retry?.backoffMs, "retry.backoffMs") ??
      200,
    maxBackoffMs:
      parseNumber(
        env.X64DBG_RETRY_MAX_BACKOFF_MS,
        "X64DBG_RETRY_MAX_BACKOFF_MS"
      ) ??
      parseNumber(fileConfig.retry?.maxBackoffMs, "retry.maxBackoffMs") ??
      2000
  };

  const events = normalizeStringList(
    parseEnvStringList(env.X64DBG_EVENTS) ??
      parseStringArray(fileConfig.events, "events") ??
      DEFAULT_EVENTS
  );

  const eventQueueLimitRaw =
    parseNumber(
      env.X64DBG_EVENT_QUEUE_LIMIT,
      "X64DBG_EVENT_QUEUE_LIMIT"
    ) ??
    parseNumber(fileConfig.eventQueueLimit, "eventQueueLimit") ??
    DEFAULT_EVENT_QUEUE_LIMIT;
  const eventQueueLimit = Math.max(0, Math.floor(eventQueueLimitRaw));

  const security = parseSecurityConfig(env, fileConfig);

  return {
    client: {
      transport,
      host,
      port,
      pipeName,
      connectTimeoutMs,
      requestTimeoutMs,
      retry
    },
    security,
    events,
    eventQueueLimit,
    configFile: configPath
  };
};

export const isConfigError = (error: unknown): error is ConfigError =>
  error instanceof ConfigError;
