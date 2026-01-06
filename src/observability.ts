import process from "node:process";

export type LogLevel = "debug" | "info" | "warn" | "error";

export type LogConfig = {
  level: LogLevel;
  redactKeys: string[];
};

export type Logger = {
  debug: (message: string, data?: unknown) => void;
  info: (message: string, data?: unknown) => void;
  warn: (message: string, data?: unknown) => void;
  error: (message: string, data?: unknown) => void;
};

export type MetricsSnapshot = {
  connectAttempts: number;
  connectFailures: number;
  connectSuccesses: number;
  requestCount: number;
  requestFailures: number;
  requestTimeouts: number;
  inflightRequests: number;
  eventCount: number;
  eventDropped: number;
  lastLatencyMs?: number;
  avgLatencyMs?: number;
};

const DEFAULT_LOG_LEVEL: LogLevel = "info";
const DEFAULT_REDACT_KEYS = ["data", "payload", "bytes", "content", "script"];

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

const parseCsv = (value: string): string[] =>
  value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

const parseLogLevel = (value: string | undefined): LogLevel => {
  if (!value) {
    return DEFAULT_LOG_LEVEL;
  }
  const normalized = value.toLowerCase();
  if (normalized === "debug" || normalized === "info" || normalized === "warn" || normalized === "error") {
    return normalized;
  }
  return DEFAULT_LOG_LEVEL;
};

export const loadLogConfig = (
  env: NodeJS.ProcessEnv = process.env
): LogConfig => {
  const level = parseLogLevel(env.X64DBG_LOG_LEVEL);
  const redactKeys = env.X64DBG_LOG_REDACT
    ? parseCsv(env.X64DBG_LOG_REDACT).map((entry) => entry.toLowerCase())
    : DEFAULT_REDACT_KEYS;
  return { level, redactKeys };
};

export const createNoopLogger = (): Logger => ({
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {}
});

class JsonLogger implements Logger {
  private readonly levelValue: number;
  private readonly redactKeys: Set<string>;

  constructor(config: LogConfig) {
    this.levelValue = LOG_LEVELS[config.level];
    this.redactKeys = new Set(config.redactKeys.map((entry) => entry.toLowerCase()));
  }

  debug(message: string, data?: unknown): void {
    this.emit("debug", message, data);
  }

  info(message: string, data?: unknown): void {
    this.emit("info", message, data);
  }

  warn(message: string, data?: unknown): void {
    this.emit("warn", message, data);
  }

  error(message: string, data?: unknown): void {
    this.emit("error", message, data);
  }

  private emit(level: LogLevel, message: string, data?: unknown): void {
    if (LOG_LEVELS[level] < this.levelValue) {
      return;
    }
    const payload: Record<string, unknown> = {
      ts: new Date().toISOString(),
      level,
      msg: message
    };
    if (data !== undefined) {
      payload.data = data;
    }
    const serialized = this.serialize(payload);
    process.stderr.write(serialized + "\n");
  }

  private serialize(payload: Record<string, unknown>): string {
    const seen = new WeakSet();
    try {
      return JSON.stringify(payload, (key, value) => {
        if (key && this.redactKeys.has(key.toLowerCase())) {
          return "[REDACTED]";
        }
        if (typeof value === "object" && value !== null) {
          if (seen.has(value)) {
            return "[Circular]";
          }
          seen.add(value);
        }
        return value;
      });
    } catch (error) {
      return JSON.stringify({
        ts: new Date().toISOString(),
        level: "error",
        msg: "Failed to serialize log entry.",
        data: { error: String(error) }
      });
    }
  }
}

export const createLoggerFromEnv = (
  env: NodeJS.ProcessEnv = process.env
): Logger => new JsonLogger(loadLogConfig(env));

export class MetricsCollector {
  private connectAttempts = 0;
  private connectFailures = 0;
  private connectSuccesses = 0;
  private requestCount = 0;
  private requestFailures = 0;
  private requestTimeouts = 0;
  private inflightRequests = 0;
  private eventCount = 0;
  private eventDropped = 0;
  private latencyTotalMs = 0;
  private latencySamples = 0;
  private lastLatencyMs?: number;

  recordConnectAttempt(): void {
    this.connectAttempts += 1;
  }

  recordConnectFailure(): void {
    this.connectFailures += 1;
  }

  recordConnectSuccess(): void {
    this.connectSuccesses += 1;
  }

  recordRequestStart(): number {
    this.requestCount += 1;
    this.inflightRequests += 1;
    return Date.now();
  }

  recordRequestSuccess(startedAt: number): number {
    return this.finishRequest(startedAt, null);
  }

  recordRequestFailure(
    startedAt: number,
    reason: "timeout" | "connection" | "remote" | "protocol"
  ): number {
    this.requestFailures += 1;
    if (reason === "timeout") {
      this.requestTimeouts += 1;
    }
    return this.finishRequest(startedAt, reason);
  }

  snapshot(): MetricsSnapshot {
    return {
      connectAttempts: this.connectAttempts,
      connectFailures: this.connectFailures,
      connectSuccesses: this.connectSuccesses,
      requestCount: this.requestCount,
      requestFailures: this.requestFailures,
      requestTimeouts: this.requestTimeouts,
      inflightRequests: this.inflightRequests,
      eventCount: this.eventCount,
      eventDropped: this.eventDropped,
      lastLatencyMs: this.lastLatencyMs,
      avgLatencyMs: this.latencySamples
        ? Math.round(this.latencyTotalMs / this.latencySamples)
        : undefined
    };
  }

  recordEvent(): void {
    this.eventCount += 1;
  }

  recordEventDrop(count = 1): void {
    this.eventDropped += count;
  }

  private finishRequest(
    startedAt: number,
    _reason: string | null
  ): number {
    this.inflightRequests = Math.max(0, this.inflightRequests - 1);
    const durationMs = Math.max(0, Date.now() - startedAt);
    this.lastLatencyMs = durationMs;
    this.latencyTotalMs += durationMs;
    this.latencySamples += 1;
    return durationMs;
  }
}
