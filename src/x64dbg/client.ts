import { randomUUID } from "node:crypto";
import { createConnection, Socket } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

import {
  createNoopLogger,
  MetricsCollector,
  type Logger
} from "../observability.js";
import {
  isX64DbgEvent,
  isX64DbgResponse,
  type X64DbgEvent,
  type X64DbgProtocolError,
  type X64DbgRequest,
  type X64DbgResponse
} from "./protocol.js";

export type X64DbgTransport = "none" | "tcp" | "pipe";

export type X64DbgRetryConfig = {
  retries: number;
  backoffMs: number;
  maxBackoffMs: number;
};

export type X64DbgClientConfig = {
  transport: X64DbgTransport;
  host: string;
  port: number;
  pipeName?: string;
  connectTimeoutMs: number;
  requestTimeoutMs: number;
  retry: X64DbgRetryConfig;
};

export type X64DbgClientOptions = {
  logger?: Logger;
  metrics?: MetricsCollector;
  eventConfig?: {
    events?: string[];
    queueLimit?: number;
  };
};

export type X64DbgStatus = {
  connected: boolean;
  connecting: boolean;
  transport: X64DbgTransport;
  pendingRequests: number;
  eventQueueSize: number;
  eventsConfigured: boolean;
  message?: string;
};

export type X64DbgStepType = "into" | "over" | "out";

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
  method: string;
  startedAt: number;
};

export type X64DbgErrorCode =
  | "timeout"
  | "connection"
  | "protocol"
  | "remote"
  | "shutdown";

export class X64DbgClientError extends Error {
  readonly code: X64DbgErrorCode;
  readonly data?: unknown;

  constructor(code: X64DbgErrorCode, message: string, data?: unknown) {
    super(message);
    this.code = code;
    this.data = data;
  }
}

export const isX64DbgClientError = (
  error: unknown
): error is X64DbgClientError =>
  error instanceof X64DbgClientError;

const isRetryable = (error: Error): boolean => {
  if (error instanceof X64DbgClientError) {
    return error.code === "timeout" || error.code === "connection";
  }
  return false;
};

const coerceError = (error: unknown, code: X64DbgErrorCode): X64DbgClientError => {
  if (error instanceof X64DbgClientError) {
    return error;
  }
  if (error instanceof Error) {
    return new X64DbgClientError(code, error.message);
  }
  return new X64DbgClientError(code, "Unknown error");
};

const normalizeEvents = (events: string[]): string[] => {
  const normalized = events
    .map((event) => event.trim().toLowerCase())
    .filter((event) => event.length > 0);
  return Array.from(new Set(normalized));
};

export class X64DbgClient {
  private readonly config: X64DbgClientConfig;
  private readonly logger: Logger;
  private readonly metrics: MetricsCollector;
  private readonly eventQueueLimit: number;
  private desiredEvents: string[];
  private eventsConfigured = false;
  private eventQueue: X64DbgEvent[] = [];
  private droppedEvents = 0;
  private socket: Socket | null = null;
  private buffer = "";
  private pending = new Map<string, PendingRequest>();
  private connected = false;
  private connecting = false;
  private lastMessage: string | null = "Not connected";
  private connectPromise: Promise<void> | null = null;
  private shutdownRequested = false;

  constructor(config: X64DbgClientConfig, options: X64DbgClientOptions = {}) {
    this.config = config;
    this.logger = options.logger ?? createNoopLogger();
    this.metrics = options.metrics ?? new MetricsCollector();
    const eventConfig = options.eventConfig ?? {};
    this.desiredEvents = normalizeEvents(eventConfig.events ?? []);
    const queueLimit = eventConfig.queueLimit ?? 1000;
    this.eventQueueLimit = Number.isFinite(queueLimit)
      ? Math.max(0, queueLimit)
      : 1000;
  }

  async connect(): Promise<void> {
    if (this.shutdownRequested) {
      throw new X64DbgClientError("shutdown", "Client is shut down.");
    }
    if (this.connected) {
      return;
    }
    if (this.connectPromise) {
      return this.connectPromise;
    }
    this.connectPromise = this.connectWithRetry();
    try {
      await this.connectPromise;
    } finally {
      this.connectPromise = null;
    }
  }

  async reconnect(): Promise<void> {
    if (this.shutdownRequested) {
      throw new X64DbgClientError("shutdown", "Client is shut down.");
    }
    await this.disconnect();
    await this.connect();
  }

  async disconnect(): Promise<void> {
    this.cleanupSocket("Disconnected");
  }

  async shutdown(): Promise<void> {
    this.shutdownRequested = true;
    this.cleanupSocket("Shutdown requested");
  }

  async attach(pid: number): Promise<unknown> {
    return this.request("debug.attach", { pid });
  }

  async detach(): Promise<unknown> {
    return this.request("debug.detach");
  }

  async pause(): Promise<unknown> {
    return this.request("debug.pause");
  }

  async step(type: X64DbgStepType): Promise<unknown> {
    return this.request("debug.step", { type });
  }

  async readMemory(address: string, length: number): Promise<unknown> {
    return this.request("memory.read", { address, length });
  }

  async writeMemory(
    address: string,
    data: string,
    encoding?: "hex" | "base64"
  ): Promise<unknown> {
    return this.request("memory.write", { address, data, encoding });
  }

  async listModules(): Promise<unknown> {
    return this.request("debug.listModules");
  }

  async listThreads(): Promise<unknown> {
    return this.request("debug.listThreads");
  }

  async listRegisters(scope?: string): Promise<unknown> {
    return this.request("debug.listRegisters", scope ? { scope } : undefined);
  }

  async setBreakpoint(options: {
    address: string;
    type?: "software" | "hardware";
    enabled?: boolean;
    temporary?: boolean;
    size?: number;
  }): Promise<unknown> {
    return this.request("debug.setBreakpoint", options);
  }

  async execCommand(
    command: string,
    mode?: "direct" | "async",
    captureOutput?: boolean
  ): Promise<unknown> {
    if (captureOutput) {
      return this.request("debug.execOutput", { command });
    }
    return this.request("debug.exec", { command, mode });
  }

  async evalExpression(expression: string): Promise<unknown> {
    return this.request("debug.eval", { expression });
  }

  async disasm(
    address: string,
    count?: number,
    detail?: boolean
  ): Promise<unknown> {
    return this.request("debug.disasm", { address, count, detail });
  }

  async getXrefs(address: string): Promise<unknown> {
    return this.request("debug.xrefs", { address });
  }

  async getMemoryMap(): Promise<unknown> {
    return this.request("debug.memmap");
  }

  async searchMemory(options: {
    address: string;
    length: number;
    pattern: string;
    encoding?: "hex" | "base64" | "ascii" | "utf16";
    maxResults?: number;
  }): Promise<unknown> {
    return this.request("memory.search", options as Record<string, unknown>);
  }

  async getCallStack(depth?: number): Promise<unknown> {
    return this.request("debug.callstack", depth ? { depth } : undefined);
  }

  async logTail(max?: number): Promise<unknown> {
    return this.request("debug.logTail", max ? { max } : undefined);
  }

  async logWrite(message: string): Promise<unknown> {
    return this.request("debug.logWrite", { message });
  }

  async guiGraphAt(address: string): Promise<unknown> {
    return this.request("gui.graph_at", { address });
  }

  async guiShowReferences(address: string): Promise<unknown> {
    return this.request("gui.show_references", { address });
  }

  async guiCurrentGraph(): Promise<unknown> {
    return this.request("gui.current_graph");
  }

  async getStatus(): Promise<X64DbgStatus> {
    return {
      connected: this.connected,
      connecting: this.connecting,
      transport: this.config.transport,
      pendingRequests: this.pending.size,
      eventQueueSize: this.eventQueue.length,
      eventsConfigured: this.eventsConfigured,
      message: this.lastMessage ?? undefined
    };
  }

  getConfig(): X64DbgClientConfig {
    return this.config;
  }

  getMetrics() {
    return this.metrics.snapshot();
  }

  getEventConfig() {
    return {
      events: [...this.desiredEvents],
      configured: this.eventsConfigured,
      queueLimit: this.eventQueueLimit,
      queued: this.eventQueue.length,
      dropped: this.droppedEvents
    };
  }

  async configureEvents(events: string[]): Promise<unknown> {
    this.desiredEvents = normalizeEvents(events);
    this.eventsConfigured = false;
    if (!this.connected) {
      await this.connect();
    }
    if (this.eventsConfigured) {
      return { events: [...this.desiredEvents] };
    }
    return this.sendEventConfig();
  }

  drainEvents(max = 50) {
    const limit = Number.isFinite(max) ? Math.max(0, Math.floor(max)) : 0;
    const events = limit
      ? this.eventQueue.splice(0, limit)
      : [];
    const dropped = this.droppedEvents;
    this.droppedEvents = 0;
    return {
      events,
      dropped,
      remaining: this.eventQueue.length,
      limit: this.eventQueueLimit
    };
  }

  private async request(
    method: string,
    params?: Record<string, unknown>
  ): Promise<unknown> {
    if (this.shutdownRequested) {
      throw new X64DbgClientError("shutdown", "Client is shut down.");
    }
    const attempts = Math.max(0, this.config.retry.retries) + 1;
    let attempt = 0;
    while (attempt < attempts) {
      attempt += 1;
      try {
        await this.connect();
        return await this.sendOnce(method, params);
      } catch (error) {
        const normalized = coerceError(error, "connection");
        this.lastMessage = normalized.message;
        if (!isRetryable(normalized) || attempt >= attempts) {
          throw normalized;
        }
        this.cleanupSocket("Retrying after failure");
        await delay(this.backoffDelay(attempt));
      }
    }
    throw new X64DbgClientError("connection", "Failed to send request.");
  }

  private async connectWithRetry(): Promise<void> {
    const attempts = Math.max(0, this.config.retry.retries) + 1;
    let attempt = 0;
    while (attempt < attempts) {
      attempt += 1;
      this.metrics.recordConnectAttempt();
      this.logger.debug("bridge.connect.attempt", {
        attempt,
        transport: this.config.transport
      });
      try {
        await this.connectOnce();
        this.metrics.recordConnectSuccess();
        this.logger.info("bridge.connect.success", {
          transport: this.config.transport
        });
        return;
      } catch (error) {
        const normalized = coerceError(error, "connection");
        this.lastMessage = normalized.message;
        this.metrics.recordConnectFailure();
        this.logger.warn("bridge.connect.failure", {
          attempt,
          message: normalized.message
        });
        if (!isRetryable(normalized) || attempt >= attempts) {
          throw normalized;
        }
        await delay(this.backoffDelay(attempt));
      }
    }
    throw new X64DbgClientError("connection", "Failed to connect.");
  }

  private async connectOnce(): Promise<void> {
    if (this.config.transport === "none") {
      throw new X64DbgClientError(
        "connection",
        "Transport not configured (set X64DBG_TRANSPORT and connection params)."
      );
    }
    if (this.config.transport === "tcp" && this.config.port <= 0) {
      throw new X64DbgClientError(
        "connection",
        "TCP transport requires a non-zero port."
      );
    }
    if (this.config.transport === "pipe" && !this.config.pipeName) {
      throw new X64DbgClientError(
        "connection",
        "Pipe transport requires X64DBG_PIPE to be set."
      );
    }

    this.connecting = true;
    this.lastMessage = "Connecting...";

    const socket = this.createSocket();
    this.socket = socket;
    this.buffer = "";

    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (settled) {
          return;
        }
        settled = true;
        socket.destroy();
        reject(new X64DbgClientError("timeout", "Connection timed out."));
      }, Math.max(100, this.config.connectTimeoutMs));

      const cleanup = (): void => {
        clearTimeout(timeout);
        socket.removeListener("error", onError);
        socket.removeListener("connect", onConnect);
      };

      const onError = (error: Error): void => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        socket.destroy();
        reject(new X64DbgClientError("connection", error.message));
      };

      const onConnect = (): void => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        socket.on("data", (data) => this.handleData(data));
        socket.on("error", (error) => this.handleSocketError(error));
        socket.on("close", () => this.handleSocketClose());
        socket.setNoDelay(true);
        this.connected = true;
        this.lastMessage = "Connected";
        resolve();
        void this.applyEventConfig();
      };

      socket.once("error", onError);
      socket.once("connect", onConnect);
    }).finally(() => {
      this.connecting = false;
    });
  }

  private async applyEventConfig(): Promise<void> {
    if (!this.connected || !this.socket) {
      return;
    }
    if (this.eventsConfigured) {
      return;
    }
    try {
      await this.sendEventConfig();
    } catch (error) {
      this.eventsConfigured = false;
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn("bridge.events.configure_failed", { message });
    }
  }

  private async sendEventConfig(): Promise<unknown> {
    if (!this.connected || !this.socket) {
      throw new X64DbgClientError("connection", "Not connected.");
    }
    const result = await this.sendOnce("event.configure", {
      events: this.desiredEvents
    });
    this.eventsConfigured = true;
    this.logger.info("bridge.events.configured", {
      events: this.desiredEvents,
      result
    });
    return result;
  }

  private createSocket(): Socket {
    if (this.config.transport === "pipe") {
      const pipePath = this.normalizePipeName(this.config.pipeName ?? "");
      return createConnection({ path: pipePath });
    }
    return createConnection({
      host: this.config.host,
      port: this.config.port
    });
  }

  private normalizePipeName(pipeName: string): string {
    if (pipeName.startsWith("\\\\")) {
      return pipeName;
    }
    return `\\\\.\\pipe\\${pipeName}`;
  }

  private handleData(data: Buffer): void {
    this.buffer += data.toString("utf8");
    while (true) {
      const newlineIndex = this.buffer.indexOf("\n");
      if (newlineIndex === -1) {
        break;
      }
      const line = this.buffer.slice(0, newlineIndex).trim();
      this.buffer = this.buffer.slice(newlineIndex + 1);
      if (!line) {
        continue;
      }
      this.handleLine(line);
    }
  }

  private handleLine(line: string): void {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch (error) {
      const normalized = coerceError(error, "protocol");
      this.lastMessage = `Protocol error: ${normalized.message}`;
      this.logger.warn("bridge.protocol.invalid_json", {
        message: normalized.message
      });
      return;
    }
    if (isX64DbgEvent(message)) {
      this.handleEvent(message as X64DbgEvent);
      return;
    }
    if (!isX64DbgResponse(message)) {
      this.lastMessage = "Protocol error: unexpected message shape.";
      this.logger.warn("bridge.protocol.invalid_shape");
      return;
    }
    const response = message as X64DbgResponse;
    const pending = this.pending.get(response.id);
    if (!pending) {
      this.logger.debug("bridge.response.orphan", { id: response.id });
      return;
    }
    clearTimeout(pending.timeout);
    this.pending.delete(response.id);
    if (response.ok) {
      const durationMs = this.metrics.recordRequestSuccess(pending.startedAt);
      this.logger.debug("bridge.response", {
        id: response.id,
        method: pending.method,
        ok: true,
        durationMs
      });
      pending.resolve(response.result);
      return;
    }
    const error = response.error;
    const durationMs = this.metrics.recordRequestFailure(
      pending.startedAt,
      "remote"
    );
    this.logger.warn("bridge.response", {
      id: response.id,
      method: pending.method,
      ok: false,
      durationMs,
      error: error?.message
    });
    pending.reject(this.toRemoteError(error));
  }

  private handleEvent(event: X64DbgEvent): void {
    this.enqueueEvent(event);
    this.logger.debug("bridge.event", { event: event.event });
  }

  private enqueueEvent(event: X64DbgEvent): void {
    this.metrics.recordEvent();
    if (this.eventQueueLimit === 0) {
      this.metrics.recordEventDrop();
      this.droppedEvents += 1;
      return;
    }
    if (this.eventQueue.length >= this.eventQueueLimit) {
      const dropCount = this.eventQueue.length - this.eventQueueLimit + 1;
      this.eventQueue.splice(0, dropCount);
      this.metrics.recordEventDrop(dropCount);
      this.droppedEvents += dropCount;
      this.logger.warn("bridge.event.dropped", {
        dropCount,
        limit: this.eventQueueLimit
      });
    }
    this.eventQueue.push(event);
  }

  private toRemoteError(error?: X64DbgProtocolError): X64DbgClientError {
    if (!error) {
      return new X64DbgClientError("remote", "Remote error.");
    }
    return new X64DbgClientError("remote", error.message, error);
  }

  private handleSocketError(error: Error): void {
    this.lastMessage = error.message;
    this.logger.warn("bridge.socket.error", { message: error.message });
    this.cleanupSocket("Socket error");
  }

  private handleSocketClose(): void {
    this.logger.warn("bridge.socket.closed");
    this.cleanupSocket("Connection closed");
  }

  private cleanupSocket(message: string): void {
    if (this.socket) {
      this.socket.removeAllListeners();
      this.socket.destroy();
      this.socket = null;
    }
    this.connected = false;
    this.connecting = false;
    this.lastMessage = message;
    this.eventsConfigured = false;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      this.metrics.recordRequestFailure(pending.startedAt, "connection");
      pending.reject(new X64DbgClientError("connection", message));
    }
    this.pending.clear();
    this.buffer = "";
    this.eventQueue = [];
    this.droppedEvents = 0;
  }

  private async sendOnce(
    method: string,
    params?: Record<string, unknown>
  ): Promise<unknown> {
    if (!this.socket || !this.connected) {
      throw new X64DbgClientError("connection", "Not connected.");
    }

    const request: X64DbgRequest = {
      id: randomUUID(),
      method,
      params
    };
    const payload = JSON.stringify(request);
    if (payload.includes("\n")) {
      throw new X64DbgClientError(
        "protocol",
        "Request payload contains a newline."
      );
    }

    return new Promise<unknown>((resolve, reject) => {
      const startedAt = this.metrics.recordRequestStart();
      this.logger.debug("bridge.request.send", {
        id: request.id,
        method,
        params
      });
      const timeout = setTimeout(() => {
        this.pending.delete(request.id);
        const durationMs = this.metrics.recordRequestFailure(
          startedAt,
          "timeout"
        );
        this.logger.warn("bridge.request.timeout", {
          id: request.id,
          method,
          durationMs
        });
        reject(new X64DbgClientError("timeout", "Request timed out."));
      }, Math.max(100, this.config.requestTimeoutMs));

      this.pending.set(request.id, {
        resolve,
        reject,
        timeout,
        method,
        startedAt
      });

      this.socket?.write(`${payload}\n`, "utf8", (error) => {
        if (!error) {
          return;
        }
        clearTimeout(timeout);
        this.pending.delete(request.id);
        const durationMs = this.metrics.recordRequestFailure(
          startedAt,
          "connection"
        );
        this.logger.warn("bridge.request.write_failed", {
          id: request.id,
          method,
          durationMs,
          message: error.message
        });
        reject(new X64DbgClientError("connection", error.message));
      });
    });
  }

  private backoffDelay(attempt: number): number {
    const base = Math.max(0, this.config.retry.backoffMs);
    const max = Math.max(base, this.config.retry.maxBackoffMs);
    const expo = base * Math.pow(2, Math.max(0, attempt - 1));
    return Math.min(expo, max);
  }
}
