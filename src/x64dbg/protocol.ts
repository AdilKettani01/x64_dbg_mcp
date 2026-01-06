export type X64DbgRequest = {
  id: string;
  method: string;
  params?: Record<string, unknown>;
};

export type X64DbgProtocolError = {
  message: string;
  code?: string;
  data?: unknown;
};

export type X64DbgResponse = {
  id: string;
  ok: boolean;
  result?: unknown;
  error?: X64DbgProtocolError;
};

export const X64DBG_EVENT_TYPES = [
  "stop_debug",
  "breakpoint",
  "create_process",
  "exit_process",
  "create_thread",
  "exit_thread",
  "system_breakpoint",
  "load_dll",
  "unload_dll",
  "trace_execute"
] as const;

export type X64DbgEvent = {
  event: string;
  data?: Record<string, unknown>;
  ts?: number;
};

export const PROTOCOL_DOC = [
  "x64dbg bridge protocol (NDJSON):",
  "- Each message is a single JSON object terminated by '\\n'.",
  "- Requests: { id, method, params? }",
  "- Responses: { id, ok, result?, error? }",
  "- Events: { event, data?, ts? } (async messages from bridge)",
  "- Event config request: method = event.configure, params = { events: string[] }",
  "- Common methods: debug.disasm, debug.xrefs, memory.search, debug.memmap, debug.callstack, debug.logTail, debug.execOutput, gui.graph_at, gui.show_references, gui.current_graph"
].join("\n");

export const isX64DbgResponse = (value: unknown): value is X64DbgResponse => {
  if (!value || typeof value !== "object") {
    return false;
  }
  const record = value as Record<string, unknown>;
  return typeof record.id === "string" && typeof record.ok === "boolean";
};

export const isX64DbgEvent = (value: unknown): value is X64DbgEvent => {
  if (!value || typeof value !== "object") {
    return false;
  }
  const record = value as Record<string, unknown>;
  return typeof record.event === "string";
};
