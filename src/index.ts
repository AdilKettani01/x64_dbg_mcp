import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  type Resource,
  type Tool
} from "@modelcontextprotocol/sdk/types.js";

import { buildCfg, buildXrefGraph } from "./analysis/graphs.js";
import { loadConfig } from "./config.js";
import { createLoggerFromEnv, MetricsCollector } from "./observability.js";
import { assertAttachAllowed, SecurityError } from "./security.js";
import { X64DbgClient, isX64DbgClientError } from "./x64dbg/client.js";
import { PROTOCOL_DOC, X64DBG_EVENT_TYPES } from "./x64dbg/protocol.js";

class InputError extends Error {
  readonly field: string;

  constructor(field: string, message: string) {
    super(message);
    this.field = field;
    this.name = "InputError";
  }
}

const MAX_DISASM_COUNT = 200;
const MAX_SEARCH_BYTES = 16 * 1024 * 1024;
const MAX_SEARCH_RESULTS = 200;
const MAX_STACK_DEPTH = 128;
const MAX_LOG_LINES = 500;
const DEFAULT_DISASM_COUNT = 16;
const DEFAULT_STACK_DEPTH = 32;
const DEFAULT_LOG_TAIL = 50;
const DEFAULT_SEARCH_RESULTS = 20;
const MAX_CFG_BLOCKS = 200;
const MAX_CFG_INSTRUCTIONS = 2000;
const MAX_CFG_BLOCK_INSTRUCTIONS = 128;
const MAX_CFG_DEPTH = 64;
const DEFAULT_CFG_BLOCKS = 64;
const DEFAULT_CFG_INSTRUCTIONS = 1000;
const DEFAULT_CFG_BLOCK_INSTRUCTIONS = 64;
const DEFAULT_CFG_DEPTH = 16;
const MAX_XREF_DEPTH = 4;
const MAX_XREF_NODES = 400;
const MAX_XREF_EDGES = 800;
const DEFAULT_XREF_DEPTH = 1;
const DEFAULT_XREF_NODES = 200;
const DEFAULT_XREF_EDGES = 400;

const asRecord = (value: unknown): Record<string, unknown> => {
  if (value === undefined) {
    return {};
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InputError("arguments", "Expected an object.");
  }
  return value as Record<string, unknown>;
};

const requireString = (value: unknown, field: string): string => {
  if (typeof value !== "string" || value.trim() === "") {
    throw new InputError(field, "Expected a non-empty string.");
  }
  return value;
};

const optionalString = (value: unknown, field: string): string | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new InputError(field, "Expected a string.");
  }
  return value;
};

const toNumber = (value: unknown, field: string): number => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  throw new InputError(field, "Expected a number.");
};

const toInteger = (
  value: unknown,
  field: string,
  min?: number
): number => {
  const num = toNumber(value, field);
  if (!Number.isInteger(num)) {
    throw new InputError(field, "Expected an integer.");
  }
  if (min !== undefined && num < min) {
    throw new InputError(field, `Expected an integer >= ${min}.`);
  }
  return num;
};

const toIntegerInRange = (
  value: unknown,
  field: string,
  min: number,
  max: number
): number => {
  const num = toInteger(value, field, min);
  if (num > max) {
    throw new InputError(field, `Expected an integer <= ${max}.`);
  }
  return num;
};

const optionalIntegerInRange = (
  value: unknown,
  field: string,
  min: number,
  max: number
): number | undefined => {
  if (value === undefined) {
    return undefined;
  }
  return toIntegerInRange(value, field, min, max);
};

const toStringArray = (value: unknown, field: string): string[] => {
  if (!Array.isArray(value)) {
    throw new InputError(field, "Expected an array.");
  }
  return value.map((entry, index) => {
    if (typeof entry !== "string") {
      throw new InputError(`${field}[${index}]`, "Expected a string.");
    }
    return entry;
  });
};

const normalizeEventList = (events: string[]): string[] => {
  const normalized = events
    .map((event) => event.trim().toLowerCase())
    .filter((event) => event.length > 0);
  return Array.from(new Set(normalized));
};

const EVENT_TYPE_SET = new Set<string>(X64DBG_EVENT_TYPES);

const optionalBoolean = (
  value: unknown,
  field: string
): boolean | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "boolean") {
    throw new InputError(field, "Expected a boolean.");
  }
  return value;
};

const optionalEnum = <T extends string>(
  value: unknown,
  field: string,
  allowed: readonly T[]
): T | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new InputError(field, `Expected one of: ${allowed.join(", ")}.`);
  }
  return value as T;
};

const requiredEnum = <T extends string>(
  value: unknown,
  field: string,
  allowed: readonly T[]
): T => {
  const parsed = optionalEnum(value, field, allowed);
  if (!parsed) {
    throw new InputError(field, "Expected a value.");
  }
  return parsed;
};

const parseAddressInput = async (
  value: unknown,
  field: string
): Promise<number> => {
  const text = requireString(value, field);
  const parsed = Number.parseInt(text, 0);
  if (Number.isFinite(parsed)) {
    return parsed;
  }
  const evalResult = await client.evalExpression(text);
  const resolved = Number((evalResult as { value?: number }).value);
  if (!Number.isFinite(resolved)) {
    throw new InputError(field, "Expected an address or expression.");
  }
  return resolved;
};

const serverConfig = loadConfig();
const logger = createLoggerFromEnv();
const metrics = new MetricsCollector();
const client = new X64DbgClient(serverConfig.client, {
  logger,
  metrics,
  eventConfig: {
    events: serverConfig.events,
    queueLimit: serverConfig.eventQueueLimit
  }
});

const getConfigSnapshot = () => ({
  client: client.getConfig(),
  security: serverConfig.security,
  events: serverConfig.events,
  eventQueueLimit: serverConfig.eventQueueLimit,
  configFile: serverConfig.configFile
});

const extractAttachPid = (command: string): number | null => {
  const trimmed = command.trim();
  const match = /^attach\s+(\d+)/i.exec(trimmed);
  if (!match) {
    return null;
  }
  const parsed = Number.parseInt(match[1], 10);
  return Number.isFinite(parsed) ? parsed : null;
};

logger.info("server.start", { config: getConfigSnapshot() });

const baseOutputSchema: Tool["outputSchema"] = {
  type: "object",
  properties: {
    ok: { type: "boolean" },
    result: {},
    error: {}
  },
  required: ["ok"]
};

const noArgsSchema: Tool["inputSchema"] = {
  type: "object",
  properties: {},
  additionalProperties: false
};

const tools: Tool[] = [
  {
    name: "ping",
    description: "Health check for the MCP server.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_status",
    description: "Get the current x64dbg bridge status.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_metrics",
    description: "Get current bridge metrics (connect failures, latency).",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_subscribe_events",
    description: "Configure which x64dbg debug events are streamed.",
    inputSchema: {
      type: "object",
      properties: {
        events: {
          type: "array",
          items: { type: "string" }
        },
        clearQueue: { type: "boolean" }
      },
      required: ["events"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_poll_events",
    description: "Fetch queued x64dbg debug events.",
    inputSchema: {
      type: "object",
      properties: {
        max: { type: "integer", minimum: 1 }
      },
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_connect",
    description: "Connect to the configured x64dbg bridge.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_reconnect",
    description: "Reconnect to the configured x64dbg bridge.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_disconnect",
    description: "Disconnect from the configured x64dbg bridge.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_shutdown",
    description: "Shutdown the bridge client and stop reconnect attempts.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_attach",
    description: "Attach the debugger to a process by PID.",
    inputSchema: {
      type: "object",
      properties: {
        pid: { type: "integer", minimum: 1 }
      },
      required: ["pid"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_detach",
    description: "Detach the debugger from the current process.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_pause",
    description: "Pause the debuggee execution.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_step",
    description: "Step the debugger (into/over/out).",
    inputSchema: {
      type: "object",
      properties: {
        type: { type: "string", enum: ["into", "over", "out"] }
      },
      required: ["type"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_read_memory",
    description: "Read memory from the debuggee.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        length: { type: "integer", minimum: 1 }
      },
      required: ["address", "length"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_write_memory",
    description: "Write memory to the debuggee.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        data: { type: "string" },
        encoding: { type: "string", enum: ["hex", "base64"] }
      },
      required: ["address", "data"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_disasm",
    description: "Disassemble instructions starting at an address.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        count: { type: "integer", minimum: 1, maximum: MAX_DISASM_COUNT },
        detail: { type: "boolean" }
      },
      required: ["address"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_cfg",
    description: "Build a lightweight control-flow graph from disassembly.",
    inputSchema: {
      type: "object",
      properties: {
        entry: { type: "string" },
        maxBlocks: { type: "integer", minimum: 1, maximum: MAX_CFG_BLOCKS },
        maxInstructions: {
          type: "integer",
          minimum: 1,
          maximum: MAX_CFG_INSTRUCTIONS
        },
        maxBlockInstructions: {
          type: "integer",
          minimum: 1,
          maximum: MAX_CFG_BLOCK_INSTRUCTIONS
        },
        maxDepth: { type: "integer", minimum: 0, maximum: MAX_CFG_DEPTH }
      },
      required: ["entry"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_xrefs",
    description: "Fetch cross-references to the given address.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" }
      },
      required: ["address"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_xref_graph",
    description: "Build an xref graph rooted at an address.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        depth: { type: "integer", minimum: 0, maximum: MAX_XREF_DEPTH },
        maxNodes: { type: "integer", minimum: 1, maximum: MAX_XREF_NODES },
        maxEdges: { type: "integer", minimum: 1, maximum: MAX_XREF_EDGES }
      },
      required: ["address"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_search_memory",
    description: "Search memory for a byte pattern.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        length: { type: "integer", minimum: 1, maximum: MAX_SEARCH_BYTES },
        pattern: { type: "string" },
        encoding: { type: "string", enum: ["hex", "base64", "ascii", "utf16"] },
        maxResults: {
          type: "integer",
          minimum: 1,
          maximum: MAX_SEARCH_RESULTS
        }
      },
      required: ["address", "length", "pattern"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_memory_map",
    description: "Get the current memory map.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_call_stack",
    description: "Get a stack snapshot of potential return addresses.",
    inputSchema: {
      type: "object",
      properties: {
        depth: { type: "integer", minimum: 1, maximum: MAX_STACK_DEPTH }
      },
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_log_tail",
    description: "Read recent bridge log entries.",
    inputSchema: {
      type: "object",
      properties: {
        max: { type: "integer", minimum: 1, maximum: MAX_LOG_LINES }
      },
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_log_write",
    description: "Write a message to the x64dbg GUI log.",
    inputSchema: {
      type: "object",
      properties: {
        message: { type: "string" }
      },
      required: ["message"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_gui_graph_at",
    description: "Open the graph view at the given address (native plugin).",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" }
      },
      required: ["address"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_gui_show_references",
    description: "Open the references view for the given address (native plugin).",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" }
      },
      required: ["address"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_gui_current_graph",
    description: "Return the currently displayed graph view (native plugin).",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_list_modules",
    description: "List modules in the debuggee.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_list_threads",
    description: "List threads in the debuggee.",
    inputSchema: noArgsSchema,
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_list_registers",
    description: "List registers in the debuggee.",
    inputSchema: {
      type: "object",
      properties: {
        scope: { type: "string" }
      },
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_set_breakpoint",
    description: "Set a breakpoint.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        type: { type: "string", enum: ["software", "hardware"] },
        enabled: { type: "boolean" },
        temporary: { type: "boolean" },
        size: { type: "integer", minimum: 1 }
      },
      required: ["address"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_command",
    description: "Execute an x64dbg command (full command access).",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        mode: { type: "string", enum: ["direct", "async"] },
        captureOutput: { type: "boolean" }
      },
      required: ["command"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  },
  {
    name: "x64dbg_eval",
    description: "Evaluate an x64dbg expression and return the value.",
    inputSchema: {
      type: "object",
      properties: {
        expression: { type: "string" }
      },
      required: ["expression"],
      additionalProperties: false
    },
    outputSchema: baseOutputSchema
  }
];

const resources: Resource[] = [
  {
    uri: "x64dbg://status",
    name: "x64dbg_status",
    description: "Current x64dbg status and client config.",
    mimeType: "application/json"
  },
  {
    uri: "x64dbg://config",
    name: "x64dbg_config",
    description: "Current MCP server config and security policy.",
    mimeType: "application/json"
  },
  {
    uri: "x64dbg://metrics",
    name: "x64dbg_metrics",
    description: "Current bridge metrics (connect failures, latency).",
    mimeType: "application/json"
  },
  {
    uri: "x64dbg://event_types",
    name: "x64dbg_event_types",
    description: "Supported x64dbg debug event names.",
    mimeType: "application/json"
  },
  {
    uri: "x64dbg://protocol",
    name: "x64dbg_protocol",
    description: "NDJSON protocol description for the bridge.",
    mimeType: "text/plain"
  }
];

const server = new Server(
  { name: "x64dbg-mcp", version: "0.1.0" },
  { capabilities: { tools: {}, resources: {} } }
);

const jsonResponse = (payload: unknown) => ({
  structuredContent: payload,
  content: [{ type: "text", text: JSON.stringify(payload, null, 2) }]
});

const okResponse = (result: unknown) => jsonResponse({ ok: true, result });

const errorResponse = (
  error: unknown,
  toolName: string,
  codeOverride?: string
) => {
  let payload: {
    message: string;
    code: string;
    tool: string;
    field?: string;
    data?: unknown;
  } = {
    message: "Unknown error.",
    code: codeOverride ?? "unknown",
    tool: toolName
  };

  if (error instanceof InputError) {
    payload = {
      message: error.message,
      code: codeOverride ?? "invalid_input",
      tool: toolName,
      field: error.field
    };
  } else if (error instanceof SecurityError) {
    payload = {
      message: error.message,
      code: codeOverride ?? "forbidden",
      tool: toolName,
      data: error.data
    };
  } else if (isX64DbgClientError(error)) {
    payload = {
      message: error.message,
      code: codeOverride ?? error.code,
      tool: toolName,
      data: error.data
    };
  } else if (error instanceof Error) {
    payload = {
      message: error.message,
      code: codeOverride ?? "unknown",
      tool: toolName
    };
  }

  const errorBody = { ok: false, error: payload };
  return {
    structuredContent: errorBody,
    content: [
      {
        type: "text",
        text: JSON.stringify(errorBody, null, 2)
      }
    ],
    isError: true
  };
};

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources }));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request.params.uri;
  if (uri === "x64dbg://status") {
    const status = await client.getStatus();
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(
            {
              ok: true,
              result: {
                status,
                config: getConfigSnapshot(),
                metrics: client.getMetrics(),
                events: client.getEventConfig()
              }
            },
            null,
            2
          )
        }
      ]
    };
  }
  if (uri === "x64dbg://config") {
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(
            { ok: true, result: getConfigSnapshot() },
            null,
            2
          )
        }
      ]
    };
  }
  if (uri === "x64dbg://metrics") {
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(
            { ok: true, result: client.getMetrics() },
            null,
            2
          )
        }
      ]
    };
  }
  if (uri === "x64dbg://event_types") {
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify({ ok: true, result: X64DBG_EVENT_TYPES }, null, 2)
        }
      ]
    };
  }
  if (uri === "x64dbg://protocol") {
    return {
      contents: [
        {
          uri,
          mimeType: "text/plain",
          text: PROTOCOL_DOC
        }
      ]
    };
  }
  return {
    contents: [
      {
        uri,
        mimeType: "text/plain",
        text: "Unknown resource."
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const toolName = request.params.name;
  const startedAt = Date.now();
  const ok = (result: unknown) => {
    logger.debug("tool.response", {
      tool: toolName,
      ok: true,
      durationMs: Date.now() - startedAt
    });
    return okResponse(result);
  };
  try {
    const args = asRecord(request.params.arguments);
    logger.debug("tool.request", { tool: toolName, args });
    switch (toolName) {
      case "ping":
        return ok({ message: "pong" });
      case "x64dbg_status": {
        const status = await client.getStatus();
        return ok({
          status,
          config: getConfigSnapshot(),
          metrics: client.getMetrics(),
          events: client.getEventConfig()
        });
      }
      case "x64dbg_metrics":
        return ok(client.getMetrics());
      case "x64dbg_subscribe_events": {
        const rawEvents = toStringArray(args.events, "events");
        const events = normalizeEventList(rawEvents);
        const unknownEvents = events.filter(
          (event) => !EVENT_TYPE_SET.has(event)
        );
        if (unknownEvents.length > 0) {
          logger.warn("bridge.events.unknown", { events: unknownEvents });
        }
        const clearQueue = optionalBoolean(args.clearQueue, "clearQueue");
        const result = await client.configureEvents(events);
        serverConfig.events = [...events];
        if (clearQueue) {
          client.drainEvents(Number.MAX_SAFE_INTEGER);
        }
        return ok({
          configured: result,
          events: client.getEventConfig(),
          unknown: unknownEvents
        });
      }
      case "x64dbg_poll_events": {
        const max =
          args.max === undefined ? 50 : toInteger(args.max, "max", 1);
        const result = client.drainEvents(max);
        return ok(result);
      }
      case "x64dbg_connect":
        await client.connect();
        return ok({ message: "connected" });
      case "x64dbg_reconnect":
        await client.reconnect();
        return ok({ message: "reconnected" });
      case "x64dbg_disconnect":
        await client.disconnect();
        return ok({ message: "disconnected" });
      case "x64dbg_shutdown":
        await client.shutdown();
        return ok({ message: "shutdown" });
      case "x64dbg_attach": {
        const pid = toInteger(args.pid, "pid", 1);
        await assertAttachAllowed(pid, serverConfig.security);
        const result = await client.attach(pid);
        return ok(result);
      }
      case "x64dbg_detach": {
        const result = await client.detach();
        return ok(result);
      }
      case "x64dbg_pause": {
        const result = await client.pause();
        return ok(result);
      }
      case "x64dbg_step": {
        const stepType = requiredEnum(args.type, "type", [
          "into",
          "over",
          "out"
        ] as const);
        const result = await client.step(stepType);
        return ok(result);
      }
      case "x64dbg_read_memory": {
        const address = requireString(args.address, "address");
        const length = toInteger(args.length, "length", 1);
        const result = await client.readMemory(address, length);
        return ok(result);
      }
      case "x64dbg_write_memory": {
        const address = requireString(args.address, "address");
        const data = requireString(args.data, "data");
        const encoding = optionalEnum(args.encoding, "encoding", [
          "hex",
          "base64"
        ] as const);
        const result = await client.writeMemory(address, data, encoding);
        return ok(result);
      }
      case "x64dbg_disasm": {
        const address = requireString(args.address, "address");
        const count =
          optionalIntegerInRange(
            args.count,
            "count",
            1,
            MAX_DISASM_COUNT
          ) ?? DEFAULT_DISASM_COUNT;
        const detail = optionalBoolean(args.detail, "detail") ?? false;
        const result = await client.disasm(address, count, detail);
        return ok(result);
      }
      case "x64dbg_cfg": {
        const entry = await parseAddressInput(args.entry, "entry");
        const maxBlocks =
          optionalIntegerInRange(
            args.maxBlocks,
            "maxBlocks",
            1,
            MAX_CFG_BLOCKS
          ) ?? DEFAULT_CFG_BLOCKS;
        const maxInstructions =
          optionalIntegerInRange(
            args.maxInstructions,
            "maxInstructions",
            1,
            MAX_CFG_INSTRUCTIONS
          ) ?? DEFAULT_CFG_INSTRUCTIONS;
        const maxBlockInstructions =
          optionalIntegerInRange(
            args.maxBlockInstructions,
            "maxBlockInstructions",
            1,
            MAX_CFG_BLOCK_INSTRUCTIONS
          ) ?? DEFAULT_CFG_BLOCK_INSTRUCTIONS;
        const maxDepth =
          optionalIntegerInRange(
            args.maxDepth,
            "maxDepth",
            0,
            MAX_CFG_DEPTH
          ) ?? DEFAULT_CFG_DEPTH;
        const result = await buildCfg(client, entry, {
          maxBlocks,
          maxInstructions,
          maxBlockInstructions,
          maxDepth
        });
        return ok(result);
      }
      case "x64dbg_xrefs": {
        const address = requireString(args.address, "address");
        const result = await client.getXrefs(address);
        return ok(result);
      }
      case "x64dbg_xref_graph": {
        const entry = await parseAddressInput(args.address, "address");
        const depth =
          optionalIntegerInRange(
            args.depth,
            "depth",
            0,
            MAX_XREF_DEPTH
          ) ?? DEFAULT_XREF_DEPTH;
        const maxNodes =
          optionalIntegerInRange(
            args.maxNodes,
            "maxNodes",
            1,
            MAX_XREF_NODES
          ) ?? DEFAULT_XREF_NODES;
        const maxEdges =
          optionalIntegerInRange(
            args.maxEdges,
            "maxEdges",
            1,
            MAX_XREF_EDGES
          ) ?? DEFAULT_XREF_EDGES;
        const result = await buildXrefGraph(client, entry, {
          depth,
          maxNodes,
          maxEdges
        });
        return ok(result);
      }
      case "x64dbg_search_memory": {
        const address = requireString(args.address, "address");
        const length = toIntegerInRange(
          args.length,
          "length",
          1,
          MAX_SEARCH_BYTES
        );
        const pattern = requireString(args.pattern, "pattern");
        const encoding = optionalEnum(args.encoding, "encoding", [
          "hex",
          "base64",
          "ascii",
          "utf16"
        ] as const);
        const maxResults =
          optionalIntegerInRange(
            args.maxResults,
            "maxResults",
            1,
            MAX_SEARCH_RESULTS
          ) ?? DEFAULT_SEARCH_RESULTS;
        const result = await client.searchMemory({
          address,
          length,
          pattern,
          encoding,
          maxResults
        });
        return ok(result);
      }
      case "x64dbg_memory_map": {
        const result = await client.getMemoryMap();
        return ok(result);
      }
      case "x64dbg_call_stack": {
        const depth =
          optionalIntegerInRange(
            args.depth,
            "depth",
            1,
            MAX_STACK_DEPTH
          ) ?? DEFAULT_STACK_DEPTH;
        const result = await client.getCallStack(depth);
        return ok(result);
      }
      case "x64dbg_log_tail": {
        const max =
          optionalIntegerInRange(args.max, "max", 1, MAX_LOG_LINES) ??
          DEFAULT_LOG_TAIL;
        const result = await client.logTail(max);
        return ok(result);
      }
      case "x64dbg_log_write": {
        const message = requireString(args.message, "message");
        const result = await client.logWrite(message);
        return ok(result);
      }
      case "x64dbg_gui_graph_at": {
        const address = requireString(args.address, "address");
        const result = await client.guiGraphAt(address);
        return ok(result);
      }
      case "x64dbg_gui_show_references": {
        const address = requireString(args.address, "address");
        const result = await client.guiShowReferences(address);
        return ok(result);
      }
      case "x64dbg_gui_current_graph": {
        const result = await client.guiCurrentGraph();
        return ok(result);
      }
      case "x64dbg_list_modules": {
        const result = await client.listModules();
        return ok(result);
      }
      case "x64dbg_list_threads": {
        const result = await client.listThreads();
        return ok(result);
      }
      case "x64dbg_list_registers": {
        const scope = optionalString(args.scope, "scope");
        const result = await client.listRegisters(scope);
        return ok(result);
      }
      case "x64dbg_set_breakpoint": {
        const address = requireString(args.address, "address");
        const type = optionalEnum(args.type, "type", [
          "software",
          "hardware"
        ] as const);
        const enabled = optionalBoolean(args.enabled, "enabled");
        const temporary = optionalBoolean(args.temporary, "temporary");
        const size =
          args.size === undefined ? undefined : toInteger(args.size, "size", 1);
        const result = await client.setBreakpoint({
          address,
          type,
          enabled,
          temporary,
          size
        });
        return ok(result);
      }
      case "x64dbg_command": {
        const command = requireString(args.command, "command");
        const mode =
          optionalEnum(args.mode, "mode", ["direct", "async"] as const) ??
          "direct";
        const captureOutput =
          optionalBoolean(args.captureOutput, "captureOutput") ?? false;
        if (captureOutput && mode !== "direct") {
          throw new InputError(
            "captureOutput",
            "captureOutput only supports direct mode."
          );
        }
        const attachPid = extractAttachPid(command);
        if (attachPid !== null) {
          await assertAttachAllowed(attachPid, serverConfig.security);
        }
        const result = await client.execCommand(command, mode, captureOutput);
        return ok(result);
      }
      case "x64dbg_eval": {
        const expression = requireString(args.expression, "expression");
        const result = await client.evalExpression(expression);
        return ok(result);
      }
      default:
        logger.warn("tool.unknown", { tool: toolName });
        return errorResponse(
          new Error(`Unknown tool: ${toolName}`),
          toolName,
          "unknown_tool"
        );
    }
  } catch (error) {
    logger.warn("tool.error", {
      tool: toolName,
      durationMs: Date.now() - startedAt,
      message: error instanceof Error ? error.message : String(error)
    });
    return errorResponse(error, toolName);
  }
});

const transport = new StdioServerTransport();

await server.connect(transport);
