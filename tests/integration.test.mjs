import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const startMockBridge = async () => {
  const requests = [];
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => {
      sockets.delete(socket);
    });
    socket.on("error", () => {});
    let buffer = "";
    socket.on("data", (data) => {
      buffer += data.toString("utf8");
      while (true) {
        const idx = buffer.indexOf("\n");
        if (idx < 0) {
          break;
        }
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) {
          continue;
        }
        const request = JSON.parse(line);
        requests.push(request);
        const result = handleRequest(request, socket);
        const response = {
          id: request.id,
          ok: true,
          result
        };
        socket.write(JSON.stringify(response) + "\n");
      }
    });
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { server, port, requests, sockets };
};

const handleRequest = (request, socket) => {
  switch (request.method) {
    case "debug.eval":
      return { value: 3, hex: "0x3" };
    case "debug.exec":
      return { ok: true, mode: request.params?.mode ?? "direct" };
    case "debug.listModules":
      return { modules: [] };
    case "event.configure":
      setTimeout(() => {
        socket.write(
          JSON.stringify({
            event: "breakpoint",
            data: { addr: 4096 },
            ts: 1
          }) + "\n"
        );
      }, 10);
      return { events: request.params?.events ?? [] };
    default:
      return { ok: true };
  }
};

const createClient = async (port) => {
  const client = new Client({ name: "x64dbg-mcp-test", version: "0.0.0" });
  const transport = new StdioClientTransport({
    command: "node",
    args: ["dist/index.js"],
    env: {
      ...process.env,
      X64DBG_TRANSPORT: "tcp",
      X64DBG_HOST: "127.0.0.1",
      X64DBG_PORT: String(port),
      X64DBG_LOG_LEVEL: "error"
    }
  });
  await client.connect(transport);
  await client.listTools();
  return client;
};

const requireStructured = (response, label) => {
  const payload = response?.structuredContent;
  if (!payload) {
    throw new Error(`${label} did not return structured content.`);
  }
  return payload;
};

test("MCP server talks to a mocked x64dbg bridge", async (t) => {
  const bridge = await startMockBridge();
  t.after(async () => {
    for (const socket of bridge.sockets) {
      socket.destroy();
    }
    await new Promise((resolve) => bridge.server.close(resolve));
  });

  const client = await createClient(bridge.port);
  t.after(async () => {
    await client.close();
  });

  const evalResult = await client.callTool({
    name: "x64dbg_eval",
    arguments: { expression: "1+2" }
  });
  const evalPayload = requireStructured(evalResult, "x64dbg_eval");
  assert.equal(evalPayload.ok, true);
  assert.equal(evalPayload.result.value, 3);

  const commandResult = await client.callTool({
    name: "x64dbg_command",
    arguments: { command: "log \"hello\"" }
  });
  const commandPayload = requireStructured(commandResult, "x64dbg_command");
  assert.equal(commandPayload.ok, true);
  assert.equal(commandPayload.result.ok, true);
  assert.equal(commandPayload.result.mode, "direct");

  await client.callTool({
    name: "x64dbg_subscribe_events",
    arguments: { events: ["breakpoint"] }
  });

  let eventsPayload = null;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const eventsResult = await client.callTool({
      name: "x64dbg_poll_events",
      arguments: { max: 10 }
    });
    const payload = requireStructured(eventsResult, "x64dbg_poll_events");
    if (payload.result.events.length > 0) {
      eventsPayload = payload;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.ok(eventsPayload);
  assert.equal(eventsPayload.result.events[0].event, "breakpoint");

  const evalRequest = bridge.requests.find(
    (request) => request.method === "debug.eval"
  );
  assert.equal(evalRequest?.params?.expression, "1+2");
});
