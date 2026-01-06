import test from "node:test";
import assert from "node:assert/strict";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const createClient = async (envOverrides = {}) => {
  const client = new Client({ name: "x64dbg-mcp-test", version: "0.0.0" });
  const transport = new StdioClientTransport({
    command: "node",
    args: ["dist/index.js"],
    env: {
      ...process.env,
      X64DBG_TRANSPORT: "none",
      X64DBG_LOG_LEVEL: "error",
      ...envOverrides
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

test("x64dbg_status returns status without connecting", async (t) => {
  const client = await createClient();
  t.after(async () => {
    await client.close();
  });

  const result = await client.callTool({
    name: "x64dbg_status",
    arguments: {}
  });

  const payload = requireStructured(result, "x64dbg_status");
  assert.equal(payload.ok, true);
  assert.equal(payload.result.config.client.transport, "none");
});

test("x64dbg_step validates the step type", async (t) => {
  const client = await createClient();
  t.after(async () => {
    await client.close();
  });

  const result = await client.callTool({
    name: "x64dbg_step",
    arguments: { type: "jump" }
  });

  const payload = requireStructured(result, "x64dbg_step");
  assert.equal(payload.ok, false);
  assert.equal(payload.error.code, "invalid_input");
  assert.equal(payload.error.field, "type");
});

test("x64dbg_poll_events returns an empty list by default", async (t) => {
  const client = await createClient();
  t.after(async () => {
    await client.close();
  });

  const result = await client.callTool({
    name: "x64dbg_poll_events",
    arguments: {}
  });

  const payload = requireStructured(result, "x64dbg_poll_events");
  assert.equal(payload.ok, true);
  assert.deepEqual(payload.result.events, []);
});
