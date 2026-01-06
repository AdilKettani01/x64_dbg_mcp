import process from "node:process";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const buildEnv = () => {
  const env = {
    ...process.env,
    X64DBG_TRANSPORT: process.env.X64DBG_TRANSPORT ?? "tcp",
    X64DBG_HOST: process.env.X64DBG_HOST ?? "127.0.0.1",
    X64DBG_PORT: process.env.X64DBG_PORT ?? "31337"
  };

  if (process.env.X64DBG_PIPE) {
    env.X64DBG_PIPE = process.env.X64DBG_PIPE;
  }

  return env;
};

const requireStructured = (response, label) => {
  const payload = response?.structuredContent;
  if (!payload || typeof payload !== "object") {
    throw new Error(`${label} did not return structured content.`);
  }
  return payload;
};

const run = async () => {
  const client = new Client({ name: "x64dbg-mcp-smoke", version: "0.0.0" });
  const transport = new StdioClientTransport({
    command: "node",
    args: ["dist/index.js"],
    env: buildEnv()
  });

  try {
    await client.connect(transport);
    const tools = await client.listTools();
    const toolNames = tools.tools.map((tool) => tool.name).sort();
    if (!toolNames.includes("x64dbg_eval")) {
      throw new Error("x64dbg_eval tool not available.");
    }

    const status = await client.callTool({
      name: "x64dbg_status",
      arguments: {}
    });
    const statusPayload = requireStructured(status, "x64dbg_status");
    if (statusPayload.ok !== true) {
      throw new Error(
        `x64dbg_status failed: ${statusPayload.error?.message ?? "unknown"}`
      );
    }

    const evalResult = await client.callTool({
      name: "x64dbg_eval",
      arguments: { expression: "1+2" }
    });
    const evalPayload = requireStructured(evalResult, "x64dbg_eval");
    if (evalPayload.ok !== true) {
      throw new Error(
        `x64dbg_eval failed: ${evalPayload.error?.message ?? "unknown"}`
      );
    }

    const value = evalPayload.result?.value;
    const hex = evalPayload.result?.hex;
    console.log(
      `OK: x64dbg_eval returned ${value ?? "?"} (${hex ?? "unknown"})`
    );
  } finally {
    await client.close();
  }
};

run().catch((error) => {
  console.error("Smoke test failed:", error?.message ?? error);
  process.exitCode = 1;
});
