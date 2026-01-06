# MCP Client Config Examples

This server communicates over stdio, so most MCP clients can launch it by
running the Node entrypoint with environment variables.

## Generic stdio config

Use this shape for any MCP client that accepts `mcpServers` JSON (for example
desktop MCP clients or IDE integrations). Update the `args` path and env vars
to match your setup.

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "node",
      "args": ["C:\\\\path\\\\to\\\\x64MCP\\\\dist\\\\index.js"],
      "env": {
        "X64DBG_TRANSPORT": "tcp",
        "X64DBG_HOST": "127.0.0.1",
        "X64DBG_PORT": "31337",
        "X64DBG_LOG_LEVEL": "info",
        "X64DBG_MCP_NATIVE_DLL": "C:\\\\Tools\\\\x64dbg\\\\release\\\\x64\\\\plugins\\\\x64dbg_mcp_native.dll"
      }
    }
  }
}
```

The same example is available at `mcp-client.example.json`.

## x32dbg config

You can run a second MCP server instance for x32dbg by changing the port and
server name:

```json
{
  "mcpServers": {
    "x32dbg": {
      "command": "node",
      "args": ["C:\\\\path\\\\to\\\\x64MCP\\\\dist\\\\index.js"],
      "env": {
        "X64DBG_TRANSPORT": "tcp",
        "X64DBG_HOST": "127.0.0.1",
        "X64DBG_PORT": "31338",
        "X64DBG_LOG_LEVEL": "info",
        "X64DBG_MCP_NATIVE_DLL": "C:\\\\Tools\\\\x64dbg\\\\release\\\\x32\\\\plugins\\\\x64dbg_mcp_native.dll"
      }
    }
  }
}
```

Start the x32dbg bridge on the matching port (for example by setting
`X64DBG_MCP_PORT=31338` before running `bridge\\x32dbgpy_bridge.py`).

## macOS/Linux path example

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "node",
      "args": ["/path/to/x64MCP/dist/index.js"],
      "env": {
        "X64DBG_TRANSPORT": "tcp",
        "X64DBG_HOST": "127.0.0.1",
        "X64DBG_PORT": "31337"
      }
    }
  }
}
```

## Notes

- Run `npm run build` first so `dist/index.js` exists.
- You can set `X64DBG_CONFIG` to point at a JSON config file instead of passing
  all env vars through the MCP client.
- The WinDbg MCP server now lives in a separate project (`windbg-mcp`), which
  ships its own config example and install script.
