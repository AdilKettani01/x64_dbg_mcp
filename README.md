# x64dbg MCP Server (Bootstrap)

Minimal MCP server scaffold for building an x64dbg integration. This uses the
MCP SDK over stdio and provides a stub `x64dbg_status` tool.

## Quick start

```bash
npm install
npm run dev
```

## Setup

See the full setup guide in `SETUP.md`.

## MCP client config examples

Example stdio configs for common MCP clients are in `MCP_CLIENT_CONFIG.md`.

## WinDbg/KD MCP server

The WinDbg/KD MCP server now lives in a separate project (`windbg-mcp`). See
that repo for setup and usage.

## Tools

- `ping`: basic server health check.
- `x64dbg_status`: returns the current stub status and client config.
- `x64dbg_metrics`: returns bridge connection and latency metrics.
- `x64dbg_subscribe_events`: configure which debug events are streamed.
- `x64dbg_poll_events`: fetch queued debug events.
- `x64dbg_command`: execute an arbitrary x64dbg command.
- `x64dbg_eval`: evaluate an x64dbg expression.
- `x64dbg_disasm`: disassemble instructions at an address.
- `x64dbg_cfg`: build a lightweight control-flow graph.
- `x64dbg_xrefs`: list cross-references to an address.
- `x64dbg_xref_graph`: build an xref graph rooted at an address.
- `x64dbg_search_memory`: search memory for a byte pattern.
- `x64dbg_memory_map`: return the current memory map.
- `x64dbg_call_stack`: stack snapshot of potential return addresses.
- `x64dbg_log_tail`: tail the bridge log buffer.
- `x64dbg_log_write`: write a message to the x64dbg GUI log.
- Additional tools cover attach/detach/pause/step, memory read/write, modules,
  threads, registers, and breakpoints.

Note: `x64dbg_call_stack` returns a stack snapshot of potential return
addresses (x64dbgpy does not expose the GUI call stack view directly).

## Usage examples

Call a command and eval:

```json
{ "name": "x64dbg_command", "arguments": { "command": "log \"hello\"" } }
```

```json
{ "name": "x64dbg_command", "arguments": { "command": "r", "captureOutput": true } }
```

```json
{ "name": "x64dbg_eval", "arguments": { "expression": "1+2" } }
```

Subscribe to events, then poll:

```json
{ "name": "x64dbg_subscribe_events", "arguments": { "events": ["breakpoint", "stop_debug"] } }
```

```json
{ "name": "x64dbg_poll_events", "arguments": { "max": 10 } }
```

Disassemble and query xrefs:

```json
{ "name": "x64dbg_disasm", "arguments": { "address": "0x401000", "count": 8 } }
```

```json
{ "name": "x64dbg_xrefs", "arguments": { "address": "0x401234" } }
```

```json
{ "name": "x64dbg_cfg", "arguments": { "entry": "0x401000", "maxBlocks": 64 } }
```

```json
{ "name": "x64dbg_xref_graph", "arguments": { "address": "0x401234", "depth": 1 } }
```

Search memory and get a stack snapshot:

```json
{ "name": "x64dbg_search_memory", "arguments": { "address": "0x401000", "length": 65536, "pattern": "crackme", "encoding": "ascii" } }
```

```json
{ "name": "x64dbg_call_stack", "arguments": { "depth": 32 } }
```

Tail bridge logs:

```json
{ "name": "x64dbg_log_tail", "arguments": { "max": 50 } }
```

## Configuration

Configuration can come from environment variables or a JSON config file. If
`X64DBG_CONFIG` is set, that file is loaded. Otherwise, the server loads
`x64dbg-mcp.config.json` from the working directory when present. A template is
available at `x64dbg-mcp.config.example.json`. Environment variables override
values from the file.

Set environment variables as needed:

- `X64DBG_CONFIG` (path to a JSON config file)
- `X64DBG_TRANSPORT` (`none`, `tcp`, `pipe`; default: `tcp` when port > 0)
- `X64DBG_HOST` (default: `127.0.0.1`)
- `X64DBG_PORT` (default: `0`)
- `X64DBG_PIPE` (pipe name when using `pipe`)
- `X64DBG_CONNECT_TIMEOUT_MS` (default: `2000`)
- `X64DBG_REQUEST_TIMEOUT_MS` (default: `3000`)
- `X64DBG_RETRY_COUNT` (default: `2`)
- `X64DBG_RETRY_BACKOFF_MS` (default: `200`)
- `X64DBG_RETRY_MAX_BACKOFF_MS` (default: `2000`)
- `X64DBG_ALLOW_PIDS` (comma-separated PIDs to allow)
- `X64DBG_DENY_PIDS` (comma-separated PIDs to deny)
- `X64DBG_ALLOW_NAMES` (comma-separated process names to allow)
- `X64DBG_DENY_NAMES` (comma-separated process names to deny)
- `X64DBG_EVENTS` (comma-separated event names to subscribe)
- `X64DBG_EVENT_QUEUE_LIMIT` (default: `1000`)
- `X64DBG_MCP_NATIVE_DLL` (path to native plugin DLL)
- `X64DBG_MCP_NATIVE_DISABLE` (set to `1` to ignore native plugin)
- `X64DBG_MCP_LOG_HISTORY_LIMIT` (bridge log buffer size; default: `500`)
- `X64DBG_MCP_MAX_DISASM` (max instructions per disasm; default: `200`)
- `X64DBG_MCP_MAX_SEARCH_BYTES` (max bytes to scan; default: `16777216`)
- `X64DBG_MCP_MAX_SEARCH_RESULTS` (max search hits; default: `200`)
- `X64DBG_MCP_MAX_STACK_DEPTH` (max stack depth; default: `128`)
- `X64DBG_LOG_LEVEL` (`debug`, `info`, `warn`, `error`; default: `info`)
- `X64DBG_LOG_REDACT` (comma-separated keys to redact in logs)

Process name lists are case-insensitive substring matches against the process
image name.

Event streaming defaults to a safe subset (breakpoints, process/thread and
module load events). Use `X64DBG_EVENTS=trace_execute` only when needed, since
it can be high volume.

Logs are emitted as JSON lines on stderr to avoid interfering with MCP stdio.

## Testing

- `npm test` runs unit + integration tests (mock bridge).
- `npm run test:mcp` runs a live smoke test against a running x64dbg bridge.

## Security and permissions

The MCP server can execute debugger commands in the attached x64dbg instance.
If you want to constrain attachments, set allow/deny lists in config or
environment. Allow/deny checks apply to `x64dbg_attach` and `x64dbg_command`
when it issues an `attach` command. x64dbg may need to run elevated to attach
to protected processes.

## x64dbg bridge (x64dbgpy)

Phase 1 uses a simple Python bridge that runs inside x64dbg and exposes a TCP
endpoint. The script lives at `bridge/x64dbgpy_bridge.py` and speaks the NDJSON
protocol described in `src/x64dbg/protocol.ts`.

1. Ensure the `x64dbgpy` plugin is installed and configured with Python 2.7.
2. In x64dbg, run `bridge/x64dbgpy_bridge.py` via the x64dbgpy plugin menu.
3. Start the MCP server with:
   - `X64DBG_TRANSPORT=tcp`
   - `X64DBG_HOST=127.0.0.1`
   - `X64DBG_PORT=31337`

## Next steps

Replace the Python bridge with a native plugin or named pipe implementation if
you need tighter integration or lower latency.

## Native plugin (optional)

For GUI log tailing, command output capture, and real callstack frames, build
the native plugin in `native/x64dbg_mcp_native` and copy the build output
(`x64dbg_mcp_native.dp64` for x64, `.dp32` for x32) into your x64dbg `plugins`
directory (for example:
`C:\Tools\x64dbg\release\x64\plugins\x64dbg_mcp_native.dp64`, or
`C:\Tools\x64dbg\release\x32\plugins\x64dbg_mcp_native.dp32` for x32dbg).
Restart x64dbg after installing the plugin. The Python bridge will detect it
automatically, or set `X64DBG_MCP_NATIVE_DLL` to the full path.

`x64dbg_command` supports `captureOutput: true` when the native plugin is
loaded (direct mode only).

The native plugin also adds a **Start MCP** entry under the x64dbg `Plugins`
menu. To launch the bridge from that button, copy
`bridge\x64dbgpy_bridge.py` into the x64dbg plugins folder (or set
`X64DBG_MCP_BRIDGE`). To show the magnet icon, copy
`native\x64dbg_mcp_native\x64dbg_mcp_native.png` alongside the DLL (or set
`X64DBG_MCP_ICON`).

With the native plugin loaded, the MCP tools `x64dbg_gui_graph_at`,
`x64dbg_gui_show_references`, and `x64dbg_gui_current_graph` can open the
graph/xref panes and read the currently displayed graph.

## x32dbg support

- Use the same MCP server; point it at the x32dbg bridge port.
- Run `bridge\\x32dbgpy_bridge.py` from x32dbg (or set `X64DBG_HOME` to
  `C:\\Tools\\x64dbg\\release\\x32` before running the main bridge script).
- Make sure x32dbgpy is configured with 32-bit Python 2.7 (edit
  `C:\\Tools\\x64dbg\\release\\x32\\x32dbg.ini` and set `PythonHome`).
  If `x64dbgpy` fails to load `python27.dll`, the install is likely 64-bit or
  missing.
- Build/install the native plugin with:
  - `scripts\\build_native_x32.ps1`
  - `scripts\\install_native_x32.ps1`
See `mcp-client.x32.example.json` for a ready-to-copy MCP client entry.
You can also start from `x32dbg-mcp.config.example.json` if you prefer config
files over env vars.

## Packaging and install helpers

- `scripts\\build_native.ps1` builds the native DLL (requires CMake + MSVC).
- `scripts\\build_native_x32.ps1` builds the 32-bit native plugin.
- `scripts\\package_native.ps1` creates `release\\x64dbg_mcp_native.zip`.
- `scripts\\install_native.ps1` copies the DLL into the x64dbg plugins folder.
- `scripts\\install_native_x32.ps1` installs the x32 plugin into the x32dbg folder.
- `scripts\\install_codex.ps1` updates a Codex MCP config file with the
  x64dbg server entry.

## Using with windbg-mcp

You can run both MCP servers side-by-side by adding them to your Codex config:

```toml
[mcp_servers.x64dbg]
command = "node"
args = ["C:\\\\path\\\\to\\\\x64MCP\\\\dist\\\\index.js"]

[mcp_servers.x64dbg.env]
X64DBG_TRANSPORT = "tcp"
X64DBG_HOST = "127.0.0.1"
X64DBG_PORT = "31337"
X64DBG_MCP_NATIVE_DLL = "C:\\\\Tools\\\\x64dbg\\\\release\\\\x64\\\\plugins\\\\x64dbg_mcp_native.dll"

[mcp_servers.windbg]
command = "node"
args = ["C:\\\\path\\\\to\\\\windbg-mcp\\\\dist\\\\index.js"]

[mcp_servers.windbg.env]
WINDBG_EXEC = "kd.exe"
WINDBG_ARGS = "-k com:port=\\\\\\\\.\\\\pipe\\\\com1,baud=115200,pipe"
```

## Troubleshooting

- Bridge not connecting: confirm x64dbg is running, the bridge script is loaded,
  and `X64DBG_HOST`/`X64DBG_PORT` match.
- `ImportError: No module named pluginsdk`: set `X64DBG_HOME` to your x64dbg
  install root so the bridge can find the x64dbgpy package.
- Python version mismatch: x64dbgpy requires Python 2.7 (64-bit); 3.x will not
  load.
- No events: call `x64dbg_subscribe_events` and poll with `x64dbg_poll_events`.
- Live logs: use x64dbg Log view (`View -> Log`) or check
  `bridge\x64dbgpy_bridge.log`.

## Versioning and release notes

This project follows Semantic Versioning. Release notes live in
`CHANGELOG.md`.

## Contributing

See `CONTRIBUTING.md` for setup and workflow.

## Security

Please report security issues privately. See `SECURITY.md`.

## License

MIT. See `LICENSE`.
