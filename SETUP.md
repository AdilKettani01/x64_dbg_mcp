# Setup Guide

This guide walks through setting up the x64dbg MCP server with the bundled
x64dbgpy TCP bridge. It assumes x64dbg is installed at
`C:\Tools\x64dbg\release\x64`.

## Prerequisites

- Node.js (LTS) + npm
- x64dbg (64-bit) installed at `C:\Tools\x64dbg\release\x64`
- x64dbgpy plugin installed (should exist at
  `C:\Tools\x64dbg\release\x64\plugins\x64dbgpy`)
- Python 2.7 (64-bit) installed for x64dbgpy

If you plan to use x32dbg:

- x32dbg installed at `C:\Tools\x64dbg\release\x32`
- Python 2.7 (32-bit) installed in its own folder (for example `C:\Python27_x86`)
  and configured in `x32dbg.ini`

Configure x32dbgpy by editing `C:\Tools\x64dbg\release\x32\x32dbg.ini`:

```
[x64dbgpy]
PythonHome=C:\Python27_x86
```

## Install the MCP server

```bash
cd C:\Users\adil\Documents\x64MCP
npm install
npm run build
```

For development, you can use:

```bash
npm run dev
```

## Configure x64dbgpy (Python 2.7)

1. Install Python 2.7 (64-bit). The x64dbgpy plugin loads `python27.dll`.
2. Edit `C:\Tools\x64dbg\release\x64\x64dbg.ini`:

```
[x64dbgpy]
PythonHome=C:\Python27
```

3. Restart x64dbg.

If x64dbg fails to load x64dbgpy, confirm `python27.dll` is reachable from
`PythonHome` or the system PATH.

## Run the x64dbg bridge

The MCP server expects a TCP bridge that runs inside x64dbg. Use the script
at `bridge/x64dbgpy_bridge.py`.

1. Launch `C:\Tools\x64dbg\release\x64\x64dbg.exe`.
2. Use the x64dbgpy plugin menu to run a Python file.
3. Select `C:\Users\adil\Documents\x64MCP\bridge\x64dbgpy_bridge.py`.

For x32dbg, run `bridge\x32dbgpy_bridge.py` instead (or set `X64DBG_HOME` to
`C:\Tools\x64dbg\release\x32` before running the main bridge script).

The bridge stays running and starts a TCP listener on `127.0.0.1:31337`
inside the x64dbg process. If your menu runs scripts synchronously, use the
command bar with `PyRunScriptAsync` to avoid blocking the UI.

## Native plugin (optional)

To capture GUI log contents, command output, and real callstack frames, build
the native plugin:

```powershell
cd C:\Users\adil\Documents\x64MCP\native\x64dbg_mcp_native
$env:X64DBG_SDK_DIR="C:\Tools\x64dbg\pluginsdk"
cmake -S . -B build
cmake --build build --config Release
```

Copy the build output (`x64dbg_mcp_native.dp64` for x64, `.dp32` for x32) to
`C:\Tools\x64dbg\release\x64\plugins\` (or `C:\Tools\x64dbg\release\x32\plugins\`
for x32dbg) and restart x64dbg. The bridge auto-detects it; use
`X64DBG_MCP_NATIVE_DLL` to override the path.

Helper scripts:

- `scripts\build_native.ps1`
- `scripts\build_native_x32.ps1` (Win32 build)
- `scripts\package_native.ps1`
- `scripts\install_native.ps1`
- `scripts\install_native_x32.ps1`

The native plugin adds a **Start MCP** entry under the x64dbg `Plugins` menu.
To launch the bridge from that button, copy
`bridge\x64dbgpy_bridge.py` into the x64dbg plugins folder (or set
`X64DBG_MCP_BRIDGE`). To show the magnet icon, copy
`native\x64dbg_mcp_native\x64dbg_mcp_native.png` into the same folder (or set
`X64DBG_MCP_ICON`).

When the native plugin is loaded, the MCP tools `x64dbg_gui_graph_at`,
`x64dbg_gui_show_references`, and `x64dbg_gui_current_graph` can open the graph
and references panes.

## Run the MCP server

In a separate PowerShell window:

```powershell
$env:X64DBG_TRANSPORT="tcp"
$env:X64DBG_HOST="127.0.0.1"
$env:X64DBG_PORT="31337"
npm run dev
```

You can also use a JSON config file. Set `X64DBG_CONFIG` to the path, or place
`x64dbg-mcp.config.json` in the working directory. A template is available at
`x64dbg-mcp.config.example.json` (and `x32dbg-mcp.config.example.json` for a
separate x32dbg port). Environment variables override the file.

Optional logging:

- `X64DBG_LOG_LEVEL` (`debug`, `info`, `warn`, `error`)
- `X64DBG_LOG_REDACT` (comma-separated keys to redact in logs)
- `X64DBG_MCP_LOG_HISTORY_LIMIT` (bridge log buffer size)
- `X64DBG_MCP_NATIVE_DLL` (path to native plugin DLL)
- `X64DBG_MCP_NATIVE_DISABLE` (set to `1` to ignore native plugin)

Logs are JSON lines written to stderr so they do not interfere with MCP stdio.

If you want a separate x32dbg MCP server entry, copy
`mcp-client.x32.example.json` and update the port to match your bridge.

Event streaming (optional):

- `X64DBG_EVENTS` (comma-separated event names to subscribe)
- `X64DBG_EVENT_QUEUE_LIMIT` (default: `1000`)

The default event list includes breakpoints, process/thread lifecycle events,
and DLL load/unload. Use `trace_execute` only when needed, since it is
high volume.

Advanced limits (optional):

- `X64DBG_MCP_MAX_DISASM` (max instructions per disasm)
- `X64DBG_MCP_MAX_SEARCH_BYTES` (max bytes to scan for search)
- `X64DBG_MCP_MAX_SEARCH_RESULTS` (max search hits)
- `X64DBG_MCP_MAX_STACK_DEPTH` (max stack depth)

Optional allow/deny lists can limit which processes are attachable:

- `X64DBG_ALLOW_PIDS` / `X64DBG_DENY_PIDS`
- `X64DBG_ALLOW_NAMES` / `X64DBG_DENY_NAMES`

Process name lists are case-insensitive substring matches against the process
image name.

## Verify connectivity

- Call the MCP tool `x64dbg_status` to confirm `connected: true`.
- Use `x64dbg_attach` with a PID to attach to a running process.

## Troubleshooting

- Bridge not connecting: ensure x64dbg is running and the bridge script is
  loaded; confirm `X64DBG_HOST`/`X64DBG_PORT` match the script.
- `ImportError: No module named pluginsdk`: the bridge needs the x64dbgpy
  package path. Set `X64DBG_HOME` to your x64dbg install root or update
  `bridge/x64dbgpy_bridge.py` to point at the correct path.
- x64dbgpy errors: verify Python 2.7 (x64) is installed and `PythonHome` points
  to it; restart x64dbg after changes.
- x32dbgpy errors: use Python 2.7 **32-bit** and confirm `PythonHome` points to
  the 32-bit install. Install it in a separate folder (for example
  `C:\Python27_x86`) to avoid mixing with 64-bit Python. A 64-bit
  `python27.dll` will fail to load.
- Live logs: open the x64dbg Log view (`View -> Log` or `Alt+L`). The bridge
  also writes to `bridge\x64dbgpy_bridge.log` by default (override with
  `X64DBG_MCP_LOG`). The MCP tool `x64dbg_log_tail` reads the bridge log
  buffer.
- Access denied: run x64dbg elevated if attaching to protected processes.
