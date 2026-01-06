# x64dbg MCP Native Plugin

This optional plugin provides:

- GUI log tailing (via `GuiLogSave`)
- Command output capture (diffs the log around a command)
- Real callstack frames (via `DbgFunctions()->GetCallStackEx`)
- GUI pane helpers (graph at address, show references, current graph)

## Build

```powershell
$env:X64DBG_SDK_DIR="C:\Tools\x64dbg\pluginsdk"
cmake -S . -B build
cmake --build build --config Release
```

For x32 builds, use:

```powershell
cmake -S . -B build-x32 -A Win32
cmake --build build-x32 --config Release
```

## Install

Copy the build output (`x64dbg_mcp_native.dp64` for x64, `.dp32` for x32)
into:

`C:\Tools\x64dbg\release\x64\plugins\` (or `C:\Tools\x64dbg\release\x32\plugins\`
for x32dbg).

Restart x64dbg after copying. The Python bridge will auto-detect the DLL or you
can set `X64DBG_MCP_NATIVE_DLL` to the full path.

## Start MCP button

The plugin adds a **Start MCP** entry under the x64dbg `Plugins` menu. It calls
`PyRunScriptAsync` to launch the Python bridge.

Place `x64dbgpy_bridge.py` next to the DLL (or under `plugins\bridge\`) so the
menu entry can find it. You can override the path with
`X64DBG_MCP_BRIDGE`.

For x32dbg, you can use `x32dbgpy_bridge.py` (it sets `X64DBG_HOME` for 32-bit
by default).

To show the magnet icon, copy `x64dbg_mcp_native.png` next to the DLL. You can
override the icon path with `X64DBG_MCP_ICON`.
