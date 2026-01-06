import os
import runpy

if not os.environ.get("X64DBG_HOME"):
    os.environ["X64DBG_HOME"] = r"C:\Tools\x64dbg\release\x32"
if not os.environ.get("X64DBG_MCP_PORT"):
    os.environ["X64DBG_MCP_PORT"] = "31338"

runpy.run_path(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "x64dbgpy_bridge.py"),
    run_name="__main__"
)
