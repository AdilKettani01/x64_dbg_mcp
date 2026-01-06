import base64
import binascii
from collections import deque
import ctypes
import json
import os
import socket
import struct
import sys
import threading
import time
import traceback

def default_x64dbg_home():
    if struct.calcsize("P") == 4:
        return r"C:\Tools\x64dbg\release\x32"
    return r"C:\Tools\x64dbg\release\x64"


DEFAULT_X64DBG_HOME = default_x64dbg_home()
X64DBG_HOME = os.environ.get("X64DBG_HOME") or DEFAULT_X64DBG_HOME
X64DBG_PY_PATH = os.path.join(X64DBG_HOME, "plugins", "x64dbgpy", "x64dbgpy")
if X64DBG_PY_PATH not in sys.path:
    sys.path.insert(0, X64DBG_PY_PATH)

import x64dbgpy
from x64dbgpy import __events as x64dbg_events
from pluginsdk import x64dbg
from pluginsdk._scriptapi import memory as mem
from pluginsdk._scriptapi import module as mod
from pluginsdk._scriptapi import stack as stackapi
from x64dbgpy.utils import is_64bit

try:
    long
except NameError:
    long = int

try:
    unicode
except NameError:
    unicode = str

ADDR_T = ctypes.c_uint64 if is_64bit() else ctypes.c_uint32


HOST = os.environ.get("X64DBG_MCP_HOST") or "127.0.0.1"
PORT = int(os.environ.get("X64DBG_MCP_PORT") or 31337)
LOG_FILE_PATH = (
    os.environ.get("X64DBG_MCP_LOG")
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "x64dbgpy_bridge.log")
)
KEEPALIVE = (os.environ.get("X64DBG_MCP_KEEPALIVE") or "1") != "0"
LOG_HISTORY_LIMIT = int(os.environ.get("X64DBG_MCP_LOG_HISTORY_LIMIT") or 500)
MAX_DISASM_COUNT = int(os.environ.get("X64DBG_MCP_MAX_DISASM") or 200)
MAX_SEARCH_BYTES = int(os.environ.get("X64DBG_MCP_MAX_SEARCH_BYTES") or 16777216)
MAX_SEARCH_RESULTS = int(os.environ.get("X64DBG_MCP_MAX_SEARCH_RESULTS") or 200)
MAX_STACK_DEPTH = int(os.environ.get("X64DBG_MCP_MAX_STACK_DEPTH") or 128)
EVENT_QUEUE_LIMIT = int(os.environ.get("X64DBG_MCP_EVENT_QUEUE_LIMIT") or 1000)
EVENTS_ENV = os.environ.get("X64DBG_MCP_EVENTS")
NATIVE_DLL_PATH = os.environ.get("X64DBG_MCP_NATIVE_DLL")
SUPPORTED_EVENTS = list(getattr(x64dbg_events, "EVENTS", []))
try:
    XREF_TYPE_NAMES = {
        int(x64dbg.XREF_NONE): "none",
        int(x64dbg.XREF_DATA): "data",
        int(x64dbg.XREF_JMP): "jump",
        int(x64dbg.XREF_CALL): "call"
    }
except Exception:
    XREF_TYPE_NAMES = {}

_ORIGINAL_LISTEN = x64dbgpy.Event.listen

SUBSCRIBED_EVENTS = set()
USER_EVENT_CALLBACKS = {}
EVENT_DISPATCHERS = {}
CLIENTS = set()
CLIENT_LOCK = threading.Lock()
EVENT_QUEUE = deque()
EVENT_COND = threading.Condition()
DROPPED_EVENTS = 0
LOG_HISTORY = deque(maxlen=LOG_HISTORY_LIMIT)
LOG_LOCK = threading.Lock()
NATIVE_BRIDGE = None


def load_native_bridge():
    global NATIVE_BRIDGE
    if NATIVE_BRIDGE is not None:
        return NATIVE_BRIDGE
    if os.environ.get("X64DBG_MCP_NATIVE_DISABLE") == "1":
        return None
    candidates = []
    if NATIVE_DLL_PATH:
        candidates.append(NATIVE_DLL_PATH)
    else:
        base = os.path.join(X64DBG_HOME, "plugins", "x64dbg_mcp_native")
        candidates.append(base + ".dll")
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            candidates.append(base + ".dp64")
            candidates.append(base + ".dp32")
        else:
            candidates.append(base + ".dp32")
            candidates.append(base + ".dp64")

    for dll_path in candidates:
        if not os.path.isfile(dll_path):
            continue
        try:
            bridge = ctypes.cdll.LoadLibrary(dll_path)
        except Exception as exc:
            log("native bridge load failed (%s): %s" % (dll_path, exc))
            continue
        try:
            bridge.McpGetLogTailJson.argtypes = [ctypes.c_int]
            bridge.McpGetLogTailJson.restype = ctypes.c_char_p
            bridge.McpGetCallstackJson.argtypes = [ctypes.c_int]
            bridge.McpGetCallstackJson.restype = ctypes.c_char_p
            bridge.McpExecCommandJson.argtypes = [ctypes.c_char_p]
            bridge.McpExecCommandJson.restype = ctypes.c_char_p
            bridge.McpGuiGraphAtJson.argtypes = [ADDR_T]
            bridge.McpGuiGraphAtJson.restype = ctypes.c_char_p
            bridge.McpGuiShowReferencesJson.argtypes = [ADDR_T]
            bridge.McpGuiShowReferencesJson.restype = ctypes.c_char_p
            bridge.McpGuiGetCurrentGraphJson.argtypes = []
            bridge.McpGuiGetCurrentGraphJson.restype = ctypes.c_char_p
        except Exception:
            pass
        NATIVE_BRIDGE = bridge
        log("native bridge loaded: %s" % dll_path)
        return NATIVE_BRIDGE
    return None


def native_call_json(func, *args):
    bridge = load_native_bridge()
    if not bridge:
        return None
    try:
        raw = func(*args)
        if not raw:
            return None
        if isinstance(raw, bytes):
            text = raw
        else:
            text = raw
        return json.loads(text)
    except Exception as exc:
        log("native bridge call failed: %s" % exc)
        return None


def native_log_tail(limit):
    bridge = load_native_bridge()
    if not bridge:
        return None
    return native_call_json(bridge.McpGetLogTailJson, int(limit))


def native_callstack(depth):
    bridge = load_native_bridge()
    if not bridge:
        return None
    return native_call_json(bridge.McpGetCallstackJson, int(depth))


def native_exec_command(command):
    bridge = load_native_bridge()
    if not bridge:
        return None
    if isinstance(command, unicode):
        command = command.encode("utf-8")
    return native_call_json(bridge.McpExecCommandJson, command)


def native_gui_graph_at(address):
    bridge = load_native_bridge()
    if not bridge:
        return None
    return native_call_json(bridge.McpGuiGraphAtJson, address)


def native_gui_show_references(address):
    bridge = load_native_bridge()
    if not bridge:
        return None
    return native_call_json(bridge.McpGuiShowReferencesJson, address)


def native_gui_current_graph():
    bridge = load_native_bridge()
    if not bridge:
        return None
    return native_call_json(bridge.McpGuiGetCurrentGraphJson)


def log(message):
    line = "[MCP] %s" % message
    try:
        with LOG_LOCK:
            LOG_HISTORY.append({"ts": time.time(), "message": message})
    except Exception:
        pass
    try:
        print line
    except Exception:
        pass
    try:
        with open(LOG_FILE_PATH, "ab") as log_file:
            log_file.write(line + "\r\n")
    except Exception:
        pass


def parse_event_list(value):
    if not value:
        return []
    return [
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    ]


def normalize_event_list(events):
    seen = set()
    results = []
    for event in events or []:
        name = to_text(event).strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        results.append(name)
    return results


def safe_value(value):
    if value is None:
        return None
    if isinstance(value, (bool, int, long, float)):
        return value
    if isinstance(value, (unicode, str)):
        return value
    if isinstance(value, dict):
        return {to_text(key): safe_value(val) for key, val in value.iteritems()}
    if isinstance(value, (list, tuple, set)):
        return [safe_value(item) for item in value]
    try:
        return long(value)
    except Exception:
        return to_text(value)


def sanitize_event_data(kwargs):
    try:
        return {to_text(key): safe_value(val) for key, val in kwargs.iteritems()}
    except Exception:
        return {"raw": to_text(kwargs)}


def enqueue_event(payload):
    global DROPPED_EVENTS
    with EVENT_COND:
        if EVENT_QUEUE_LIMIT <= 0:
            DROPPED_EVENTS += 1
            return
        if len(EVENT_QUEUE) >= EVENT_QUEUE_LIMIT:
            drop_count = len(EVENT_QUEUE) - EVENT_QUEUE_LIMIT + 1
            for _ in range(drop_count):
                EVENT_QUEUE.popleft()
            DROPPED_EVENTS += drop_count
        EVENT_QUEUE.append(payload)
        EVENT_COND.notify()


def broadcast_event(payload):
    with CLIENT_LOCK:
        clients = list(CLIENTS)
    for sock in clients:
        try:
            respond(sock, payload)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            with CLIENT_LOCK:
                if sock in CLIENTS:
                    CLIENTS.remove(sock)


def event_worker():
    while True:
        with EVENT_COND:
            while not EVENT_QUEUE:
                EVENT_COND.wait()
            payload = EVENT_QUEUE.popleft()
        broadcast_event(payload)


def make_event_dispatcher(event_name):
    def handler(**kwargs):
        user_callback = USER_EVENT_CALLBACKS.get(event_name)
        if user_callback:
            try:
                user_callback(**kwargs)
            except Exception:
                log("event callback failed for %s" % event_name)
        if event_name in SUBSCRIBED_EVENTS:
            enqueue_event(
                {
                    "event": event_name,
                    "data": sanitize_event_data(kwargs),
                    "ts": time.time()
                }
            )
    return handler


def apply_event_handlers():
    if not SUPPORTED_EVENTS:
        return
    for event_name in SUPPORTED_EVENTS:
        should_listen = (
            event_name in SUBSCRIBED_EVENTS
            or event_name in USER_EVENT_CALLBACKS
        )
        if should_listen:
            dispatcher = EVENT_DISPATCHERS.get(event_name)
            if not dispatcher:
                dispatcher = make_event_dispatcher(event_name)
                EVENT_DISPATCHERS[event_name] = dispatcher
            _ORIGINAL_LISTEN(event_name, dispatcher)
        else:
            _ORIGINAL_LISTEN(event_name, None)


def configure_events(events):
    global SUBSCRIBED_EVENTS
    SUBSCRIBED_EVENTS = set(normalize_event_list(events))
    apply_event_handlers()
    return sorted(SUBSCRIBED_EVENTS)


def patched_listen(event_name, callback):
    name = to_text(event_name).strip().lower()
    if name not in SUPPORTED_EVENTS:
        raise Exception("%s Is not a valid event." % name)
    if callback is None:
        if name in USER_EVENT_CALLBACKS:
            del USER_EVENT_CALLBACKS[name]
    else:
        USER_EVENT_CALLBACKS[name] = callback
    apply_event_handlers()


def setup_event_hooks():
    if not SUPPORTED_EVENTS:
        log("no supported events found; event streaming disabled")
        return
    for event_name in SUPPORTED_EVENTS:
        existing = getattr(x64dbgpy.Event, event_name, None)
        if callable(existing):
            USER_EVENT_CALLBACKS[event_name] = existing
    x64dbgpy.Event.listen = patched_listen
    apply_event_handlers()
    if EVENTS_ENV is not None:
        configure_events(parse_event_list(EVENTS_ENV))


def to_int(value):
    if value is None:
        raise ValueError("missing value")
    if isinstance(value, (int, long)):
        return long(value)
    return long(str(value), 0)


def to_text(value):
    if value is None:
        return ""
    if isinstance(value, unicode):
        return value.encode("utf-8", "replace")
    return str(value)

def safe_int(value):
    if value is None:
        return None
    try:
        if isinstance(value, bool):
            return int(value)
        return int(value)
    except Exception:
        return None

def extract_fields(obj, names):
    result = {}
    if not obj:
        return result
    for name in names:
        if not hasattr(obj, name):
            continue
        try:
            value = getattr(obj, name)
        except Exception:
            continue
        if isinstance(value, (int, long, bool)):
            result[name] = int(value)
        elif isinstance(value, (unicode, str)):
            result[name] = to_text(value)
    return result

def extract_simple_attrs(obj):
    result = {}
    if not obj:
        return result
    for name in dir(obj):
        if name.startswith("_"):
            continue
        try:
            value = getattr(obj, name)
        except Exception:
            continue
        if callable(value):
            continue
        if isinstance(value, (int, long, bool)):
            result[name] = int(value)
        elif isinstance(value, (unicode, str)):
            result[name] = to_text(value)
    return result


def iter_vector(vec):
    try:
        for item in vec:
            yield item
        return
    except Exception:
        pass
    try:
        count = int(vec.size())
        for idx in range(count):
            yield vec[idx]
    except Exception:
        return


def decode_data(data, encoding):
    if encoding == "hex":
        return binascii.unhexlify(data)
    if encoding == "base64" or encoding is None:
        return base64.b64decode(data)
    raise ValueError("unsupported encoding: %s" % encoding)


def encode_data(data):
    return base64.b64encode(data)

def decode_hex(value):
    if isinstance(value, unicode):
        value = value.encode("utf-8", "replace")
    cleaned = "".join([ch for ch in value if ch not in " \t\r\n"])
    return binascii.unhexlify(cleaned)

def decode_pattern(pattern, encoding):
    if pattern is None:
        raise ValueError("missing pattern")
    if isinstance(pattern, unicode):
        raw = pattern
    else:
        raw = str(pattern)
    enc = (encoding or "hex").lower()
    if enc == "hex":
        return decode_hex(raw)
    if enc == "base64":
        return base64.b64decode(raw)
    if enc == "ascii":
        return raw.encode("ascii")
    if enc == "utf16" or enc == "utf16le":
        return raw.encode("utf-16le")
    raise ValueError("unsupported pattern encoding: %s" % enc)


def list_modules():
    modules = mod.GetList()
    if not modules:
        return []
    results = []
    for module in iter_vector(modules):
        results.append(
            {
                "base": int(module.base),
                "size": int(module.size),
                "entry": int(module.entry),
                "sectionCount": int(module.sectionCount),
                "name": to_text(module.name),
                "path": to_text(module.path),
            }
        )
    return results


def list_threads():
    info = x64dbg.ListInfo()
    ok = x64dbg.DbgGetThreadList(info)
    if not ok:
        return []
    threads = x64dbg.GetThreadInfoList(info)
    results = []
    for thread in iter_vector(threads):
        results.append(
            {
                "threadNumber": int(thread.ThreadNumber),
                "threadId": int(thread.ThreadId),
                "handle": int(thread.Handle),
                "startAddress": int(thread.ThreadStartAddress),
                "localBase": int(thread.ThreadLocalBase),
            }
        )
    return results


def list_registers():
    if is_64bit():
        names = [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rip",
            "rflags",
            "cs",
            "ds",
            "es",
            "fs",
            "gs",
            "ss",
            "cip",
            "csp",
        ]
    else:
        names = [
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "eip",
            "eflags",
            "cs",
            "ds",
            "es",
            "fs",
            "gs",
            "ss",
            "cip",
            "csp",
        ]
    results = {}
    for name in names:
        try:
            results[name] = int(x64dbg.DbgValFromString(name))
        except Exception:
            continue
    return results


def disasm_block(params):
    address = to_int(params.get("address"))
    count = params.get("count")
    detail = params.get("detail", False)
    if count is None:
        count = 16
    try:
        count = int(count)
    except Exception:
        raise ValueError("invalid count")
    if count <= 0 or count > MAX_DISASM_COUNT:
        raise ValueError("count must be between 1 and %d" % MAX_DISASM_COUNT)

    results = []
    current = address
    for _ in range(count):
        if detail:
            instr = x64dbg.DISASM_INSTR()
            ok = bool(x64dbg.DbgDisasmAt(current, instr))
            if not ok:
                break
            size = safe_int(instr.instr_size) or 1
            entry = {
                "address": int(current),
                "size": int(size),
                "instruction": to_text(instr.instruction)
            }
            instr_type = safe_int(instr.type)
            if instr_type is not None:
                entry["type"] = instr_type
            argcount = safe_int(instr.argcount) or 0
            entry["argcount"] = argcount
            args = []
            for idx in range(argcount):
                try:
                    arg = instr.arg[idx]
                except Exception:
                    break
                arg_entry = {}
                arg_type = safe_int(getattr(arg, "type", None))
                if arg_type is not None:
                    arg_entry["type"] = arg_type
                segment = safe_int(getattr(arg, "segment", None))
                if segment is not None:
                    arg_entry["segment"] = segment
                mnemonic = getattr(arg, "mnemonic", None)
                if mnemonic:
                    arg_entry["mnemonic"] = to_text(mnemonic)
                constant = safe_int(getattr(arg, "constant", None))
                if constant is not None:
                    arg_entry["constant"] = constant
                value = safe_int(getattr(arg, "value", None))
                if value is not None:
                    arg_entry["value"] = value
                memvalue = safe_int(getattr(arg, "memvalue", None))
                if memvalue is not None:
                    arg_entry["memvalue"] = memvalue
                if arg_entry:
                    args.append(arg_entry)
            if args:
                entry["args"] = args
        else:
            info = x64dbg.BASIC_INSTRUCTION_INFO()
            ok = bool(x64dbg.DbgDisasmFastAt(current, info))
            if not ok:
                break
            size = safe_int(info.size) or 1
            entry = {
                "address": int(current),
                "size": int(size),
                "instruction": to_text(info.instruction)
            }
            for key in ["type", "value", "memory", "addr", "branch", "call"]:
                value = safe_int(getattr(info, key, None))
                if value is not None:
                    entry[key] = value
        results.append(entry)
        current += int(size)
    return {"instructions": results, "count": len(results)}


def get_xrefs(params):
    address = to_int(params.get("address"))
    info = x64dbg.XREF_INFO()
    ok = bool(x64dbg.DbgXrefGet(address, info))
    if not ok:
        return {"xrefs": [], "count": 0}
    refcount = safe_int(info.refcount) or 0
    refs = []
    try:
        refs_ptr = info.references
    except Exception:
        refs_ptr = None
    for idx in range(refcount):
        try:
            record = refs_ptr[idx]
        except Exception:
            break
        addr = safe_int(getattr(record, "addr", None))
        ref_type = safe_int(getattr(record, "type", None))
        entry = {}
        if addr is not None:
            entry["address"] = addr
        if ref_type is not None:
            entry["type"] = ref_type
            entry["kind"] = XREF_TYPE_NAMES.get(ref_type, "unknown")
        if entry:
            refs.append(entry)
    return {"xrefs": refs, "count": len(refs)}


def get_memory_map():
    memmap = x64dbg.MEMMAP()
    ok = bool(x64dbg.DbgMemMap(memmap))
    if not ok:
        return {"regions": [], "count": 0}
    count = safe_int(memmap.count) or 0
    regions = []
    try:
        pages = memmap.page
    except Exception:
        pages = None
    for idx in range(count):
        try:
            page = pages[idx]
        except Exception:
            break
        region = {"index": idx}
        try:
            mbi = page.mbi
        except Exception:
            mbi = None
        try:
            info = page.info
        except Exception:
            info = None
        mbi_fields = extract_fields(
            mbi,
            [
                "BaseAddress",
                "AllocationBase",
                "AllocationProtect",
                "RegionSize",
                "State",
                "Protect",
                "Type",
                "base",
                "allocationBase",
                "allocationProtect",
                "regionSize",
                "state",
                "protect",
                "type"
            ]
        )
        info_fields = extract_fields(
            info,
            [
                "base",
                "size",
                "section",
                "module",
                "protect",
                "allocBase",
                "allocbase",
                "allocProtect",
                "type",
                "state",
                "info",
                "comment",
                "name"
            ]
        )
        if not mbi_fields:
            mbi_fields = extract_simple_attrs(mbi)
        if not info_fields:
            info_fields = extract_simple_attrs(info)
        if mbi_fields:
            region["mbi"] = mbi_fields
        if info_fields:
            region["info"] = info_fields
        regions.append(region)
    return {"regions": regions, "count": len(regions)}


def search_memory(params):
    address = to_int(params.get("address"))
    length = to_int(params.get("length"))
    if length <= 0:
        raise ValueError("length must be positive")
    if length > MAX_SEARCH_BYTES:
        raise ValueError("length exceeds max search size")
    pattern = params.get("pattern")
    encoding = params.get("encoding") or "hex"
    max_results = params.get("maxResults")
    if max_results is None:
        max_results = 20
    try:
        max_results = int(max_results)
    except Exception:
        raise ValueError("invalid maxResults")
    if max_results <= 0 or max_results > MAX_SEARCH_RESULTS:
        raise ValueError("maxResults must be between 1 and %d" % MAX_SEARCH_RESULTS)

    needle = decode_pattern(pattern, encoding)
    if not needle:
        raise ValueError("pattern is empty")
    needle_len = len(needle)
    chunk_size = 65536
    overlap = needle_len - 1 if needle_len > 1 else 0
    results = []
    offset = 0
    prev_tail = ""

    while offset < length and len(results) < max_results:
        to_read = min(chunk_size, length - offset)
        data = mem.Read(address + offset, to_read)
        if not data:
            break
        if prev_tail:
            data = prev_tail + data
        idx = 0
        while True:
            found = data.find(needle, idx)
            if found < 0:
                break
            match_addr = address + offset - len(prev_tail) + found
            results.append(int(match_addr))
            if len(results) >= max_results:
                break
            idx = found + 1
        if overlap > 0 and len(data) >= overlap:
            prev_tail = data[-overlap:]
        else:
            prev_tail = data
        offset += to_read

    return {
        "matches": results,
        "count": len(results),
        "truncated": len(results) >= max_results
    }


def get_call_stack(params):
    depth = params.get("depth")
    if depth is None:
        depth = 32
    try:
        depth = int(depth)
    except Exception:
        raise ValueError("invalid depth")
    if depth <= 0 or depth > MAX_STACK_DEPTH:
        raise ValueError("depth must be between 1 and %d" % MAX_STACK_DEPTH)

    native_result = native_callstack(depth)
    if native_result is not None:
        native_result["source"] = "native"
        return native_result

    modules = list_modules()
    ranges = []
    for module in modules:
        base = safe_int(module.get("base"))
        size = safe_int(module.get("size"))
        if base is None or size is None:
            continue
        ranges.append((base, base + size, module))

    stack_pointer = None
    try:
        stack_pointer = int(
            x64dbg.DbgValFromString("rsp" if is_64bit() else "esp")
        )
    except Exception:
        pass

    frames = []
    for idx in range(depth):
        try:
            value = stackapi.Peek(idx)
        except Exception:
            break
        if value is None:
            continue
        addr = int(value)
        entry = {"index": idx, "address": addr}
        entry["valid"] = bool(x64dbg.DbgMemIsValidReadPtr(addr))
        for start, end, module in ranges:
            if addr >= start and addr < end:
                entry["module"] = module.get("name")
                entry["moduleBase"] = module.get("base")
                entry["modulePath"] = module.get("path")
                break
        frames.append(entry)
    return {
        "stackPointer": stack_pointer,
        "frames": frames,
        "depth": depth,
        "source": "bridge"
    }


def log_tail(params):
    max_items = params.get("max")
    if max_items is None:
        max_items = 50
    try:
        max_items = int(max_items)
    except Exception:
        raise ValueError("invalid max")
    if max_items <= 0:
        return {"entries": [], "count": 0, "source": "bridge"}

    native_result = native_log_tail(max_items)
    if native_result is not None:
        native_result["source"] = "native"
        return native_result
    with LOG_LOCK:
        entries = list(LOG_HISTORY)
    if len(entries) > max_items:
        entries = entries[-max_items:]
    return {"entries": entries, "count": len(entries), "source": "bridge"}


def log_write(params):
    message = to_text(params.get("message"))
    if not message:
        raise ValueError("missing message")
    try:
        x64dbg.GuiAddLogMessage(message)
    except Exception:
        pass
    log("gui_log: %s" % message)
    return {"ok": True}


def set_breakpoint(params):
    address = to_int(params.get("address"))
    bp_type = params.get("type") or "software"
    enabled = params.get("enabled", True)
    if bp_type == "hardware":
        ok = bool(x64dbg.SetHardwareBreakpoint(address))
    else:
        ok = bool(x64dbg.SetBreakpoint(address))
    if enabled is False:
        try:
            x64dbg.DisableBreakpoint(address)
        except Exception:
            pass
    return {"ok": ok}


def handle_request(request):
    method = request.get("method")
    params = request.get("params") or {}

    if method == "debug.attach":
        pid = to_int(params.get("pid"))
        ok = bool(x64dbg.DbgCmdExecDirect("attach %d" % pid))
        return {"ok": ok}
    if method == "debug.detach":
        ok = bool(x64dbg.DbgCmdExecDirect("detach"))
        return {"ok": ok}
    if method == "debug.pause":
        ok = bool(x64dbg.Pause())
        return {"ok": ok}
    if method == "debug.step":
        step_type = params.get("type")
        if step_type == "into":
            ok = bool(x64dbg.StepIn())
        elif step_type == "over":
            ok = bool(x64dbg.StepOver())
        elif step_type == "out":
            ok = bool(x64dbg.StepOut())
        else:
            raise ValueError("invalid step type")
        return {"ok": ok}
    if method == "memory.read":
        address = to_int(params.get("address"))
        length = to_int(params.get("length"))
        data = mem.Read(address, length)
        return {"encoding": "base64", "data": encode_data(data)}
    if method == "memory.write":
        address = to_int(params.get("address"))
        data = params.get("data")
        encoding = params.get("encoding")
        raw = decode_data(data, encoding)
        ok = bool(mem.Write(address, raw))
        return {"ok": ok, "written": len(raw)}
    if method == "debug.listModules":
        return {"modules": list_modules()}
    if method == "debug.listThreads":
        return {"threads": list_threads()}
    if method == "debug.listRegisters":
        return {"registers": list_registers()}
    if method == "debug.setBreakpoint":
        return set_breakpoint(params)
    if method == "debug.exec":
        command = to_text(params.get("command"))
        mode = params.get("mode") or "direct"
        if mode == "async":
            ok = bool(x64dbg.DbgCmdExec(command))
        else:
            ok = bool(x64dbg.DbgCmdExecDirect(command))
        return {"ok": ok, "mode": mode}
    if method == "debug.execOutput":
        command = to_text(params.get("command"))
        result = native_exec_command(command)
        if result is None:
            raise ValueError("native command capture not available")
        if "source" not in result:
            result["source"] = "native"
        return result
    if method == "debug.eval":
        expression = to_text(params.get("expression"))
        value = long(x64dbg.DbgValFromString(expression))
        return {"value": value, "hex": "0x%X" % value}
    if method == "debug.disasm":
        return disasm_block(params)
    if method == "debug.xrefs":
        return get_xrefs(params)
    if method == "debug.memmap":
        return get_memory_map()
    if method == "memory.search":
        return search_memory(params)
    if method == "debug.callstack":
        return get_call_stack(params)
    if method == "debug.logTail":
        return log_tail(params)
    if method == "debug.logWrite":
        return log_write(params)
    if method == "gui.graph_at":
        address = to_int(params.get("address"))
        result = native_gui_graph_at(address)
        if result is None:
            try:
                shown = bool(x64dbg.GuiGraphAt(address))
            except Exception:
                raise ValueError("gui graph not available")
            return {"shown": shown, "address": address, "source": "python"}
        if "source" not in result:
            result["source"] = "native"
        return result
    if method == "gui.show_references":
        address = to_int(params.get("address"))
        result = native_gui_show_references(address)
        if result is None:
            raise ValueError("native GUI references not available")
        if "source" not in result:
            result["source"] = "native"
        return result
    if method == "gui.current_graph":
        result = native_gui_current_graph()
        if result is None:
            raise ValueError("native GUI graph not available")
        if "source" not in result:
            result["source"] = "native"
        return result
    if method == "event.configure":
        events = params.get("events") or []
        configured = configure_events(events)
        return {"events": configured}

    raise ValueError("unknown method: %s" % method)


def respond(sock, payload):
    data = json.dumps(payload, ensure_ascii=True)
    sock.sendall(data + "\n")


def client_loop(sock, addr):
    try:
        host, port = addr
        log("client connected from %s:%s" % (host, port))
    except Exception:
        log("client connected")
    with CLIENT_LOCK:
        CLIENTS.add(sock)
    try:
        file_obj = sock.makefile("rb")
        while True:
            try:
                line = file_obj.readline()
            except Exception as exc:
                try:
                    err_no = getattr(exc, "errno", None)
                    if err_no is None and exc.args:
                        err_no = exc.args[0]
                    if err_no == 10054:
                        break
                except Exception:
                    pass
                log("client read failed: %s" % exc)
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                request_id = request.get("id")
                response = {
                    "id": request_id,
                    "ok": True,
                    "result": handle_request(request),
                }
            except Exception as exc:
                response = {
                    "id": request_id if "request_id" in locals() else None,
                    "ok": False,
                    "error": {
                        "message": "%s" % exc,
                        "details": traceback.format_exc(),
                    },
                }
            respond(sock, response)
    finally:
        try:
            sock.close()
        except Exception:
            pass
        with CLIENT_LOCK:
            if sock in CLIENTS:
                CLIENTS.remove(sock)
        log("client disconnected")


def server_loop():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        log("bridge listening on %s:%d" % (HOST, PORT))
        while True:
            try:
                client, addr = server.accept()
            except Exception as exc:
                log("accept failed: %s" % exc)
                continue
            thread = threading.Thread(target=client_loop, args=(client, addr))
            thread.daemon = True
            thread.start()
    except Exception as exc:
        log("bridge failed to start: %s" % exc)
        try:
            log(traceback.format_exc())
        except Exception:
            pass


def start():
    log("bridge starting (python %s)" % sys.version.split()[0])
    log("bridge log file: %s" % LOG_FILE_PATH)
    load_native_bridge()
    setup_event_hooks()
    event_thread = threading.Thread(target=event_worker)
    event_thread.daemon = True
    event_thread.start()
    thread = threading.Thread(target=server_loop)
    thread.daemon = True
    thread.start()


def keepalive():
    log("bridge keepalive active")
    while True:
        time.sleep(1)


start()
if KEEPALIVE:
    keepalive()
