#include <windows.h>

#include <algorithm>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "bridgemain.h"
#include "bridgegraph.h"
#include "_dbgfunctions.h"
#include "_plugins.h"

static int g_plugin_handle = 0;
static HMODULE g_module = nullptr;
static std::mutex g_json_mutex;
static std::string g_last_json;
static std::string g_log_path;
static std::vector<unsigned char> g_icon_bytes;
static ICONDATA g_icon_data = {};

static const int MENU_ENTRY_START_MCP = 0x1000;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
  UNREFERENCED_PARAMETER(reserved);
  if (reason == DLL_PROCESS_ATTACH) {
    g_module = hModule;
  }
  return TRUE;
}

static std::string JsonEscape(const std::string &input) {
  std::string output;
  output.reserve(input.size());
  for (size_t i = 0; i < input.size(); ++i) {
    unsigned char ch = static_cast<unsigned char>(input[i]);
    switch (ch) {
      case '\"':
        output += "\\\"";
        break;
      case '\\':
        output += "\\\\";
        break;
      case '\b':
        output += "\\b";
        break;
      case '\f':
        output += "\\f";
        break;
      case '\n':
        output += "\\n";
        break;
      case '\r':
        output += "\\r";
        break;
      case '\t':
        output += "\\t";
        break;
      default:
        if (ch < 0x20) {
          char buf[7];
          _snprintf_s(buf, sizeof(buf), "\\u%04x", ch);
          output += buf;
        } else {
          output.push_back(static_cast<char>(ch));
        }
    }
  }
  return output;
}

static std::string FormatHex(duint value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << value;
  return stream.str();
}

static void AppendHexArray(std::ostringstream &out,
                           const std::vector<duint> &values) {
  for (size_t i = 0; i < values.size(); ++i) {
    if (i > 0) {
      out << ",";
    }
    out << "\"" << FormatHex(values[i]) << "\"";
  }
}

static std::string GetLogPath() {
  if (!g_log_path.empty()) {
    return g_log_path;
  }
  char temp_path[MAX_PATH] = {0};
  DWORD len = GetTempPathA(MAX_PATH, temp_path);
  if (len == 0 || len >= MAX_PATH) {
    g_log_path = "x64dbg_mcp_native.log";
  } else {
    g_log_path = std::string(temp_path) + "x64dbg_mcp_native.log";
  }
  return g_log_path;
}

static std::string GetEnvVar(const char *name) {
  DWORD len = GetEnvironmentVariableA(name, nullptr, 0);
  if (len == 0) {
    return "";
  }
  std::string value(len, '\0');
  DWORD written = GetEnvironmentVariableA(name, &value[0], len);
  if (written == 0) {
    return "";
  }
  value.resize(written);
  return value;
}

static std::string GetModuleDir() {
  char path[MAX_PATH] = {0};
  HMODULE module = g_module;
  if (!module) {
    module = GetModuleHandleA("x64dbg_mcp_native.dll");
  }
  DWORD len = GetModuleFileNameA(module, path, MAX_PATH);
  if (len == 0 || len >= MAX_PATH) {
    return "";
  }
  std::string full(path, len);
  size_t pos = full.find_last_of("\\/");
  if (pos == std::string::npos) {
    return "";
  }
  return full.substr(0, pos);
}

static bool FileExists(const std::string &path) {
  if (path.empty()) {
    return false;
  }
  DWORD attrs = GetFileAttributesA(path.c_str());
  if (attrs == INVALID_FILE_ATTRIBUTES) {
    return false;
  }
  return (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static bool LoadFileBytes(const std::string &path,
                          std::vector<unsigned char> &out) {
  std::ifstream file(path.c_str(), std::ios::in | std::ios::binary);
  if (!file.is_open()) {
    return false;
  }
  file.seekg(0, std::ios::end);
  std::streamoff end = file.tellg();
  if (end <= 0) {
    return false;
  }
  std::streamsize size = static_cast<std::streamsize>(end);
  file.seekg(0, std::ios::beg);
  out.resize(static_cast<size_t>(size));
  file.read(reinterpret_cast<char *>(out.data()), size);
  return file.gcount() == size;
}

static std::string ResolveIconPath() {
  std::string env = GetEnvVar("X64DBG_MCP_ICON");
  if (!env.empty() && FileExists(env)) {
    return env;
  }
  std::string dir = GetModuleDir();
  if (dir.empty()) {
    return "";
  }
  std::string candidate = dir + "\\x64dbg_mcp_native.png";
  if (FileExists(candidate)) {
    return candidate;
  }
  candidate = dir + "\\start_mcp.png";
  if (FileExists(candidate)) {
    return candidate;
  }
  return "";
}

static std::string ResolveBridgeScriptPath() {
  std::string env = GetEnvVar("X64DBG_MCP_BRIDGE");
  if (!env.empty() && FileExists(env)) {
    return env;
  }
  std::string dir = GetModuleDir();
  if (dir.empty()) {
    return "";
  }
  bool prefer32 =
#if defined(_WIN64)
      false;
#else
      true;
#endif
  std::string candidate;
  if (prefer32) {
    candidate = dir + "\\x32dbgpy_bridge.py";
    if (FileExists(candidate)) {
      return candidate;
    }
    candidate = dir + "\\bridge\\x32dbgpy_bridge.py";
    if (FileExists(candidate)) {
      return candidate;
    }
  }
  candidate = dir + "\\x64dbgpy_bridge.py";
  if (FileExists(candidate)) {
    return candidate;
  }
  candidate = dir + "\\bridge\\x64dbgpy_bridge.py";
  if (FileExists(candidate)) {
    return candidate;
  }
  return "";
}

static void SetupMenuIcon(int entry_id) {
  std::string icon_path = ResolveIconPath();
  if (icon_path.empty()) {
    return;
  }
  if (!LoadFileBytes(icon_path, g_icon_bytes)) {
    return;
  }
  g_icon_data.data = g_icon_bytes.data();
  g_icon_data.size = static_cast<duint>(g_icon_bytes.size());
  _plugin_menuentryseticon(g_plugin_handle, entry_id, &g_icon_data);
}

static void StartMcpBridge() {
  std::string script = ResolveBridgeScriptPath();
  if (script.empty()) {
    _plugin_logputs(
        "[x64dbg-mcp-native] bridge script not found. Set X64DBG_MCP_BRIDGE "
        "or copy x64dbgpy_bridge.py into the plugins folder.");
    return;
  }
  std::string cmd = "PyRunScriptAsync \"" + script + "\"";
  bool ok = DbgCmdExecDirect(cmd.c_str());
  if (ok) {
    _plugin_logputs("[x64dbg-mcp-native] MCP bridge started.");
  } else {
    _plugin_logputs(
        "[x64dbg-mcp-native] Failed to start MCP bridge. Is x64dbgpy loaded?");
  }
}

static void HandleMenuEntry(CBTYPE cbType, void *callbackInfo) {
  if (cbType != CB_MENUENTRY || !callbackInfo) {
    return;
  }
  const PLUG_CB_MENUENTRY *info =
      static_cast<const PLUG_CB_MENUENTRY *>(callbackInfo);
  if (info->hEntry == MENU_ENTRY_START_MCP) {
    StartMcpBridge();
  }
}

static std::vector<std::string> LoadLogLines() {
  std::vector<std::string> lines;
  const std::string path = GetLogPath();
  GuiFlushLog();
  GuiLogSave(path.c_str());

  std::ifstream file(path.c_str(), std::ios::in | std::ios::binary);
  if (!file.is_open()) {
    return lines;
  }
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line[line.size() - 1] == '\r') {
      line.erase(line.size() - 1);
    }
    lines.push_back(line);
  }
  return lines;
}

static std::vector<std::string> TailLogLines(int max_lines) {
  std::vector<std::string> lines = LoadLogLines();
  if (max_lines <= 0) {
    return std::vector<std::string>();
  }
  if (static_cast<int>(lines.size()) > max_lines) {
    lines.erase(lines.begin(), lines.end() - max_lines);
  }
  return lines;
}

static const char *SetJsonResult(const std::string &json) {
  std::lock_guard<std::mutex> guard(g_json_mutex);
  g_last_json = json;
  return g_last_json.c_str();
}

extern "C" __declspec(dllexport) const char *McpGetLogTailJson(int max_lines) {
  std::vector<std::string> lines = TailLogLines(max_lines);
  std::ostringstream out;
  out << "{\"entries\":[";
  for (size_t i = 0; i < lines.size(); ++i) {
    if (i > 0) {
      out << ",";
    }
    out << "{\"message\":\"" << JsonEscape(lines[i]) << "\"}";
  }
  out << "],\"count\":" << lines.size() << "}";
  return SetJsonResult(out.str());
}

extern "C" __declspec(dllexport) const char *McpExecCommandJson(
    const char *command) {
  if (!command) {
    return SetJsonResult("{\"ok\":false,\"output\":[],\"count\":0}");
  }
  std::vector<std::string> before = LoadLogLines();
  bool ok = DbgCmdExecDirect(command);
  std::vector<std::string> after = LoadLogLines();

  std::vector<std::string> output;
  if (after.size() >= before.size()) {
    output.assign(after.begin() + before.size(), after.end());
  } else {
    output = after;
  }

  std::ostringstream out;
  out << "{\"ok\":" << (ok ? "true" : "false") << ",\"output\":[";
  for (size_t i = 0; i < output.size(); ++i) {
    if (i > 0) {
      out << ",";
    }
    out << "\"" << JsonEscape(output[i]) << "\"";
  }
  out << "],\"count\":" << output.size() << "}";
  return SetJsonResult(out.str());
}

extern "C" __declspec(dllexport) const char *McpGetCallstackJson(
    int max_frames) {
  const DBGFUNCTIONS *funcs = DbgFunctions();
  if (!funcs || !funcs->GetCallStackEx) {
    return SetJsonResult("{\"frames\":[],\"count\":0}");
  }

  DBGCALLSTACK callstack = {};
  funcs->GetCallStackEx(&callstack, true);

  int total = callstack.total;
  if (max_frames > 0 && total > max_frames) {
    total = max_frames;
  }

  std::ostringstream out;
  out << "{\"frames\":[";
  for (int i = 0; i < total; ++i) {
    const DBGCALLSTACKENTRY &entry = callstack.entries[i];
    if (i > 0) {
      out << ",";
    }
    out << "{";
    out << "\"addr\":\"" << FormatHex(entry.addr) << "\",";
    out << "\"from\":\"" << FormatHex(entry.from) << "\",";
    out << "\"to\":\"" << FormatHex(entry.to) << "\",";
    out << "\"comment\":\"" << JsonEscape(entry.comment) << "\"";
    out << "}";
  }
  out << "],\"count\":" << total << "}";

  if (callstack.entries) {
    BridgeFree(callstack.entries);
  }

  return SetJsonResult(out.str());
}

extern "C" __declspec(dllexport) const char *McpGuiGraphAtJson(duint addr) {
  duint result = GuiGraphAt(addr);
  std::ostringstream out;
  out << "{\"shown\":" << (result ? "true" : "false") << ",\"address\":\""
      << FormatHex(addr) << "\",\"result\":\"" << FormatHex(result) << "\"}";
  return SetJsonResult(out.str());
}

extern "C" __declspec(dllexport) const char *McpGuiShowReferencesJson(
    duint addr) {
  SELECTIONDATA selection = {};
  selection.start = addr;
  selection.end = addr;
  bool selection_ok = GuiSelectionSet(GUI_DISASSEMBLY, &selection);
  GuiShowReferences();
  std::ostringstream out;
  out << "{\"shown\":true,\"selection\":" << (selection_ok ? "true" : "false")
      << ",\"address\":\"" << FormatHex(addr) << "\"}";
  return SetJsonResult(out.str());
}

extern "C" __declspec(dllexport) const char *McpGuiGetCurrentGraphJson() {
  BridgeCFGraphList graph_list = {};
  GuiGetCurrentGraph(&graph_list);
  int count = graph_list.nodes.count;
  if (count <= 0 || !graph_list.nodes.data) {
    return SetJsonResult("{\"entry\":\"0x0\",\"nodes\":[],\"count\":0}");
  }

  BridgeCFGraph graph(&graph_list, false);
  BridgeCFGraph::Free(&graph_list);

  std::ostringstream out;
  out << "{\"entry\":\"" << FormatHex(graph.entryPoint) << "\",\"nodes\":[";
  bool first = true;
  for (const auto &it : graph.nodes) {
    const BridgeCFNode &node = it.second;
    if (!first) {
      out << ",";
    }
    first = false;
    out << "{";
    out << "\"start\":\"" << FormatHex(node.start) << "\",";
    out << "\"end\":\"" << FormatHex(node.end) << "\",";
    out << "\"brtrue\":\"" << FormatHex(node.brtrue) << "\",";
    out << "\"brfalse\":\"" << FormatHex(node.brfalse) << "\",";
    out << "\"icount\":" << node.icount << ",";
    out << "\"terminal\":" << (node.terminal ? "true" : "false") << ",";
    out << "\"split\":" << (node.split ? "true" : "false") << ",";
    out << "\"indirectcall\":" << (node.indirectcall ? "true" : "false");
    if (!node.exits.empty()) {
      out << ",\"exits\":[";
      AppendHexArray(out, node.exits);
      out << "]";
    }
    if (!node.instrs.empty()) {
      out << ",\"instructions\":[";
      for (size_t i = 0; i < node.instrs.size(); ++i) {
        if (i > 0) {
          out << ",";
        }
        out << "{\"address\":\"" << FormatHex(node.instrs[i].addr) << "\"}";
      }
      out << "]";
    }
    out << "}";
  }
  out << "],\"count\":" << graph.nodes.size() << "}";
  return SetJsonResult(out.str());
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT *initStruct) {
  g_plugin_handle = initStruct->pluginHandle;
  initStruct->sdkVersion = PLUG_SDKVERSION;
  initStruct->pluginVersion = 1;
  strncpy_s(initStruct->pluginName, "x64dbg-mcp-native", _TRUNCATE);
  _plugin_registercallback(initStruct->pluginHandle, CB_MENUENTRY,
                           HandleMenuEntry);
  return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT *setupStruct) {
  if (!setupStruct) {
    return;
  }
  _plugin_menuaddentry(setupStruct->hMenu, MENU_ENTRY_START_MCP, "Start MCP");
  SetupMenuIcon(MENU_ENTRY_START_MCP);
}

extern "C" __declspec(dllexport) bool plugstop() {
  return true;
}
