cmake_minimum_required(VERSION 3.20)

project(x64dbg_mcp_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(X64DBG_SDK_DIR $ENV{X64DBG_SDK_DIR})
if(NOT X64DBG_SDK_DIR)
  set(X64DBG_SDK_DIR "C:/Tools/x64dbg/pluginsdk")
endif()

add_library(x64dbg_mcp_native SHARED x64dbg_mcp_native.cpp)

target_include_directories(x64dbg_mcp_native PRIVATE ${X64DBG_SDK_DIR})
target_compile_definitions(x64dbg_mcp_native PRIVATE _CRT_SECURE_NO_WARNINGS)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(X64DBG_BRIDGE_LIB "x64bridge.lib")
  set(X64DBG_DBG_LIB "x64dbg.lib")
  set(X64DBG_PLUGIN_SUFFIX ".dp64")
else()
  set(X64DBG_BRIDGE_LIB "x32bridge.lib")
  set(X64DBG_DBG_LIB "x32dbg.lib")
  set(X64DBG_PLUGIN_SUFFIX ".dp32")
endif()

target_link_directories(x64dbg_mcp_native PRIVATE ${X64DBG_SDK_DIR})
target_link_libraries(x64dbg_mcp_native PRIVATE ${X64DBG_BRIDGE_LIB} ${X64DBG_DBG_LIB})

set_target_properties(x64dbg_mcp_native PROPERTIES OUTPUT_NAME "x64dbg_mcp_native")
set_target_properties(x64dbg_mcp_native PROPERTIES SUFFIX ${X64DBG_PLUGIN_SUFFIX})
