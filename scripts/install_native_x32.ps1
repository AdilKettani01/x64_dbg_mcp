param(
  [string]$PluginsDir = "C:\\Tools\\x64dbg\\release\\x32\\plugins",
  [ValidateSet("Release", "Debug")] [string]$Config = "Release",
  [string]$BuildDir = "$PSScriptRoot\\..\\native\\x64dbg_mcp_native\\build-x32"
)

$binaryPath = Join-Path (Join-Path $BuildDir $Config) "x64dbg_mcp_native.dp32"
& "$PSScriptRoot\\install_native.ps1" -DllPath $binaryPath -PluginsDir $PluginsDir
