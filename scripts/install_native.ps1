param(
  [string]$DllPath = "$PSScriptRoot\\..\\native\\x64dbg_mcp_native\\build\\Release\\x64dbg_mcp_native.dll",
  [string]$PluginsDir = "C:\\Tools\\x64dbg\\release\\x64\\plugins",
  [string]$IconPath = "$PSScriptRoot\\..\\native\\x64dbg_mcp_native\\x64dbg_mcp_native.png",
  [string]$BridgePath = "$PSScriptRoot\\..\\bridge\\x64dbgpy_bridge.py",
  [string]$Bridge32Path = "$PSScriptRoot\\..\\bridge\\x32dbgpy_bridge.py"
)

$binaryPath = $DllPath
if (-not (Test-Path $binaryPath)) {
  $buildDir = Split-Path -Parent $DllPath
  $base = Join-Path $buildDir "x64dbg_mcp_native"
  $candidates = @("$base.dp64", "$base.dp32", "$base.dll")
  $binaryPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $binaryPath) {
  Write-Error "Plugin binary not found. Checked: $DllPath"
  exit 1
}

if (-not (Test-Path $PluginsDir)) {
  Write-Error "Plugins dir not found: $PluginsDir"
  exit 1
}

$ext = ([System.IO.Path]::GetExtension($binaryPath)).ToLowerInvariant()
if ($ext -eq ".dp64" -or $ext -eq ".dp32") {
  $pluginExt = $ext
} elseif ($PluginsDir -match "\\\\x32\\\\") {
  $pluginExt = ".dp32"
} elseif ($PluginsDir -match "\\\\x64\\\\") {
  $pluginExt = ".dp64"
} else {
  $pluginExt = if ([Environment]::Is64BitOperatingSystem) { ".dp64" } else { ".dp32" }
}

$pluginDest = Join-Path $PluginsDir ("x64dbg_mcp_native" + $pluginExt)
Copy-Item $binaryPath $pluginDest -Force
Write-Host "Installed: $pluginDest"

$dllDest = Join-Path $PluginsDir "x64dbg_mcp_native.dll"
Copy-Item $binaryPath $dllDest -Force
Write-Host "Installed: $dllDest"

if (Test-Path $IconPath) {
  $iconDest = Join-Path $PluginsDir "x64dbg_mcp_native.png"
  Copy-Item $IconPath $iconDest -Force
  Write-Host "Installed: $iconDest"
}

if (Test-Path $BridgePath) {
  $bridgeDest = Join-Path $PluginsDir "x64dbgpy_bridge.py"
  Copy-Item $BridgePath $bridgeDest -Force
  Write-Host "Installed: $bridgeDest"
}

if (Test-Path $Bridge32Path) {
  $bridge32Dest = Join-Path $PluginsDir "x32dbgpy_bridge.py"
  Copy-Item $Bridge32Path $bridge32Dest -Force
  Write-Host "Installed: $bridge32Dest"
}
