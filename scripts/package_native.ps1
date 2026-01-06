param(
  [string]$BuildDir = "$PSScriptRoot\\..\\native\\x64dbg_mcp_native\\build\\Release",
  [string]$OutDir = "$PSScriptRoot\\..\\release",
  [string]$OutFile = "x64dbg_mcp_native.zip"
)

$base = Join-Path $BuildDir "x64dbg_mcp_native"
$candidates = @("$base.dp64", "$base.dp32", "$base.dll")
$binaryPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $binaryPath) {
  Write-Error "Plugin binary not found in: $BuildDir"
  exit 1
}

$readme = Resolve-Path "$PSScriptRoot\\..\\native\\x64dbg_mcp_native\\README.md"
$iconPath = Resolve-Path "$PSScriptRoot\\..\\native\\x64dbg_mcp_native\\x64dbg_mcp_native.png" -ErrorAction SilentlyContinue
$bridgePath = Resolve-Path "$PSScriptRoot\\..\\bridge\\x64dbgpy_bridge.py" -ErrorAction SilentlyContinue
$bridge32Path = Resolve-Path "$PSScriptRoot\\..\\bridge\\x32dbgpy_bridge.py" -ErrorAction SilentlyContinue
$outDirResolved = Resolve-Path -Path $OutDir -ErrorAction SilentlyContinue
if (-not $outDirResolved) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
  $outDirResolved = Resolve-Path -Path $OutDir
}

$tempDir = Join-Path $outDirResolved "x64dbg_mcp_native"
if (Test-Path $tempDir) {
  Remove-Item -Recurse -Force $tempDir
}
New-Item -ItemType Directory -Path $tempDir | Out-Null

$ext = ([System.IO.Path]::GetExtension($binaryPath)).ToLowerInvariant()
if ($ext -eq ".dp64" -or $ext -eq ".dp32") {
  $pluginExt = $ext
} elseif ($BuildDir -match "\\\\x32\\\\") {
  $pluginExt = ".dp32"
} elseif ($BuildDir -match "\\\\x64\\\\") {
  $pluginExt = ".dp64"
} else {
  $pluginExt = if ([Environment]::Is64BitOperatingSystem) { ".dp64" } else { ".dp32" }
}

Copy-Item $binaryPath (Join-Path $tempDir ("x64dbg_mcp_native" + $pluginExt)) -Force
Copy-Item $binaryPath (Join-Path $tempDir "x64dbg_mcp_native.dll") -Force
Copy-Item $readme (Join-Path $tempDir "README.md") -Force
if ($iconPath) {
  Copy-Item $iconPath (Join-Path $tempDir "x64dbg_mcp_native.png") -Force
}
if ($bridgePath) {
  Copy-Item $bridgePath (Join-Path $tempDir "x64dbgpy_bridge.py") -Force
}
if ($bridge32Path) {
  Copy-Item $bridge32Path (Join-Path $tempDir "x32dbgpy_bridge.py") -Force
}

$zipPath = Join-Path $outDirResolved $OutFile
if (Test-Path $zipPath) {
  Remove-Item -Force $zipPath
}

Compress-Archive -Path (Join-Path $tempDir "*") -DestinationPath $zipPath

Write-Host "Created: $zipPath"
