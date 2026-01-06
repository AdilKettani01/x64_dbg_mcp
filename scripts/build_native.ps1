param(
  [string]$SdkDir = $env:X64DBG_SDK_DIR,
  [string]$SourceDir = (Resolve-Path "$PSScriptRoot\\..\\native\\x64dbg_mcp_native"),
  [string]$BuildDir = "$PSScriptRoot\\..\\native\\x64dbg_mcp_native\\build",
  [ValidateSet("Release", "Debug")] [string]$Config = "Release"
)

if (-not $SdkDir -or $SdkDir.Trim() -eq "") {
  $SdkDir = "C:\\Tools\\x64dbg\\pluginsdk"
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
  Write-Error "cmake is not installed or not on PATH."
  exit 1
}

if (-not (Test-Path $SdkDir)) {
  Write-Error "X64DBG_SDK_DIR not found: $SdkDir"
  exit 1
}

$env:X64DBG_SDK_DIR = $SdkDir

cmake -S $SourceDir -B $BuildDir
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

cmake --build $BuildDir --config $Config
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

$configDir = Join-Path $BuildDir $Config
$candidates = @(
  (Join-Path $configDir "x64dbg_mcp_native.dp64"),
  (Join-Path $configDir "x64dbg_mcp_native.dp32"),
  (Join-Path $configDir "x64dbg_mcp_native.dll")
)
$binaryPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $binaryPath) {
  Write-Error "Build succeeded but plugin binary not found in: $configDir"
  exit 1
}

Write-Host "Built: $binaryPath"
