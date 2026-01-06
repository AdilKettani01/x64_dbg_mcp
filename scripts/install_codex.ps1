param(
  [Parameter(Mandatory = $true)] [string]$ConfigPath,
  [string]$X64dbgServer = "$PSScriptRoot\\..\\dist\\index.js"
)

$configDir = Split-Path -Parent $ConfigPath
if ($configDir -and -not (Test-Path $configDir)) {
  New-Item -ItemType Directory -Path $configDir | Out-Null
}

if (Test-Path $ConfigPath) {
  $raw = Get-Content -Path $ConfigPath -Raw
  if ($raw.Trim().Length -gt 0) {
    $config = $raw | ConvertFrom-Json
  } else {
    $config = @{}
  }
} else {
  $config = @{}
}

if (-not $config.mcpServers) {
  $config | Add-Member -MemberType NoteProperty -Name mcpServers -Value @{}
}

$config.mcpServers.x64dbg = @{
  command = "node"
  args = @($X64dbgServer)
  env = @{
    X64DBG_TRANSPORT = "tcp"
    X64DBG_HOST = "127.0.0.1"
    X64DBG_PORT = "31337"
    X64DBG_LOG_LEVEL = "info"
  }
}

$json = $config | ConvertTo-Json -Depth 8
$json | Set-Content -Path $ConfigPath -Encoding UTF8

Write-Host "Updated: $ConfigPath"
