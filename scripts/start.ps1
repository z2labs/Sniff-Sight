# One-click launcher: scripts\start.ps1 [--demo] [sniff_sight options...]
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (-not (Test-Path .venv\Scripts\python.exe)) { & "$PSScriptRoot\install.ps1" }
$port = 8000
for ($i = 0; $i -lt $args.Count - 1; $i++) { if ($args[$i] -eq '--http-port') { $port = $args[$i + 1] } }
if ($args -contains '--demo') { Start-Job { Start-Sleep 3; Start-Process "http://127.0.0.1:$using:port/" } | Out-Null }
& .venv\Scripts\python.exe -m sniff_sight @args