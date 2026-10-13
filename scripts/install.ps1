<#
.SYNOPSIS
  Sniff-Sight installer for Windows: Wireshark + Python 3.11+ (winget), .venv, pip install -e .
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -WithSpinel -NoWireshark
#>
param([switch]$NoWireshark, [switch]$WithSpinel, [switch]$Tailscale)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Have($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function Winget($id) {
  if (-not (Have winget)) { Write-Warning "winget not found: install $id manually"; return }
  winget install --id $id -e --accept-source-agreements --accept-package-agreements
}

function Find-Python {
  foreach ($c in @('py -3.13', 'py -3.12', 'py -3.11', 'python')) {
    $exe, $arg = $c.Split(' ', 2)
    if (-not (Have $exe)) { continue }
    try {
      $v = & $exe $arg -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
      if ($v -and [version]$v -ge [version]'3.11') { return , @($exe, $arg) }
    } catch {}
  }
  return $null
}

if (-not $NoWireshark) {
  if (Test-Path "$env:ProgramFiles\Wireshark\tshark.exe") { Write-Host 'Wireshark: found' }
  else { Write-Host 'Installing Wireshark (tshark + Npcap prompt)...'; Winget 'WiresharkFoundation.Wireshark' }
}

$py = Find-Python
if (-not $py) {
  Write-Host 'Installing Python 3.12...'; Winget 'Python.Python.3.12'
  $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
  $py = Find-Python
  if (-not $py) { throw 'Python 3.11+ not found; open a new terminal and run this script again.' }
}
Write-Host "Python: $($py -join ' ')"

if (-not (Test-Path .venv\Scripts\python.exe)) { & $py[0] $py[1] -m venv .venv }
& .venv\Scripts\python.exe -m pip install --upgrade pip
& .venv\Scripts\python.exe -m pip install -e .

if ($WithSpinel) {
  $sv = Join-Path (Split-Path -Parent $Root) 'spinel_venv'
  if (-not (Test-Path "$sv\Scripts\python.exe")) { & $py[0] $py[1] -m venv $sv }
  & "$sv\Scripts\python.exe" -m pip install pyspinel pyserial
  Write-Host "RCP sniffer venv: $sv (override with SNIFF_SPINEL_VENV)"
}

if ($Tailscale) { Winget 'Tailscale.Tailscale' }
else { Write-Host 'Optional: remote access via Tailscale (winget install Tailscale.Tailscale); see README "Remote access". Always use --auth-file with funnel.' }

Write-Host ''
Write-Host 'Done. Try:  scripts\start.bat --demo      (no hardware)'
Write-Host '       or:  scripts\start.bat --esp-port COM7 --thread-port COM16 --channel 15'