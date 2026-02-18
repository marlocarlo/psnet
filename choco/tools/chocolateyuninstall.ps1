$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Remove the extracted executable
$exePath = Join-Path $toolsDir 'psnet.exe'
if (Test-Path $exePath) {
  Remove-Item $exePath -Force
  Write-Host "Removed psnet.exe"
}

# Clean up the zip tracking file created by Install-ChocolateyZipPackage
$zipTxt = Join-Path $toolsDir '$zipFileName$.zip.txt'
if (Test-Path $zipTxt) {
  Remove-Item $zipTxt -Force
}

Write-Host "psnet has been uninstalled." -ForegroundColor Green
