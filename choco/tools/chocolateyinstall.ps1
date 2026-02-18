$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  unzipLocation  = $toolsDir
  url64bit       = '$url$'
  checksum64     = '$checksum$'
  checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

# Verify the extracted exe exists
$exePath = Join-Path $toolsDir 'psnet.exe'
if (-not (Test-Path $exePath)) {
  throw "psnet.exe was not found after extraction at $exePath"
}

Write-Host "psnet installed successfully. Run 'psnet' from any terminal." -ForegroundColor Green
Write-Host "For packet inspection (Wire preview), run your terminal as Administrator." -ForegroundColor Yellow
