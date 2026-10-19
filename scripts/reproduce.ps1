# Rebuild the native binaries reproducibly and compare their SHA-256 to the released values.
# Usage: powershell -NoProfile -File scripts\reproduce.ps1
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$expected = @{
    'avrt.dll'       = '34bb35d2a3fc42ede1e821ea963c99df38bb695f3d88b089c8a7aed5c5c9855a'
    'azcoop-net.exe' = '07317673dc3141e1076d26ce4a889d47304d8788ba045b2ecfe1330920dd7ad5'
}
Write-Host "[ .... ] reproducible rebuild from $root"
& powershell -NoProfile -File (Join-Path $root 'tools\build\release.ps1')
if ($LASTEXITCODE -ne 0) { Write-Host "[FAILED] release build exited $LASTEXITCODE"; exit 1 }
$bad = 0
foreach ($name in $expected.Keys) {
    $file = Join-Path $root "target\release\$name"
    $got = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
    if ($got -eq $expected[$name]) {
        Write-Host "[  OK  ] $name sha256 $got matches the release"
    } else {
        $bad++
        Write-Host "[FAILED] $name sha256 $got does NOT match the released $($expected[$name])"
    }
}
if ($bad) { Write-Host "[FAILED] reproduce: $bad mismatch(es)"; exit 1 }
Write-Host "[  OK  ] reproduce: every binary matches the released hash"
