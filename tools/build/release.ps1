# Reproducible audit build without local paths: avrt.dll and azcoop-net.exe are built with --locked, --remap-path-prefix, no debug info,
# /DEBUG:NONE (no PDB, its GUID differed between builds) and /TIMESTAMP:1, then scanned for the user profile, the checkout and the
# cargo/rustup folders. Crash symbols need a separate debug build. Usage: powershell -NoProfile -File tools\build\release.ps1
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$sysroot = (& rustc --print sysroot).Trim()
$env:RUSTFLAGS = "--remap-path-prefix=$root=/azcoop --remap-path-prefix=$cargoHome=/cargo --remap-path-prefix=$sysroot=/rust -C debuginfo=0 -C link-arg=/DEBUG:NONE -C link-arg=/TIMESTAMP:1"
Write-Host "[ .... ] cargo build --release --locked -p azeroth-coop-native -p azcoop-net (paths remapped)"
$t = [Diagnostics.Stopwatch]::StartNew()
& cargo build --release --locked -p azeroth-coop-native -p azcoop-net
if ($LASTEXITCODE -ne 0) { Write-Host "[FAILED] cargo build exited with $LASTEXITCODE"; exit 1 }
Write-Host ("[  OK  ] cargo build --release --locked ({0:N1} s)" -f $t.Elapsed.TotalSeconds)
$needles = @($env:USERPROFILE, $root, $cargoHome, $sysroot, $env:USERNAME) | Where-Object { $_ -and $_.Length -ge 4 } | Select-Object -Unique
$bad = 0
foreach ($name in 'avrt.dll', 'azcoop-net.exe') {
    $file = Join-Path $root "target\release\$name"
    $bytes = [IO.File]::ReadAllBytes($file)
    $ascii = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    foreach ($needle in $needles) {
        foreach ($variant in @($needle, $needle.Replace('\', '/'))) {
            $at = $ascii.IndexOf($variant, [StringComparison]::OrdinalIgnoreCase)
            if ($at -ge 0) {
                $bad++
                Write-Host "[FAILED] $name contains the local path part '$variant' at offset $at"
            }
        }
    }
    # live-test switches (cargo feature test-hooks) never ship: their env names must not be in a release binary
    $at = $ascii.IndexOf('AZCOOP_TEST_', [StringComparison]::Ordinal)
    if ($at -ge 0) {
        $bad++
        Write-Host "[FAILED] $name contains a live-test switch ('$($ascii.Substring($at, [Math]::Min(40, $ascii.Length - $at)).Split([char]0)[0])' at offset $at): build without --features test-hooks"
    }
    Write-Host ("[ INFO ] {0}: {1:N0} bytes, sha256 {2}" -f $name, $bytes.Length, (Get-FileHash $file -Algorithm SHA256).Hash.ToLower().Substring(0, 16))
}
if ($bad) { exit 1 }
Write-Host "[  OK  ] no local paths in avrt.dll and azcoop-net.exe"
