# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Helpers shared by build-bundle-windows.ps1 and windows\run-unit-tests.ps1 (dot-sourced).

function Write-Step([string] $Title) {
    Write-Host ''
    Write-Host "=== $Title" -ForegroundColor Cyan
}

function Invoke-Native([string] $Exe, [string[]] $Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$Exe $($Arguments -join ' ')' failed with exit code $LASTEXITCODE"
    }
}

# Finds the newest Visual Studio with the x64 C++ tools and imports its x64 developer environment
# (vcvars64.bat: cl, link, dumpbin, the Windows SDK, and VS's CMake and Ninja) into this process.
function Import-VsDevEnvironment {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'Visual Studio (vswhere.exe) was not found; see BUILD-WINDOWS.md' }
    $instance = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json |
        ConvertFrom-Json | Select-Object -First 1
    if (-not $instance) { throw 'no Visual Studio with the "Desktop development with C++" workload (VC.Tools.x86.x64)' }
    $vcvars = Join-Path $instance.installationPath 'VC\Auxiliary\Build\vcvars64.bat'
    $lines = & $env:ComSpec /c "call `"$vcvars`" >nul && set"
    if ($LASTEXITCODE -ne 0) { throw "$vcvars failed" }
    foreach ($line in $lines) {
        $eq = $line.IndexOf('=')
        if ($eq -gt 0) {
            [Environment]::SetEnvironmentVariable($line.Substring(0, $eq), $line.Substring($eq + 1), 'Process')
        }
    }
    [pscustomobject]@{
        Path        = $instance.installationPath
        Version     = $instance.installationVersion
        DisplayName = $instance.displayName
    }
}

# vcpkg: the given root when it is a vcpkg, else the copy bundled with Visual Studio.
function Resolve-VcpkgRoot([string] $Requested, $Vs) {
    foreach ($candidate in $Requested, (Join-Path $Vs.Path 'VC\vcpkg')) {
        if ($candidate -and (Test-Path (Join-Path $candidate 'scripts\buildsystems\vcpkg.cmake'))) {
            return (Resolve-Path $candidate).Path
        }
    }
    throw 'vcpkg was not found: install the Visual Studio "vcpkg package manager" component or set VCPKG_ROOT'
}

# CBOR diagnostic notation -> CBOR bytes (cmd redirection keeps the bytes intact).
function Convert-CborDiag([string] $Diag, [string] $Cbor) {
    & $env:ComSpec /c "cbor-diag --from=diag --to=bytes < `"$Diag`" > `"$Cbor`""
    if ($LASTEXITCODE -ne 0) { throw "cbor-diag failed for $Diag" }
}

# SHA-256 of a text file with LF line endings (the same header hashes alike from either platform).
function Get-NormalizedSha256([string] $Path) {
    $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
    $hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text))
    return ([Convert]::ToHexString($hash)).ToLowerInvariant()
}
