# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Windows counterpart of prepare-test-data.sh: materialises the unit-test fixtures (certs, unsigned
# CoRIM/CoMID/CoEV/EAT .diag -> .cbor, signed CoRIM, OCSP fixtures) under <TestData>.
#
#   prepare-test-data.ps1 -TestData <testdata-root> -VenvDir <python venv to create / reuse>
#
# Needs: cbor-diag (cargo install cbor-diag-cli), python 3 (the venv gets cbor2 and cryptography, pinned as in
# requirements-dev.txt) and Git for Windows (its bash and openssl run the certificate scripts).
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $TestData,
    [Parameter(Mandatory = $true)] [string] $VenvDir
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Checked([string] $Exe, [string[]] $Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "'$Exe $($Arguments -join ' ')' failed with exit code $LASTEXITCODE" }
}

if (-not (Get-Command cbor-diag -ErrorAction SilentlyContinue)) {
    throw "cbor-diag missing. Run 'cargo install cbor-diag-cli'."
}

$git = Get-Command git -ErrorAction SilentlyContinue
$bash = if ($git) { Join-Path (Split-Path -Parent (Split-Path -Parent $git.Source)) 'bin\bash.exe' } else { $null }
if (-not $bash -or -not (Test-Path $bash)) {
    throw 'Git for Windows (bin\bash.exe) is needed for the certificate scripts.'
}

# The python venv: only what the fixture generators import (requirements-dev.txt also lists the zcbor CLI).
$python = Join-Path $VenvDir 'Scripts\python.exe'
if (-not (Test-Path $python)) {
    Write-Host "Creating venv at $VenvDir"
    Invoke-Checked 'python' @('-m', 'venv', $VenvDir)
    $requirements = Get-Content (Join-Path $repoRoot 'requirements-dev.txt') | Where-Object { $_ -match '^(cbor2|cryptography)==' }
    Invoke-Checked $python (@('-m', 'pip', 'install', '--quiet') + $requirements)
}

# Git Bash would turn "-subj /CN=..." arguments into Windows paths.
$env:MSYS_NO_PATHCONV = '1'
foreach ($certDir in 'x509_cert_chain\generate_test_certs.sh', 'tls_test\generate_tls_certs.sh') {
    $dir = Join-Path $TestData (Split-Path -Parent $certDir)
    Push-Location $dir
    try {
        Invoke-Checked $bash @((Split-Path -Leaf $certDir))
    } finally {
        Pop-Location
    }
}

foreach ($kind in 'corim', 'comid', 'coev', 'eat') {
    foreach ($diag in Get-ChildItem (Join-Path $TestData "sample_rims\$kind") -Filter *.diag -ErrorAction SilentlyContinue) {
        $cbor = [IO.Path]::ChangeExtension($diag.FullName, '.cbor')
        & $env:ComSpec /c "cbor-diag --from=diag --to=bytes < `"$($diag.FullName)`" > `"$cbor`""
        if ($LASTEXITCODE -ne 0) { throw "cbor-diag failed for $($diag.FullName)" }
    }
}

Invoke-Checked $python @((Join-Path $TestData 'sample_rims\corim\generate_fixtures.py')) | Out-Null

# OCSP fixtures: REVOKED variants for the real Rubin chain + a full test-CA PKI with GOOD/REVOKED responses.
Invoke-Checked $python @((Join-Path $repoRoot 'unit-tests\testdata\ocsp_fixtures\generate_test_ocsp_fixtures.py'), $TestData)
