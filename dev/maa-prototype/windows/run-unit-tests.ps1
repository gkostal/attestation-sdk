#Requires -Version 7.0
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Runs NVAT's unit suite (ctest -L unit) from a Windows test build tree; the counterpart of
    container/run-unit-tests.sh.

.DESCRIPTION
    A subset of the suite talks to the live NVIDIA services (RIM / OCSP / NRAS) and needs a real
    NVAT_C_SDK_TEST_SERVICE_KEY; those tests (container/live-service-tests.txt, the same list as on Linux)
    may fail. Every other test must pass. Exit status 0 when no other test failed.

.PARAMETER BuildDir
    The test build tree (build-bundle-windows.ps1: <WorkDir>\test).

.PARAMETER CTestArgs
    Extra ctest arguments, e.g. -R CApiCollateralCb.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BuildDir,
    [string[]] $CTestArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not (Get-Command ctest -ErrorAction SilentlyContinue)) {
    $null = Import-VsDevEnvironment
}
if (-not $env:NVAT_C_SDK_TEST_SERVICE_KEY) {
    # The unit-test environment refuses to start without a non-empty key; tests that need a real one fail by design.
    $env:NVAT_C_SDK_TEST_SERVICE_KEY = 'nvat-maa-dummy-service-key'
}
$jobs = if ($env:CTEST_JOBS) { $env:CTEST_JOBS } else { '4' }
$timeout = if ($env:CTEST_TIMEOUT) { $env:CTEST_TIMEOUT } else { '600' }

$log = Join-Path $BuildDir 'unit-tests.log'
$failedLog = Join-Path $BuildDir 'Testing\Temporary\LastTestsFailed.log'
# ctest leaves the previous run's list in place when nothing fails.
Remove-Item $failedLog -ErrorAction SilentlyContinue
Push-Location $BuildDir
try {
    & ctest -L unit --output-on-failure -j $jobs --timeout $timeout @CTestArgs 2>&1 | Tee-Object -FilePath $log |
        Select-String -Pattern 'tests passed|tests failed|\*\*\*(Failed|Skipped|Exception|Timeout)'
} finally {
    Pop-Location
}

$expected = Get-Content (Join-Path $PSScriptRoot '..\container\live-service-tests.txt') |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } | Sort-Object -Unique
$actual = @()
if (Test-Path $failedLog) {
    $actual = Get-Content $failedLog | ForEach-Object { $_ -replace '^\d+:', '' } | Sort-Object -Unique
}
$unexpected = @($actual | Where-Object { $expected -notcontains $_ })
$expectedHit = @($actual | Where-Object { $expected -contains $_ }).Count
$text = Get-Content -Raw $log
$ran = if ($text -match 'tests passed, (\d+) tests failed out of (\d+)') { [int]$Matches[2] } else { 0 }
$skipped = ([regex]::Matches($text, '\*\*\*Skipped')).Count

Write-Host ("=== unit test summary: total={0} passed={1} skipped={2} failed={3} (expected live-service failures: {4}, unexpected: {5})" -f
    ($ran + $skipped), ($ran - $actual.Count), $skipped, $actual.Count, $expectedHit, $unexpected.Count)
if ($ran -eq 0) {
    Write-Host 'NO TESTS RAN' -ForegroundColor Red
    exit 1
}
if ($unexpected.Count -gt 0) {
    Write-Host 'UNEXPECTED FAILURES:' -ForegroundColor Red
    $unexpected | ForEach-Object { Write-Host "  $_" }
    exit 1
}
exit 0
