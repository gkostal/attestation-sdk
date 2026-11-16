#Requires -Version 7.0
<#
.SYNOPSIS
    Build, test and package the libnvat bundle for the MAA prototype (Linux x64, Ubuntu 22.04).

.DESCRIPTION
    1. builds the Ubuntu 22.04 build image (dev/maa-prototype/Dockerfile);
    2. captures live NVIDIA OCSP responses (host python + `cryptography`; falls back to responses
       captured earlier under <OutDir>\fixtures\ocsp when offline) and test-responder REVOKED variants;
    3. builds libnvat (Release, shared, USE_SYSTEM_DEPS=OFF) with default symbol visibility, runs the
       unit tests (`ctest -L unit`) and the offline collateral tests again with `--network none`;
    4. builds libnvat again with NVAT_HIDE_INTERNAL_SYMBOLS=ON (only nvat_* exported), gates on
       `nm -D --defined-only` / DT_NEEDED, and stages include/, lib/linux-x64/, fixtures/, ldd.txt;
    5. runs the bundle's C self-test (selftest/smoke) offline in a dotnet runtime-deps jammy container for
       each verdict scenario and checks the resulting EARs;
    6. writes manifest.json (sha256 of every file, NVAT git commit, build date).

    Needs: Docker (Linux engine), python with `cryptography`, git.

.PARAMETER OutDir
    Bundle directory (created; stale generated files are replaced, fixtures\ocsp is kept as an offline cache).

.PARAMETER SkipTests
    Skip steps 3 (the container unit-test run); the bundle build, gates and self-test still run.

.PARAMETER PipIndexUrl
    PyPI index for the in-container python venv (default: $env:PIP_INDEX_URL, else the host's pip
    configuration). Needed on networks where files.pythonhosted.org is not reachable.

.EXAMPLE
    .\build-bundle.ps1 -OutDir C:\src\nvat-bundle
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $OutDir,
    [switch] $SkipTests,
    [string] $PipIndexUrl = $env:PIP_INDEX_URL,
    [string] $ImageTag = 'nvat-maa-build:22.04',
    [string] $WorkVolume = 'nvat-maa-work',
    [string] $RuntimeImage = 'mcr.microsoft.com/dotnet/runtime-deps:8.0-jammy-amd64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = $PSScriptRoot
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path
$ContainerDir = Join-Path $ScriptDir 'container'
$SelftestDir = Join-Path $ScriptDir 'selftest'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

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

# Runs a bash command inside the build image. The source tree is mounted read-only at /src-ro and
# mirrored into the work volume by container/sync-src.sh (builds never write into the host tree).
function Invoke-Container([string] $Command, [switch] $NoNetwork, [string[]] $ExtraMounts = @()) {
    $dockerArgs = @('run', '--rm')
    if ($NoNetwork) { $dockerArgs += @('--network', 'none') }
    if ($PipIndexUrl) { $dockerArgs += @('-e', "PIP_INDEX_URL=$PipIndexUrl") }
    $dockerArgs += @('-v', "${RepoRoot}:/src-ro:ro", '-v', "${ContainerDir}:/scripts:ro",
                     '-v', "${SelftestDir}:/selftest:ro", '-v', "${WorkVolume}:/work")
    foreach ($mount in $ExtraMounts) { $dockerArgs += @('-v', $mount) }
    $dockerArgs += @($ImageTag, 'bash', '-c', $Command)
    Invoke-Native 'docker' $dockerArgs
}

# --- preflight --------------------------------------------------------------------------------
Write-Step 'Preflight'
foreach ($tool in 'docker', 'git', 'python') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is required but not on PATH" }
}
Invoke-Native 'python' @('-c', 'import cryptography')
$NvatCommit = (git -C $RepoRoot rev-parse HEAD).Trim()
$NvatBranch = (git -C $RepoRoot rev-parse --abbrev-ref HEAD).Trim()
$NvatDirty = [bool](git -C $RepoRoot status --porcelain)
if (-not $PipIndexUrl) {
    try {
        $configured = pip config list 2>$null | Select-String 'index-url'
        if ($configured) { $PipIndexUrl = ($configured.Line -replace ".*index-url='([^']*)'.*", '$1') }
    } catch {
        Write-Host 'pip not found on the host; the container uses the default PyPI index' -ForegroundColor Yellow
    }
}
Write-Host "NVAT $NvatBranch @ $NvatCommit (dirty: $NvatDirty)"
Write-Host "bundle -> $OutDir"

# Stale generated files go; the captured OCSP responses stay as the offline cache. The Windows library
# (lib\win-x64\, win-x64\; build-bundle-windows.ps1) is left alone.
foreach ($stale in 'include', 'lib\linux-x64', 'symbols', 'selftest', 'fixtures\corim', 'fixtures\cmw', 'ldd.txt',
                   'build-info.json', 'manifest.json', 'README.md') {
    Remove-Item -Recurse -Force (Join-Path $OutDir $stale) -ErrorAction SilentlyContinue
}

# --- OCSP fixtures (host) ----------------------------------------------------------------------
Write-Step 'Capture OCSP responses (live; falls back to earlier captures when offline)'
$OcspDir = Join-Path $OutDir 'fixtures\ocsp'
$OcspIndex = Join-Path $OutDir 'fixtures\ocsp-index.json'
Invoke-Native 'python' @((Join-Path $ScriptDir 'capture_ocsp.py'), '--out-dir', $OcspDir,
                         '--revoked-dir', (Join-Path $OutDir 'fixtures\ocsp-revoked'),
                         '--index', $OcspIndex)

# --- build image + work volume -----------------------------------------------------------------
Write-Step "Build image $ImageTag"
Invoke-Native 'docker' @('build', '-t', $ImageTag, '-f', (Join-Path $ScriptDir 'Dockerfile'), $ScriptDir)
Invoke-Native 'docker' @('volume', 'create', $WorkVolume)

Write-Step 'Sync sources into the work volume'
Invoke-Container 'bash /scripts/sync-src.sh'

# --- unit tests --------------------------------------------------------------------------------
if (-not $SkipTests) {
    Write-Step 'Build libnvat (default visibility) + unit tests'
    Invoke-Container 'bash /scripts/build.sh test'
    Write-Step 'Run the unit suite (ctest -L unit)'
    Invoke-Container 'bash /scripts/run-unit-tests.sh'
    Write-Step 'Offline collateral tests with --network none'
    Invoke-Container 'bash /scripts/test.sh -R "CApiCollateralCb|CorimStoreCollateralTest|RimLookupKeyTest"' -NoNetwork
} else {
    Write-Host 'unit tests skipped (-SkipTests)' -ForegroundColor Yellow
}

# --- bundle build ------------------------------------------------------------------------------
Write-Step 'Build libnvat with hidden internal symbols'
Invoke-Container 'bash /scripts/build.sh bundle'
Write-Step 'Verify symbols / dependencies and stage the bundle'
Invoke-Container 'bash /scripts/bundle.sh /out' -ExtraMounts @("${OutDir}:/out")
Copy-Item (Join-Path $SelftestDir 'check_ear.py') (Join-Path $OutDir 'selftest\check_ear.py')

# --- self-test in a runtime-like container -----------------------------------------------------
Write-Step "Self-test offline in $RuntimeImage"
$index = Get-Content -Raw $OcspIndex | ConvertFrom-Json
$latestThisUpdate = ($index.responses | Measure-Object -Property this_update_epoch -Maximum).Maximum
$latestNextUpdate = ($index.responses | Measure-Object -Property next_update_epoch -Maximum).Maximum
$pinned = $latestThisUpdate + 300
$expiredAt = $latestNextUpdate + 3600

& docker image inspect $RuntimeImage *> $null
if ($LASTEXITCODE -ne 0) {
    & docker pull $RuntimeImage
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "could not pull $RuntimeImage; running the self-test in $ImageTag instead"
        $RuntimeImage = $ImageTag
    }
}

$scenarios = @(
    @{ Name = 'affirming';              Scenario = 'affirming';     Time = $pinned;    Extra = @() },
    @{ Name = 'ocsp-missing';           Scenario = 'ocsp-missing';  Time = $pinned;    Extra = @() },
    @{ Name = 'ocsp-revoked';           Scenario = 'ocsp-revoked';  Time = $pinned;    Extra = @() },
    @{ Name = 'corim-missing';          Scenario = 'corim-missing'; Time = $pinned;    Extra = @() },
    @{ Name = 'ocsp-expired-enforced';     Scenario = 'affirming';  Time = $expiredAt; Extra = @('--enforce', '1') },
    @{ Name = 'ocsp-expired-not-enforced'; Scenario = 'affirming';  Time = $expiredAt; Extra = @('--enforce', '0') }
)
$failed = @()
foreach ($s in $scenarios) {
    $ear = Join-Path $OutDir "selftest\ear-$($s.Name).json"
    $log = Join-Path $OutDir "selftest\$($s.Name).log"
    $dockerArgs = @('run', '--rm', '--network', 'none', '-v', "${OutDir}:/bundle:ro", $RuntimeImage,
                    '/bundle/selftest/smoke', '/bundle', $s.Scenario, '--time', "$($s.Time)") + $s.Extra
    & docker @dockerArgs 1> $ear 2> $log
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL $($s.Name): smoke exited with $LASTEXITCODE (see $log)" -ForegroundColor Red
        $failed += $s.Name
        continue
    }
    & python (Join-Path $SelftestDir 'check_ear.py') $s.Name $ear
    if ($LASTEXITCODE -ne 0) { $failed += $s.Name }
}
if ($failed.Count -gt 0) { throw "self-test scenarios failed: $($failed -join ', ')" }

# --- README + manifest -------------------------------------------------------------------------
Copy-Item (Join-Path $ScriptDir 'README.md') (Join-Path $OutDir 'README.md')

Write-Step 'Write manifest.json'
$buildInfo = Get-Content -Raw (Join-Path $OutDir 'build-info.json') | ConvertFrom-Json
$nvatVersion = ((Select-String -Path (Join-Path $OutDir 'include\nvat.h') -Pattern 'NVAT_VERSION_STRING\s+"([^"]+)"').Matches[0].Groups[1].Value)
$files = Get-ChildItem $OutDir -Recurse -File | Where-Object {
    $relative = $_.FullName.Substring($OutDir.Length + 1)
    $_.Name -ne 'manifest.json' -and -not $relative.StartsWith('win-x64\') -and -not $relative.StartsWith('lib\win-x64\')
} | Sort-Object FullName
$entries = foreach ($file in $files) {
    [ordered]@{
        path   = $file.FullName.Substring($OutDir.Length + 1).Replace('\', '/')
        size   = $file.Length
        sha256 = (Get-FileHash -Algorithm SHA256 $file.FullName).Hash.ToLowerInvariant()
    }
}
$manifest = [ordered]@{
    name             = 'nvat-maa-bundle'
    nvat_version     = $nvatVersion
    nvat_git_commit  = $NvatCommit
    nvat_git_branch  = $NvatBranch
    nvat_git_dirty   = $NvatDirty
    build_date_utc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    platform         = 'linux-x64 (Ubuntu 22.04 build, glibc >= 2.35 / GLIBCXX 3.4.30 compatible)'
    build            = $buildInfo
    files            = @($entries)
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8NoBOM (Join-Path $OutDir 'manifest.json')

Write-Host ''
Write-Host "Bundle ready: $OutDir ($(@($entries).Count) files, NVAT $NvatCommit)" -ForegroundColor Green
