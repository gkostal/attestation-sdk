#Requires -Version 7.0
<#
.SYNOPSIS
    Build, test and package nvat.dll for the MAA prototype (Windows x64, MSVC).

.DESCRIPTION
    The Windows counterpart of build-bundle.ps1: it adds the Windows library to the same bundle
    directory (lib\win-x64\ and win-x64\) next to the Linux one. See BUILD-WINDOWS.md for the tools.

    1. finds Visual Studio (vswhere), loads its x64 build environment, and finds vcpkg (VS's bundled
       copy unless -VcpkgRoot / VCPKG_ROOT name another);
    2. stages the shared fixtures: captures live NVIDIA OCSP responses (falling back to earlier
       captures when offline), converts the Rubin CoRIMs from CBOR diagnostic notation, copies the
       golden CMW. When the bundle already has the Linux library, its fixtures are kept: the Linux
       manifest.json lists them, and a new OCSP capture would not match it;
    3. unless -SkipTests: builds NVAT as a static library with its unit tests and runs them
       (windows\run-unit-tests.ps1);
    4. builds nvat.dll (Release, OpenSSL / curl / libxml2 / xmlsec / zlib from vcpkg, statically
       linked; PDB; CFG, Spectre, CET) and gates it with windows\check_dll.py: only the functions of
       nvat.h are exported, only system / CRT DLLs are imported, the hardening flags are set;
    5. stages include\nvat.h (with LF line endings, byte for byte the header the Linux build writes)
       and lib\win-x64\{nvat.dll,nvat.lib,nvat.pdb};
    6. builds the C self-test (selftest\smoke.c) and runs it offline for every verdict scenario, plus
       one with OPENSSL_CONF pointing at a configuration that would break NVAT's OpenSSL (it must be
       ignored) and one with the host's own OpenSSL (-HostOpenSslDll) loaded in the same process;
    7. writes win-x64\build-info.json and win-x64\manifest.json.

.PARAMETER OutDir
    Bundle directory, shared with the Linux bundle (only the Windows files, the header and, without a
    Linux library in it, the shared fixtures are replaced).

.PARAMETER WorkDir
    Build trees and the vcpkg installation (default C:\src\nvat-win). Keep the path short: vcpkg and
    cargo build trees are deep.

.PARAMETER SkipTests
    Skip step 3.

.PARAMETER VcpkgRoot
    vcpkg to use (default: $env:VCPKG_ROOT when it points at a vcpkg, else Visual Studio's).

.PARAMETER HostOpenSslDll
    A libcrypto DLL of another OpenSSL to load next to nvat.dll in the self-test (default: MAA's
    OpenSSL 1.1.1 NuGet package under C:\src\maa, when present).

.PARAMETER Jobs
    Parallel compile jobs and test processes (default 4). Several NVAT sources need gigabytes of compiler
    heap each, and every test runs in its own process, which antivirus scanning makes expensive.

.EXAMPLE
    .\build-bundle-windows.ps1 -OutDir C:\src\nvat-bundle
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $OutDir,
    [string] $WorkDir = 'C:\src\nvat-win',
    [switch] $SkipTests,
    [string] $VcpkgRoot = $env:VCPKG_ROOT,
    [string] $HostOpenSslDll = 'C:\src\maa\src\packages\OpenSSL.1.1.1579.74\x64\release\bin\libcrypto-1_1-x64.dll',
    [int] $Jobs = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = $PSScriptRoot
$WindowsDir = Join-Path $ScriptDir 'windows'
$SelftestDir = Join-Path $ScriptDir 'selftest'
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path
$SdkDir = Join-Path $RepoRoot 'nv-attestation-sdk-cpp'
$TestData = Join-Path $SdkDir 'unit-tests\testdata'
$Triplet = 'x64-windows-static-md-nvat'

New-Item -ItemType Directory -Force $OutDir, $WorkDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$WorkDir = (Resolve-Path $WorkDir).Path
$WinOut = Join-Path $OutDir 'win-x64'
$LibOut = Join-Path $OutDir 'lib\win-x64'

. (Join-Path $WindowsDir 'common.ps1')

# --- preflight --------------------------------------------------------------------------------
Write-Step 'Preflight'
$vs = Import-VsDevEnvironment
$VcpkgRoot = Resolve-VcpkgRoot $VcpkgRoot $vs
foreach ($tool in 'cmake', 'ninja', 'cl', 'dumpbin', 'cargo', 'rustc', 'git', 'python', 'cbor-diag') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is required but not on PATH (see BUILD-WINDOWS.md)" }
}
Invoke-Native 'python' @('-c', 'import cryptography')
$NvatCommit = (git -C $RepoRoot rev-parse HEAD).Trim()
$NvatBranch = (git -C $RepoRoot rev-parse --abbrev-ref HEAD).Trim()
$NvatDirty = [bool](git -C $RepoRoot status --porcelain)
Write-Host "Visual Studio $($vs.Version) at $($vs.Path)"
Write-Host "vcpkg $VcpkgRoot"
Write-Host "NVAT $NvatBranch @ $NvatCommit (dirty: $NvatDirty)"
Write-Host "bundle -> $OutDir, build trees -> $WorkDir"

# The Linux manifest.json lists the shared fixtures, so with the Linux library present they are kept as they are.
$linuxBundled = Test-Path (Join-Path $OutDir 'manifest.json')
$stales = @($WinOut, $LibOut)
if (-not $linuxBundled) { $stales += (Join-Path $OutDir 'fixtures\corim'), (Join-Path $OutDir 'fixtures\cmw') }
foreach ($stale in $stales) {
    Remove-Item -Recurse -Force $stale -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force $WinOut, $LibOut, (Join-Path $WinOut 'selftest'), (Join-Path $WinOut 'symbols') | Out-Null

# --- fixtures (shared with the Linux bundle) ---------------------------------------------------
$OcspIndex = Join-Path $OutDir 'fixtures\ocsp-index.json'
if ($linuxBundled) {
    Write-Step 'Fixtures: kept from the Linux bundle (its manifest.json lists them)'
} else {
    Write-Step 'Capture OCSP responses (live; falls back to earlier captures when offline)'
    Invoke-Native 'python' @((Join-Path $ScriptDir 'capture_ocsp.py'), '--out-dir', (Join-Path $OutDir 'fixtures\ocsp'),
                             '--revoked-dir', (Join-Path $OutDir 'fixtures\ocsp-revoked'), '--index', $OcspIndex)

    Write-Step 'CoRIM and CMW fixtures'
    # Named by the canonical RIM id of their rim-locator, i.e. the CORIM collateral lookup key.
    New-Item -ItemType Directory -Force (Join-Path $OutDir 'fixtures\corim'), (Join-Path $OutDir 'fixtures\cmw') | Out-Null
    Convert-CborDiag (Join-Path $TestData 'sample_rims\corim\rubin_vbios_example.diag') (Join-Path $OutDir 'fixtures\corim\GR100_081D_9900230000.cbor')
    Convert-CborDiag (Join-Path $TestData 'sample_rims\corim\rubin_driver_example.diag') (Join-Path $OutDir 'fixtures\corim\NV_GPU_DRIVER_GR100_620.54.cbor')
    Copy-Item (Join-Path $TestData 'sample_attestation_data\rubin_evidence.cmw.json') (Join-Path $OutDir 'fixtures\cmw\rubin_evidence.cmw.json')
}

# --- unit tests --------------------------------------------------------------------------------
$commonCMakeArgs = @(
    '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
    "-DCMAKE_TOOLCHAIN_FILE=$VcpkgRoot\scripts\buildsystems\vcpkg.cmake",
    "-DVCPKG_MANIFEST_DIR=$WindowsDir",
    "-DVCPKG_OVERLAY_TRIPLETS=$WindowsDir\triplets",
    "-DVCPKG_TARGET_TRIPLET=$Triplet",
    "-DVCPKG_INSTALLED_DIR=$WorkDir\vcpkg_installed",
    '-DUSE_SYSTEM_DEPS=ON',
    # Release with a PDB: debug information in the objects (/Z7), linked into nvat.pdb. /MD: the
    # project's CMake policies keep the runtime library in these flags.
    '-DCMAKE_C_FLAGS_RELEASE=/MD /O2 /Ob2 /DNDEBUG /Z7',
    '-DCMAKE_CXX_FLAGS_RELEASE=/MD /O2 /Ob2 /DNDEBUG /Z7',
    '-DCMAKE_SHARED_LINKER_FLAGS_RELEASE=/DEBUG /OPT:REF /OPT:ICF /INCREMENTAL:NO',
    '-DCMAKE_EXE_LINKER_FLAGS_RELEASE=/DEBUG /OPT:REF /OPT:ICF /INCREMENTAL:NO'
)

if (-not $SkipTests) {
    Write-Step 'Build NVAT (static) + unit tests'
    $testBuild = Join-Path $WorkDir 'test'
    Invoke-Native 'cmake' (@('-S', $SdkDir, '-B', $testBuild) + $commonCMakeArgs + @('-DBUILD_SHARED_LIBS=OFF', '-DBUILD_TESTING=ON'))
    Invoke-Native 'cmake' @('--build', $testBuild, '--parallel', "$Jobs")
    Write-Step 'Run the unit suite'
    $env:CTEST_JOBS = "$Jobs"
    & (Join-Path $WindowsDir 'run-unit-tests.ps1') -BuildDir $testBuild
    if ($LASTEXITCODE -ne 0) { throw 'unit tests failed' }
} else {
    Write-Host 'unit tests skipped (-SkipTests)' -ForegroundColor Yellow
}

# --- bundle build ------------------------------------------------------------------------------
Write-Step 'Build nvat.dll'
$bundleBuild = Join-Path $WorkDir 'bundle'
Invoke-Native 'cmake' (@('-S', $SdkDir, '-B', $bundleBuild) + $commonCMakeArgs + @('-DBUILD_SHARED_LIBS=ON', '-DBUILD_TESTING=OFF'))
Invoke-Native 'cmake' @('--build', $bundleBuild, '--parallel', "$Jobs")

Write-Step 'Verify exports / dependencies / hardening and stage the library'
New-Item -ItemType Directory -Force (Join-Path $OutDir 'include') | Out-Null
$header = Join-Path $OutDir 'include\nvat.h'
# LF line endings: the header the Linux build writes into the same bundle, byte for byte.
$headerText = [IO.File]::ReadAllText((Join-Path $bundleBuild 'include\nvat.h')).Replace("`r`n", "`n")
[IO.File]::WriteAllText($header, $headerText, [Text.UTF8Encoding]::new($false))
foreach ($file in 'nvat.dll', 'nvat.lib', 'nvat.pdb') {
    Copy-Item (Join-Path $bundleBuild $file) (Join-Path $LibOut $file) -Force
}
$dumpbin = (Get-Command dumpbin).Source
Invoke-Native 'python' @((Join-Path $WindowsDir 'check_dll.py'), $dumpbin, (Join-Path $LibOut 'nvat.dll'), $header, (Join-Path $WinOut 'symbols'))

# --- self-test ---------------------------------------------------------------------------------
Write-Step 'Self-test (offline, every verdict scenario)'
$smokeDir = Join-Path $WinOut 'selftest'
Copy-Item (Join-Path $SelftestDir 'smoke.c') (Join-Path $smokeDir 'smoke.c')
Copy-Item (Join-Path $SelftestDir 'check_ear.py') (Join-Path $smokeDir 'check_ear.py')
Push-Location $smokeDir
try {
    Invoke-Native 'cl' @('/nologo', '/std:c11', '/W4', '/WX', '/O1', '/guard:cf', "/I$(Join-Path $OutDir 'include')", 'smoke.c',
                         '/Fe:smoke.exe', '/link', (Join-Path $LibOut 'nvat.lib'), '/guard:cf', '/CETCOMPAT')
    Remove-Item smoke.obj -ErrorAction SilentlyContinue
} finally {
    Pop-Location
}

$index = Get-Content -Raw $OcspIndex | ConvertFrom-Json
$latestThisUpdate = ($index.responses | Measure-Object -Property this_update_epoch -Maximum).Maximum
$latestNextUpdate = ($index.responses | Measure-Object -Property next_update_epoch -Maximum).Maximum
$pinned = $latestThisUpdate + 300
$expiredAt = $latestNextUpdate + 3600

# An OpenSSL configuration that NVAT's OpenSSL would fail with (no FIPS provider): it must be ignored.
$hostileConf = Join-Path $smokeDir 'openssl-fips-only.cnf'
Set-Content -Encoding ascii $hostileConf @(
    'openssl_conf = openssl_init', '[openssl_init]', 'alg_section = evp_properties',
    '[evp_properties]', 'default_properties = fips=yes')

$scenarios = @(
    @{ Name = 'affirming';                 Scenario = 'affirming';     Time = $pinned;    Extra = @() },
    @{ Name = 'ocsp-missing';              Scenario = 'ocsp-missing';  Time = $pinned;    Extra = @() },
    @{ Name = 'ocsp-revoked';              Scenario = 'ocsp-revoked';  Time = $pinned;    Extra = @() },
    @{ Name = 'corim-missing';             Scenario = 'corim-missing'; Time = $pinned;    Extra = @() },
    @{ Name = 'ocsp-expired-enforced';     Scenario = 'affirming';     Time = $expiredAt; Extra = @('--enforce', '1') },
    @{ Name = 'ocsp-expired-not-enforced'; Scenario = 'affirming';     Time = $expiredAt; Extra = @('--enforce', '0') },
    @{ Name = 'openssl-conf-ignored';      Scenario = 'affirming';     Time = $pinned;    Extra = @(); Check = 'affirming'; Conf = $hostileConf }
)
if ($HostOpenSslDll -and (Test-Path $HostOpenSslDll)) {
    $scenarios += @{ Name = 'host-openssl'; Scenario = 'affirming'; Time = $pinned; Extra = @('--host-openssl', $HostOpenSslDll); Check = 'affirming' }
} else {
    Write-Warning "no host OpenSSL DLL ($HostOpenSslDll): the coexistence scenario is skipped"
}

$failed = @()
$savedPath = $env:PATH
$savedConf = $env:OPENSSL_CONF
try {
    $env:PATH = "$LibOut;$env:PATH"
    foreach ($s in $scenarios) {
        $ear = Join-Path $smokeDir "ear-$($s.Name).json"
        $log = Join-Path $smokeDir "$($s.Name).log"
        $env:OPENSSL_CONF = if ($s.ContainsKey('Conf')) { $s.Conf } else { $null }
        $smokeArgs = @($OutDir, $s.Scenario, '--time', "$($s.Time)") + $s.Extra
        & (Join-Path $smokeDir 'smoke.exe') @smokeArgs 1> $ear 2> $log
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAIL $($s.Name): smoke exited with $LASTEXITCODE (see $log)" -ForegroundColor Red
            $failed += $s.Name
            continue
        }
        $check = if ($s.ContainsKey('Check')) { $s.Check } else { $s.Name }
        & python (Join-Path $SelftestDir 'check_ear.py') $check $ear
        if ($LASTEXITCODE -ne 0) { $failed += $s.Name }
    }
} finally {
    $env:PATH = $savedPath
    $env:OPENSSL_CONF = $savedConf
}
if ($failed.Count -gt 0) { throw "self-test scenarios failed: $($failed -join ', ')" }
Get-Content (Join-Path $smokeDir 'host-openssl.log') -ErrorAction SilentlyContinue | Select-String 'host OpenSSL'

# --- build info + manifest ---------------------------------------------------------------------
# README.md is shared; the Linux manifest.json lists it, so with the Linux library present it is kept as it is.
if (-not $linuxBundled) {
    Copy-Item (Join-Path $ScriptDir 'README.md') (Join-Path $OutDir 'README.md') -Force
}
Copy-Item (Join-Path $ScriptDir 'BUILD-WINDOWS.md') (Join-Path $WinOut 'BUILD-WINDOWS.md') -Force

Write-Step 'Write win-x64\build-info.json and win-x64\manifest.json'
$installed = Join-Path $WorkDir "vcpkg_installed\$Triplet"
function Get-Define([string] $Path, [string] $Pattern) {
    if (-not (Test-Path $Path)) { return $null }
    $match = Select-String -Path $Path -Pattern $Pattern | Select-Object -First 1
    if ($match) { return $match.Matches[0].Groups[1].Value } else { return $null }
}
$vcpkgManifest = Get-Content -Raw (Join-Path $WindowsDir 'vcpkg.json') | ConvertFrom-Json
$buildInfo = [ordered]@{
    dll                 = 'nvat.dll'
    import_library      = 'nvat.lib'
    pdb                 = 'nvat.pdb'
    crt                 = 'dynamic (/MD): MSVCP140, VCRUNTIME140, VCRUNTIME140_1 and the Universal CRT'
    visual_studio       = "$($vs.DisplayName) $($vs.Version)"
    msvc                = $env:VCToolsVersion
    windows_sdk         = $env:WindowsSDKVersion.TrimEnd('\')
    cmake               = ((cmake --version) | Select-Object -First 1)
    rust                = (rustc --version)
    cmake_build_type    = 'Release (/O2, /Z7; /DEBUG /OPT:REF /OPT:ICF)'
    hardening           = '/guard:cf /Qspectre (compile), /guard:cf /CETCOMPAT (link); dependencies: /guard:cf /Qspectre (vcpkg triplet)'
    vcpkg_baseline      = $vcpkgManifest.'builtin-baseline'
    vcpkg_triplet       = $Triplet
    static_dependencies = [ordered]@{
        openssl = Get-Define "$installed\include\openssl\opensslv.h" 'OPENSSL_VERSION_STR\s+"([^"]+)"'
        curl    = Get-Define "$installed\include\curl\curlver.h" 'LIBCURL_VERSION\s+"([^"]+)"'
        libxml2 = Get-Define "$installed\include\libxml2\libxml\xmlversion.h" 'LIBXML_DOTTED_VERSION\s+"([^"]+)"'
        xmlsec  = Get-Define "$installed\include\xmlsec\version.h" 'XMLSEC_VERSION\s+"([^"]+)"'
        zlib    = Get-Define "$installed\include\zlib.h" 'ZLIB_VERSION\s+"([^"]+)"'
    }
    size_bytes          = (Get-Item (Join-Path $LibOut 'nvat.dll')).Length
}
$buildInfo | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8NoBOM (Join-Path $WinOut 'build-info.json')

$nvatVersion = ((Select-String -Path $header -Pattern 'NVAT_VERSION_STRING\s+"([^"]+)"').Matches[0].Groups[1].Value)
$files = @(Get-Item $header) + @(Get-ChildItem $LibOut, $WinOut -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' }) | Sort-Object FullName
$entries = foreach ($file in $files) {
    [ordered]@{
        path   = $file.FullName.Substring($OutDir.Length + 1).Replace('\', '/')
        size   = $file.Length
        sha256 = (Get-FileHash -Algorithm SHA256 $file.FullName).Hash.ToLowerInvariant()
    }
}
$manifest = [ordered]@{
    name            = 'nvat-maa-bundle (win-x64)'
    nvat_version    = $nvatVersion
    nvat_git_commit = $NvatCommit
    nvat_git_branch = $NvatBranch
    nvat_git_dirty  = $NvatDirty
    build_date_utc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    platform        = 'win-x64 (MSVC, dynamic CRT)'
    header_sha256   = Get-NormalizedSha256 $header
    build           = $buildInfo
    files           = @($entries)
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8NoBOM (Join-Path $WinOut 'manifest.json')

Write-Host ''
Write-Host "Windows bundle ready: $LibOut ($(@($entries).Count) files, NVAT $NvatCommit)" -ForegroundColor Green
