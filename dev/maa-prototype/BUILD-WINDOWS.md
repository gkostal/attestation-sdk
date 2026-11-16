# Building `nvat.dll` (NVAT for MAA on Windows)

The Windows counterpart of the Linux `libnvat.so.2` bundle described in [README.md](./README.md). MAA's Windows
EnclaveHost loads `AttestationEnclave.dll` in-process, and with the bundle staged that DLL imports `nvat.dll`. The
Windows library goes into the same bundle directory as the Linux one, under `lib\win-x64\` and `win-x64\`.

```powershell
.\dev\maa-prototype\build-bundle-windows.ps1 -OutDir C:\src\nvat-bundle            # tests, nvat.dll, gates, self-test
.\dev\maa-prototype\build-bundle-windows.ps1 -OutDir C:\src\nvat-bundle -SkipTests # without the unit-test build and run
```

MAA then stages both platforms with `src\AttestationServices\Instance\NvidiaCmwQuoteProcessor\tools\Stage-NvatBundle.ps1`
(in the MAA repository).

## Required tools

Versions are the ones this was built and tested with.

| Tool | Notes |
| --- | --- |
| **Visual Studio 2026** (18.11) | Workload **Desktop development with C++** (MSVC v145 x64 tools, 14.51; Windows SDK), plus the components **C++ CMake tools for Windows** (CMake 4.3 and Ninja 1.13) and **vcpkg package manager**. The script finds Visual Studio with `vswhere` and imports its x64 environment itself: no developer prompt needed. |
| **Rust** (rustup, stable `x86_64-pc-windows-msvc`, 1.99.1) | Builds regorus, NVAT's Rego engine, through Corrosion. `winget install Rustlang.Rustup` |
| **Git for Windows** (2.56) | Source downloads; its `bash` and `openssl` run the unit-test certificate scripts. |
| **Python 3** (3.12) with `cryptography` | OCSP capture (`capture_ocsp.py`), EAR checks (`selftest\check_ear.py`), the DLL gate (`windows\check_dll.py`). `pip install cryptography`. The unit-test fixture generators get their own venv (`cbor2`, `cryptography`, pinned as in `requirements-dev.txt`). |
| **cbor-diag** (0.1.8) | CoRIM fixtures from CBOR diagnostic notation: `cargo install cbor-diag-cli --locked` |
| **PowerShell 7** | The build scripts need `pwsh`. |

Also needed:

- **Network access** for the first build: vcpkg downloads OpenSSL, curl, libxml2, xmlsec and zlib sources; CMake fetches
  Corrosion, regorus, jwt-cpp, nlohmann/json, zcbor, fmt, spdlog and googletest from GitHub; cargo fetches regorus's crates.
  The OCSP capture asks `ocsp.ndis.nvidia.com` (it falls back to earlier captures when offline).
- **Disk:** about 4.5 GB under the work directory (`C:\src\nvat-win`: vcpkg packages and the two build trees), plus
  vcpkg's download and binary caches under `%LOCALAPPDATA%\vcpkg`.
- **Memory:** a few NVAT sources (e.g. `coev.cpp`) need several GB of compiler heap each. Keep `-Jobs` at its default 4;
  more parallel compiles end in `C1060: compiler is out of heap space`.

Antivirus: each unit test runs in its own process (about 1,000 processes per run), and every compile reads thousands of
toolchain headers. On a machine with real-time scanning, keep the work directory, the bundle and the vcpkg and cargo caches
(`%LOCALAPPDATA%\vcpkg`, `%USERPROFILE%\.cargo`) where your antivirus policy allows them to be excluded, and keep the
parallelism low.

## What the script does

`build-bundle-windows.ps1` (helpers in `windows\common.ps1`):

1. Finds Visual Studio and imports its x64 environment, and uses Visual Studio's vcpkg (or `-VcpkgRoot` / `VCPKG_ROOT`).
2. Stages the shared fixtures: captures the live OCSP responses, converts the two Rubin CoRIMs from `.diag`, copies the
   golden CMW. If the bundle already has the Linux library, its fixtures are kept instead: the Linux `manifest.json` lists
   them, and a new OCSP capture would not match it.
3. Unless `-SkipTests`: builds NVAT as a **static** library with its unit tests (`<WorkDir>\test`) and runs them with
   `windows\run-unit-tests.ps1` (see below).
4. Builds **`nvat.dll`** (`<WorkDir>\bundle`): Release, `/MD`, a PDB, OpenSSL / curl / libxml2 / xmlsec / zlib from
   vcpkg linked statically (triplet `windows\triplets\x64-windows-static-md-nvat.cmake`, manifest `windows\vcpkg.json`
   pinned to a vcpkg baseline).
5. Gates it with `windows\check_dll.py`, which fails unless:
   - the exports are exactly the functions declared in `nvat.h`, all `nvat_*`;
   - the imports are only Windows system DLLs, the Universal CRT and the Visual C++ runtime;
   - it is x64 with ASLR (high entropy), NX, Control Flow Guard and CET shadow-stack compatibility;
   - it references its PDB.
6. Stages `include\nvat.h` (with LF line endings, so it is byte for byte the header the Linux build writes) and
   `lib\win-x64\{nvat.dll,nvat.lib,nvat.pdb}`.
7. Builds `selftest\smoke.c` against `nvat.lib` and runs it offline for every verdict scenario of the Linux self-test
   (`affirming`, `ocsp-missing`, `ocsp-revoked`, `corim-missing`, `ocsp-expired-enforced`, `ocsp-expired-not-enforced`;
   EARs checked by `selftest\check_ear.py`), plus:
   - `openssl-conf-ignored`: `OPENSSL_CONF` points at a configuration that NVAT's OpenSSL could not work with (FIPS-only
     algorithms); the appraisal must still be `affirming`, because NVAT never loads an OpenSSL configuration;
   - `host-openssl`: another OpenSSL (`-HostOpenSslDll`, by default MAA's OpenSSL 1.1.1 `libcrypto-1_1-x64.dll`) is
     loaded into the same process before NVAT initializes and must still work after the verification.
8. Writes `win-x64\build-info.json` (toolchain and dependency versions) and `win-x64\manifest.json` (sha256 of every
   Windows file, the NVAT commit, and the `nvat.h` hash that `Stage-NvatBundle.ps1` checks against the Linux library).

### Bundle layout (Windows part)

```
include\nvat.h                       shared with the Linux library (the same header)
lib\win-x64\nvat.dll                 exports exactly the nvat_* functions of nvat.h
lib\win-x64\nvat.lib                 import library
lib\win-x64\nvat.pdb
win-x64\symbols\{exports,dependents}.txt, headers.txt
win-x64\selftest\smoke.exe, smoke.c, check_ear.py, ear-<scenario>.json, <scenario>.log
win-x64\build-info.json, win-x64\manifest.json, win-x64\BUILD-WINDOWS.md
fixtures\...                         shared with the Linux bundle
```

## Unit tests on Windows

`nvat.dll` exports only the C ABI, while the unit tests also call internal C++ functions, so they are built against a static
NVAT (`-DBUILD_SHARED_LIBS=OFF`), as Linux uses a separate default-visibility build. The fixtures are prepared by
`nv-attestation-sdk-cpp\scripts\prepare-test-data.ps1` (the counterpart of `prepare-test-data.sh`).

```powershell
.\dev\maa-prototype\windows\run-unit-tests.ps1 -BuildDir C:\src\nvat-win\test                       # the whole suite
.\dev\maa-prototype\windows\run-unit-tests.ps1 -BuildDir C:\src\nvat-win\test -CTestArgs '-R','CApiCollateralCb'
```

The runner accepts failures only for the tests that need the live NVIDIA services and a real service key
(`container\live-service-tests.txt`, the same list as on Linux). Result: **968 passed, 1 skipped, 37 expected live-service
failures, 0 unexpected**, the same as the Linux container run.

## Building by hand

From a shell with the Visual Studio x64 environment (`vcvars64.bat`; it does not set `VCPKG_ROOT`):

```powershell
$vcpkg = "$env:VSINSTALLDIR\VC\vcpkg"
$win = 'C:\src\github\gkostal\attestation-sdk\dev\maa-prototype\windows'
cmake -S nv-attestation-sdk-cpp -B C:\src\nvat-win\bundle -G Ninja -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_TOOLCHAIN_FILE="$vcpkg\scripts\buildsystems\vcpkg.cmake" `
    -DVCPKG_MANIFEST_DIR="$win" -DVCPKG_OVERLAY_TRIPLETS="$win\triplets" `
    -DVCPKG_TARGET_TRIPLET=x64-windows-static-md-nvat -DVCPKG_INSTALLED_DIR=C:\src\nvat-win\vcpkg_installed `
    -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF
cmake --build C:\src\nvat-win\bundle --parallel 4
```

On Windows `USE_SYSTEM_DEPS` defaults to `ON` (the dependencies must come from a package manager) and
`NVAT_OPENSSL_NO_CONFIG` to `ON`.

## What the Windows port changed in NVAT

| Area | Change |
| --- | --- |
| Public header | `NVAT_API` on every function of `nvat.h`: `dllexport` while building the DLL (`NVAT_EXPORTS`), `dllimport` for consumers, default visibility on GCC/Clang (replacing the `#pragma GCC visibility` block), nothing for static builds (`NVAT_STATIC`). |
| POSIX calls | `include\nv_attestation\platform.h`: `timegm` / `gmtime_r` (proleptic Gregorian arithmetic on Windows; the CRT's functions stop at the year 3000 and the NVIDIA certificates expire at the end of 9999), `S_ISDIR`, and `dlopen` stubs (NVML, NSCQ and corelib evidence collection is Linux only). |
| zcbor | `include\zcbor_msvc_compat.h` (force-included): zcbor's own weak `strnlen` is renamed, GCC attributes dropped. The generated decoders size arrays with a `const size_t`, which MSVC's C does not accept as a constant; CMake compiles copies that use an enum constant. `REGENERATE_ZCBOR` is not supported with MSVC. |
| Build | MSVC flags (`/W4` with the warnings the GCC flags also leave off, `/utf-8`, `/bigobj`, `/permissive-`, `/guard:cf`, `/Qspectre`, `/CETCOMPAT`), `/FI` instead of `-include`; dependencies through `find_package` (vcpkg's `unofficial-xmlsec`); the CMake package export only for shared builds. |
| OpenSSL configuration | `NVAT_OPENSSL_NO_CONFIG` (default on when OpenSSL is private to libnvat, i.e. built from source or on Windows): `nvat_sdk_init` initializes OpenSSL with `OPENSSL_INIT_NO_LOAD_CONFIG`, so neither `OPENSSL_CONF` nor the compiled-in `OPENSSLDIR` (a build-machine path) is read. Applies to Linux too. |
| Runtime | The default console logger writes through the C runtime's `stderr` (spdlog's Windows console sink bypasses redirection); libcurl uses the Windows certificate store when no CA file is given (`CURLSSLOPT_NATIVE_CA`); `readFileIntoString` reads in binary mode. |
| Tests | `unit-tests\include\test_platform.h` (force-included on MSVC: `realpath`, `setenv`, `mkstemp`, `mkdtemp`, `strptime`, ...), a Windows `LocalHttpsTestServer` (`CreateProcess`); the test HTTPS server binds a free port itself and reports it; per-process JWKS files; the repository root comes from the build instead of `git`; `generate_test_certs.sh` works with OpenSSL 3.4+ (no negative `-days`). |

### Differences from the Linux library

| | Linux (`libnvat.so.2`) | Windows (`nvat.dll`) |
| --- | --- | --- |
| Compiler | clang 14 (Ubuntu 22.04 container) | MSVC 19.51 (Visual Studio 2026) |
| Dependencies | built from hash-pinned source tarballs by CMake | vcpkg at a pinned baseline |
| OpenSSL | 3.6.4 | 3.6.5 |
| curl | 8.22.0 | 8.23.0 |
| libxml2 | 2.15.4 | 2.15.4 |
| xmlsec | 1.2.39 | 1.3.13 (the only XML-signature APIs NVAT uses are unchanged in 1.3) |
| zlib | 1.3.1 | 1.4 |
| Hiding the dependencies | hidden visibility + `nvat.lds` | a DLL exports only what is marked `dllexport` |

## Troubleshooting

- `LNK1104: cannot open file ...exe` or `...dll`: usually an antivirus scan holding the new file; build again.
- `C1060: compiler is out of heap space`: lower `-Jobs`.
- `Could not find toolchain file "%VCPKG_ROOT%..."`: `vcvars64.bat` does not set `VCPKG_ROOT`; pass the path explicitly
  (the scripts do).
- Unit tests fail with `Failed to initialize SDK` or `The system cannot find the path specified`: run them from the test
  build tree's `unit-tests` directory, as `ctest` does (they use relative `testdata\` paths).
