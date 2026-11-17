# Proposal: Windows (MSVC) support for `nv-attestation-sdk-cpp`

> **For:** the maintainers of NVIDIA's attestation-sdk.
>
> **Status:** draft for discussion; not yet submitted upstream. The changes are on the `gkostal/attestation-sdk` fork,
> branch `dev/gkostal/maa-nvat-implementation-sonnet-5-5`, commit `6f93974` ("Build libnvat for Windows (nvat.dll) with
> MSVC and vcpkg"). That commit builds on upstream release 2026.10.02 (`11b2bfe`) plus the fork's separate
> offline-collateral work (section 7, item 1).
>
> **Build instructions:** [BUILD-WINDOWS.md](./BUILD-WINDOWS.md).

This document explains how `libnvat` was ported to Windows, why each change was made the way it was, how the port was
validated, and what we would still do before opening pull requests.

## Summary

- **What it adds.** `libnvat` builds with MSVC as **`nvat.dll`** (or a static library). It uses the existing
  `CMakeLists.txt` and sources and has the same features as on Linux. The one exception is GPU and switch evidence
  collection, which stays Linux-only.
- **Size.** 25 files in `nv-attestation-sdk-cpp`, with no change to verification logic:
  - 14 library files, +546/−175. Of that, +156/−143 is the mechanical `NVAT_API` annotation of `nvat.h.in`, and about 70
    lines are in `src/`.
  - 11 test files, +374/−60.
- **On Linux,** existing builds behave as before, with one exception: the OpenSSL-configuration hardening
  (section 3.9). As written it is on by default in upstream's default Linux build, so we propose it as its own PR. The
  other changes compile to the same code on Linux, or make the unit tests more robust when run in parallel (section 4).
- **Validation.** On Windows the full unit suite gives the same results as on Linux. The DLL exports exactly the C ABI
  and imports only system and C runtime DLLs. A real consumer, Microsoft Azure Attestation, runs it end to end
  (section 5).

## 1. Motivation

Microsoft Azure Attestation (MAA) is prototyping verification of NVIDIA GPU evidence with NVAT: CMW collections, CoRIM
reference values and EAR results. MAA's verification process runs on Linux hosts in some deployments and on Windows
hosts in others. A verifier available on only one of them would split the service. We would rather use NVIDIA's own
verifier on both than reimplement NVIDIA's appraisal logic.

We want the Windows build **upstream** rather than in a fork, so that NVIDIA's fixes and new device support reach
Windows consumers in the same release as Linux ones. Verification does not need a GPU, so other Windows relying parties
and tools could use the same library.

## 2. Scope

| In scope | Not in scope (yet) |
|---|---|
| `libnvat` as a DLL and as a static library, MSVC, x64 | Evidence collection on Windows: NVML, NSCQ and corelib are `dlopen`ed (section 3.5) |
| All verification features: local CoRIM verifier, OCSP and certificate-chain checks, EAR/EAT, the NRAS client, Rego policies (regorus) | `nv-attestation-cli` and the Rust SDK on Windows |
| The complete unit-test suite on Windows | Packaging: installer, CPack generator, vcpkg port |
| | Windows CI (proposed in section 6) |

## 3. Design decisions

Each subsection gives the decision, the reason, and the alternatives that were considered.

### 3.1 One CMake build

MSVC support is added to the existing `CMakeLists.txt` in `if(MSVC)` / `if(WIN32)` blocks. There is no separate Visual
Studio solution or second build system. The port was built with the Ninja generator; section 7 lists the configurations
that were not tried.

*Why:* a second build system would drift. Keeping one CMake build means every source, option and dependency change
reaches Windows automatically.

### 3.2 Third-party libraries from a package manager (vcpkg)

On Windows, OpenSSL, curl, libxml2, xmlsec and zlib come through `find_package`. `USE_SYSTEM_DEPS` now defaults to `ON`
on Windows, and configuring with it `OFF` stops with a clear error. The port pins versions with a vcpkg manifest
(`vcpkg.json` with a `builtin-baseline`) and a triplet that builds the libraries **statically against the dynamic CRT**
(`/MD`). vcpkg names the xmlsec targets `unofficial::xmlsec::*`, so the port maps them to the `xmlsec::xmlsec` and
`xmlsec::xmlsec-openssl` targets the rest of the CMake already uses. It also defines the same no-op `*_external` targets
as the existing system-dependencies branch.

*Why:*

- The source builds that `USE_SYSTEM_DEPS=OFF` performs are autotools and Make based. OpenSSL's Windows build needs Perl,
  NASM and nmake; curl, libxml2 and xmlsec use autotools. None of that exists in an MSVC environment. On Windows,
  libraries normally come from a package manager.
- vcpkg ships with Visual Studio and is installed on GitHub's Windows runners. Through its CMake toolchain file, the
  existing `find_package` path works almost unchanged.
- A manifest plus a baseline pins versions as reproducibly as the hash-pinned tarballs do on Linux.
- Static libraries with the dynamic CRT make `nvat.dll` self-contained. There is no `libcrypto-3-x64.dll` to deploy, and
  nothing a host could resolve to its *own*, different OpenSSL DLL. The goal is the same as Linux's static linking with
  hidden symbols: NVAT's dependencies stay private. `/MD` is the CRT most host processes use.

*Alternatives:*

- Extending the source builds to Windows (Perl/NASM/nmake for OpenSSL, CMake builds of the others) would be a large,
  separate build path.
- Conan would work just as well. We chose vcpkg because Visual Studio already ships it.

### 3.3 Exporting the C ABI with an `NVAT_API` macro

`nvat.h.in` defines `NVAT_API` and puts it on every function:

| Case | `NVAT_API` |
|---|---|
| Windows, while building the DLL (`NVAT_EXPORTS`, set through the target's `DEFINE_SYMBOL`) | `__declspec(dllexport)` |
| Windows, consumers | `__declspec(dllimport)` |
| GCC / Clang | `__attribute__((visibility("default")))` |
| Static library and its consumers (`NVAT_STATIC`, a `PUBLIC` definition of the static `nvat` target) | nothing |

*Why:*

- MSVC exports nothing from a DLL unless told to, so every public function must be marked somehow.
- Putting the macro in `nvat.h` itself keeps a single public header: what is installed today, and what consumers and
  bindgen already parse.
- On GCC and Clang the attribute changes nothing for today's default-visibility builds. It also lets the library be built
  with `-fvisibility=hidden`, so that only the C ABI is exported.
- It documents the API surface at each declaration.

*Alternatives:*

- **A `.def` file:** a second list of about 125 names to keep in sync with the header, and it does nothing for GCC/Clang.
- **`CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS`:** exports every C++ internal of `nvat`: thousands of decorated names, an unstable
  ABI, and the opposite of what `nvat.h` promises.
- **CMake's `generate_export_header`:** adds a second generated header that every consumer must find.

### 3.4 A small platform header, not a portability layer

`include/nv_attestation/platform.h` (new) holds the few POSIX facilities the library uses:

- `timegm_utc` and `gmtime_utc`;
- `S_ISDIR`;
- the `dlopen` family (section 3.5).

On Linux, `timegm_utc` and `gmtime_utc` simply call `timegm` and `gmtime_r`, so Linux behavior is identical.

*Why not the CRT's `_mkgmtime` and `gmtime_s`?* They reject dates after 3000-12-31. NVIDIA's device-identity
certificates expire at **9999-12-31T23:59:59Z** (RFC 5280's "no well-defined expiration" value). With the CRT functions,
every chain's expiration computation fails.

The Windows implementation uses Howard Hinnant's public-domain `days_from_civil` and `civil_from_days` algorithms: exact
proleptic Gregorian arithmetic for any year. It was validated against Python's `datetime`, including the 9999-12-31
expiration dates.

Unlike POSIX `timegm`, `timegm_utc` does not normalize the `struct tm` in place. No caller relies on that.

### 3.5 Evidence collection: runtime stubs rather than `#ifdef`s

NVML, NSCQ and corelib are already loaded at runtime with `dlopen`. On Windows, `platform.h` provides `dlopen`/`dlsym`
stubs that always fail, so the collectors report that they are unavailable. The only source changes are that the three
collector files no longer include `<dlfcn.h>` themselves; they get it through `utils.h`.

*Why:* the port can stay verifier-only without touching the collector sources. A real Windows collector (for example
`LoadLibraryW` for NVML, which ships with the Windows driver) can come later; see section 7.

### 3.6 zcbor under MSVC

zcbor and its generated decoders hit three MSVC limitations. All three are worked around **without modifying the fetched
zcbor sources or the committed generated decoders**.

1. **`strnlen`.** zcbor declares its own `strnlen()` and defines it as a weak symbol, for C libraries that lack one.
   MSVC's CRT declares a `dllimport` `strnlen`, which conflicts, and MSVC has no weak symbols. The new
   `include/zcbor_msvc_compat.h` includes `<string.h>` first, then renames zcbor's copy to `zcbor_strnlen`. It is
   force-included (`/FI`, the counterpart of the `-include` the build already uses for `zcbor_logger.h`) into
   `zcbor_lib`, `nvat` and the tests, because NVAT's internal headers include zcbor's.
2. **Variable-length arrays.** The generated decoders write `const size_t num_flags = N; bool flags[num_flags];`. In C,
   a `const` variable is not a constant expression, so this is a VLA, and MSVC does not support VLAs. At configure time,
   CMake writes copies of the generated sources to `<build>/generated-msvc/`, with `num_flags` as an `enum` constant.
   Configuration fails if the pattern is still present. The committed `generated/` files are untouched, and
   `REGENERATE_ZCBOR` is rejected with MSVC.
3. **GCC attributes** (`__weak__`, `used`) in zcbor's C sources are defined away for C compilation on MSVC.

*Alternatives:*

- A `PATCH_COMMAND` against the pinned zcbor commit would be a patch to maintain.
- Compiling the decoders as C++ would compile them as a different language from every other platform.

The proper fix belongs in zcbor itself; see section 7.

### 3.7 Compiler flags and warnings

| Flags | Why |
|---|---|
| `/W4` with `/wd4100 4101 4189 4505` (unused), `4244 4267 4245` (integer conversions), `4456–4459` (shadowing), `4127` (constant conditions), `4201` (nameless struct/union) | The counterpart of `-Wall -Wextra -Wpedantic` with what the GCC/Clang build also leaves off: `-Wno-unused*`, no `-Wconversion`, no `-Wshadow`. The nameless structs are in zcbor's generated types. The result is a warning-free build log, as `CONTRIBUTING.md` asks. The conversion warnings need an audit; see section 7. |
| `/utf-8` | The sources are UTF-8; without it MSVC reads them in the system code page. |
| `/bigobj` | Some translation units exceed MSVC's default limit on sections per object file. |
| `/permissive-`, `/Zc:__cplusplus` | Standard conformance. Without `/Zc:__cplusplus`, MSVC reports `199711L` for every standard, which misleads code that tests `__cplusplus`. |
| `WIN32_LEAN_AND_MEAN`, `NOMINMAX`, `NOGDI` | Keep `<windows.h>`'s `min`/`max` macros and `wingdi.h`'s `ERROR` macro from colliding with names in NVAT and its dependencies. |
| `_CRT_SECURE_NO_WARNINGS`, `_CRT_NONSTDC_NO_WARNINGS` | Silence MSVC's deprecation of standard and POSIX names (`getenv`, `strncpy`, ...) instead of rewriting portable code. |
| `/guard:cf`, `/Qspectre`; `/CETCOMPAT` when linking | Control Flow Guard, Spectre mitigations and CET shadow-stack compatibility, the hardening expected of Windows binaries that handle security decisions. The dependencies are compiled the same way (vcpkg triplet). |
| Policy `CMP0092` | Stops CMake from adding its default `/W3`, which would otherwise conflict with `/W4` (warning D9025). |
| `-Wno-c++17-extensions` on jwt-cpp only for non-MSVC compilers | MSVC does not know the flag. |
| `gtest_force_shared_crt` | googletest otherwise uses the static CRT on MSVC, which does not link with `/MD` code. It has no effect elsewhere. |

### 3.8 Windows runtime behavior

- **`readFileIntoString` opens files in binary mode.** The SDK reads evidence and reference-manifest (RIM) files with
  it, and the tests read their fixtures with it. On Windows, text mode translates CRLF and stops at a `0x1A` byte, so the
  bytes read could differ from the file, and signed content would no longer verify. `std::ios::binary` is a no-op on
  POSIX.
- **The default console logger writes through `std::cerr` on Windows** (spdlog `ostream_sink_mt`). spdlog's Windows
  console sinks keep the console handle they found when they were created and write to it directly. That bypasses any
  later redirection of `stderr` in the process, such as googletest's `CaptureStderr`, which several tests use. The cost
  is that console output is not colored on Windows. Linux is unchanged.
- **libcurl trusts the Windows certificate store when no CA file or path is given** (`CURLSSLOPT_NATIVE_CA`, libcurl ≥
  7.71). libcurl built with OpenSSL has no default CA bundle on Windows, so without this every HTTPS request (NRAS, the
  RIM service, OCSP) fails certificate verification. A caller's explicit `tls_ca_cert` or `tls_ca_path` still wins, and
  nothing else in `nv_http.cpp` sets `CURLOPT_SSL_OPTIONS`. We kept OpenSSL (rather than Schannel) as curl's TLS backend
  so that TLS behaves the same on both platforms.

### 3.9 The private OpenSSL does not load an OpenSSL configuration (`NVAT_OPENSSL_NO_CONFIG`)

There is a new option, `NVAT_OPENSSL_NO_CONFIG`. With it on, `nvat_sdk_init` first calls
`OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG)`, before curl and xmlsec initialize OpenSSL. OpenSSL runs its
configuration step only once, so their later initialization cannot load a configuration either.

The option defaults to `ON` when OpenSSL is private to libnvat: on Windows, and when it is built from source
(`USE_SYSTEM_DEPS=OFF`). It defaults to `OFF` with a system OpenSSL on Linux, so that build keeps following the system
crypto policy.

*Why:* a statically linked, private OpenSSL has no business reading:

- `OPENSSL_CONF`, which belongs to the host's own OpenSSL. A host's FIPS-only configuration, for example, breaks NVAT's
  OpenSSL, which has no FIPS provider; the self-test reproduces exactly this.
- its compiled-in `OPENSSLDIR`, which is the build machine's install prefix. On Windows that can be a directory an
  unprivileged user is able to create: the issue behind CVE-2019-1552.

This changes the default behavior of upstream's default Linux build, so we propose it as a separate PR (section 6). See
section 7, item 3.

### 3.10 CMake package export only for shared builds

`install(EXPORT nvatTargets ...)` now runs only when `BUILD_SHARED_LIBS` is on. A static `nvat` cannot be exported as a
CMake package: its private link dependencies become part of its interface, and the in-tree `own-jwt-cpp` target is in no
export set. The Windows unit-test build, which is static, needs this. Shared builds, the default and what the packages
ship, are unchanged.

### 3.11 Unit tests on Windows

- **Static build.** The tests call internal C++ functions, but `nvat.dll` exports only the C ABI, so on Windows they are
  built against a static `nvat` (`-DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=ON`).
- **POSIX shims.** `unit-tests/include/test_platform.h` is force-included on MSVC. It provides `realpath`, `setenv`,
  `unsetenv`, `mkstemp`, `mkdtemp`, `popen`, `F_OK`, a `strptime` covering the numeric formats the tests parse, and a
  temporary directory.
- **Fixtures.** `scripts/prepare-test-data.ps1` is the counterpart of `prepare-test-data.sh`. It uses `cbor-diag`, a
  Python virtual environment in the build tree, and Git for Windows' `bash` and `openssl` for the certificate scripts.
- **Test HTTPS server.** `LocalHttpsTestServer` has a `CreateProcess` implementation on Windows.

Changes that also help on Linux:

- **No port race.** The test HTTPS server now binds port 0 itself and reports the actual port (`READY <port>`), which
  the C++ side parses. Previously `find_free_port()` picked a port that another test could take before the server bound
  it. `find_free_port()` is removed.
- **`SO_REUSEADDR` off on Windows.** In `https_server.py`, `allow_reuse_address` is false on Windows. There,
  `SO_REUSEADDR` lets a second socket bind a port that is in use, so parallel tests could end up sharing one server.
- **Per-process files.** JWKS files and temporary files are named per process, so parallel `ctest` runs no longer
  collide.
- **No `git` per test.** `get_git_repo_root()` returns `NVAT_REPOSITORY_ROOT`, a definition the test CMake already
  provides, instead of running `git rev-parse` in each of the ~1,000 test processes. That was slow, especially with
  real-time antivirus scanning, and failed for build trees outside a git checkout.
- **OpenSSL 3.4+.** `generate_test_certs.sh` falls back to `-not_before`/`-not_after` when `openssl x509` rejects
  `-days -1` (OpenSSL 3.4 and later).

## 4. Effect on Linux and other existing builds

| Change | Effect on Linux |
|---|---|
| `NVAT_API` on every declaration | `visibility("default")`, which is already the default: the exported symbols do not change. Static builds: empty. |
| `timegm_utc`, `gmtime_utc` | They call `timegm` and `gmtime_r`: identical. |
| `<dlfcn.h>` included from `platform.h` | The same header reaches the same sources. |
| `readFileIntoString` in binary mode | No-op on POSIX. |
| Logger, curl CA store, MSVC flags, zcbor workarounds, `CMP0092`, `gtest_force_shared_crt` | Windows/MSVC only. |
| `USE_SYSTEM_DEPS` default | Unchanged outside Windows. |
| `install(EXPORT)` only for shared builds | Shared builds unchanged; static builds no longer attempt an export that cannot work. |
| **`NVAT_OPENSSL_NO_CONFIG`** | **Behavior change** for builds with `USE_SYSTEM_DEPS=OFF` (upstream's default): the bundled OpenSSL no longer reads `OPENSSL_CONF` or its `OPENSSLDIR`. Unchanged with `USE_SYSTEM_DEPS=ON`. Proposed as a separate PR. |
| Unit tests | Same results, and more robust in parallel runs (section 3.11). |

## 5. Validation

Toolchain:

- Visual Studio 2026 18.11 (MSVC 14.51), Windows SDK 10.0.26100.0, CMake 4.3.1, Ninja 1.13, Rust 1.99.1;
- vcpkg baseline `4df3365f`, which supplied OpenSSL 3.6.5, curl 8.23.0, libxml2 2.15.4, xmlsec 1.3.13 and zlib 1.4.

The Linux results come from NVAT's Ubuntu 22.04 container build (clang 14) of the same library sources.

| Check | Result |
|---|---|
| Unit suite, Windows (static build, `ctest -j4`) | 968 passed, 1 skipped, 37 failed. The 37 need live NVIDIA services or a real service key and fail the same way on Linux. They are listed in `container/live-service-tests.txt`. |
| Unit suite, Linux, same library sources | 968 passed; the same 37. |
| Exports | `nvat.dll` exports exactly the functions declared in `nvat.h` (135 on the fork: upstream's 125 plus 10 from the fork's offline-collateral API); `libnvat.so.2` exports the same 135. Checked by `windows/check_dll.py` and `container/check_symbols.py`. |
| Imports | Only Windows system DLLs, the Universal CRT and the Visual C++ runtime. OpenSSL, curl, libxml2, xmlsec and zlib are static and private. |
| Hardening | High-entropy ASLR, NX, Control Flow Guard and CET compatibility; PDB generated. |
| Offline self-test (`selftest/smoke.c`, a C program linked against `nvat.dll`) | Every verdict scenario as on Linux: affirming; OCSP missing; OCSP revoked; OCSP past `nextUpdate`, with and without enforcement; CoRIM missing. |
| Two OpenSSLs in one process | Another OpenSSL (1.1.1) loaded before `nvat_sdk_init` still works after a verification. |
| OpenSSL configuration (section 3.9) | With a hostile `OPENSSL_CONF` (FIPS-only properties) the verdict is still `affirming`. A build with `NVAT_OPENSSL_NO_CONFIG=OFF` fails `nvat_sdk_init` under the same configuration, so the option is what makes the difference. |
| A real consumer | Microsoft Azure Attestation's Windows host links `nvat.lib` and passes its 10 GPU-attestation end-to-end tests. The same tests pass against the Linux build. A Debug consumer works with the Release `nvat.dll`, since only the C ABI crosses. |

## 6. Proposed upstream pull requests

Following `CONTRIBUTING.md` (an approved issue first, then one concern per PR):

| # | PR | Contents | Depends on |
|---|---|---|---|
| 1 | Mark the public C ABI with `NVAT_API` | `nvat.h.in`, `DEFINE_SYMBOL`, `NVAT_STATIC`. Linux-neutral. | — |
| 2 | Make the unit tests robust in parallel runs | Test HTTPS server on port 0 with `READY <port>`, per-process files, repository root without `git`, OpenSSL 3.4 fallback in `generate_test_certs.sh`. Linux benefits on its own. | — |
| 3 | Portable time and file helpers | `platform.h`, `timegm_utc` and `gmtime_utc` callers, binary `readFileIntoString`. Linux-neutral. | — |
| 4 | Build with MSVC | The CMake MSVC blocks, zcbor compatibility, vcpkg dependencies with a generic `vcpkg.json`, logger, curl CA store, the Windows test support (`test_platform.h`, `prepare-test-data.ps1`, the Windows `LocalHttpsTestServer`), documentation. | 1, 3 |
| 5 | Do not load an OpenSSL configuration into a private OpenSSL | `NVAT_OPENSSL_NO_CONFIG` (section 3.9). | — |
| 6 | Windows CI | A GitHub Actions job that builds shared, and static with the tests, and runs `ctest` without the live-service tests. | 4 |

## 7. Outstanding issues before submitting upstream

### Must address before opening the PRs

1. **Separate the port from the fork's other work.** The branch also carries a separate proposal, MAA's offline-collateral
   C ABI (`nvat_local_corim_verifier_verify_cmw_ex`, the collateral callback, 10 new functions), and the
   `dev/maa-prototype/` tooling. Neither belongs in these PRs.
   - A trial cherry-pick of `6f93974` onto `11b2bfe` applied every library and test file except two small conflicts.
     One is in `nvat.h.in`: the fork's `#pragma GCC visibility` block and the 10 fork-only declarations. The other is in
     `unit-tests/CMakeLists.txt`: an adjacent fork change to the fixture step.
   - After rebasing, rebuild and retest on both platforms; the export check should then expect 125 functions.
2. **Remove the MAA-specific references.**
   - A CMake comment and the `USE_SYSTEM_DEPS=OFF` error message point to `dev/maa-prototype/BUILD-WINDOWS.md`.
   - The vcpkg manifest and triplet live in `dev/maa-prototype/windows/`, and the manifest is named `nvat-maa-windows`.
   - Move a generic `vcpkg.json` next to the SDK (for example `nv-attestation-sdk-cpp/vcpkg.json`), and write a Windows
     section in the SDK's build documentation. `CONTRIBUTING.md` requires documentation for new components.
3. **Decide the default of `NVAT_OPENSSL_NO_CONFIG` on Linux.** `CONTRIBUTING.md` asks that new options default to
   existing behavior, and as written the option changes upstream's default Linux build (`USE_SYSTEM_DEPS=OFF`). Either:
   - (a) default it to `ON` on Windows only and leave Linux opt-in; or
   - (b) argue for `ON` wherever OpenSSL is private, as a security fix: the baked-in `OPENSSLDIR` is a build-machine
     path.

   We recommend (b), in its own PR; if the maintainers prefer to keep the default unchanged, (a).
4. **Build with Visual Studio 2022 (MSVC 14.4x)**, which GitHub's Windows runners and most developers have; only Visual
   Studio 2026 (MSVC 14.51) and CMake 4.3 were used. `cmake_minimum_required` stays at 3.11, and `CMP0092` is set only
   where the policy exists.
5. **Windows CI.** Today the repository's only workflow is `stale.yaml`. Without a Windows job the port will regress
   silently.
6. **Contribution formalities.**
   - Open the issue first.
   - Every commit needs a DCO `Signed-off-by`. None of the fork's commits have one, so the contributor must recreate
     them with `git commit -s`.
   - Use the `#<Issue> - <Title>` commit format.
   - Run `clang-format`. `CONTRIBUTING.md` refers to a `.clang-format` that the repository does not contain, so ask
     which style applies.
   - The new files carry NVIDIA's SPDX copyright header; confirm the header maintainers want on contributed files.
7. **Audit the suppressed conversion warnings.** `/wd4244 /wd4267 /wd4245` keep the log clean, but Windows is LLP64:
   `long` is 32 bits while `size_t` is 64. A conversion that is harmless on Linux (LP64) can truncate on Windows. Build
   once with these warnings enabled and fix or justify each.

### Should address, in the PRs or as agreed follow-ups

8. **Fix zcbor upstream.** zcbor could guard its `strnlen` for MSVC, and its generator could emit constant-expression
   array sizes. NVAT could then drop the force-included compatibility header and the configure-time rewrite, and allow
   `REGENERATE_ZCBOR` with MSVC.
9. **Label the live-service tests** (for example a `network` `ctest` label), so offline runs and CI on both platforms
   can exclude them without a hand-kept list.
10. **Run the tests from a shared-library configuration.** Today the Windows tests need a separate static build,
    because the DLL exports only the C ABI; a Linux build with hidden visibility has the same limitation. An internal
    static or `OBJECT` library, linked by both the DLL and the tests, would remove the second build.
11. **Configurations not yet built:**
    - Debug and RelWithDebInfo builds of NVAT itself with MSVC (including the `ZCBOR_VERBOSE` path).
    - The multi-config Visual Studio generator. The `CMakeLists.txt` tests `CMAKE_BUILD_TYPE`, which is empty with
      multi-config generators.
    - clang-cl and ARM64.
    - The static CRT (`/MT`). regorus's Rust static library uses the dynamic CRT by default and would need
      `+crt-static`.
12. **Evidence collection on Windows.** Either implement loading NVML with `LoadLibraryW`, or add a CMake option that
    compiles the collectors out. In both cases, check that the error an API caller gets on Windows is clear.
13. **Packaging and versioning.**
    - The CPack configuration covers DEB and archives.
    - The install tree has not been tested on Windows: DLL in `bin`, import library, PDB, `nvatTargets`.
    - `nvat.dll` has no version resource (`VERSIONINFO`).
    - The DLL name carries no major version, unlike `libnvat.so.2`. Decide on naming, and consider a vcpkg port.
14. **Align dependency versions.**
    - Windows uses xmlsec 1.3.13 and Linux the source-built 1.2.39. NVAT's xmlsec calls are unchanged, but the two
      platforms test different xmlsec generations.
    - OpenSSL (3.6.5 vs 3.6.4), curl (8.23.0 vs 8.22.0) and zlib (1.4 vs 1.3.1) also differ.
    - Pin them with vcpkg `overrides`, or move Linux forward.
    - The `unofficial-xmlsec` target names are vcpkg's; another package manager would need its own mapping.
15. **Make the hardening flags an option.** `/guard:cf /Qspectre /CETCOMPAT` are unconditional with MSVC, and the custom
    triplet applies them to the dependencies. Maintainers may prefer an `NVAT_MSVC_HARDENING` option (default `ON`) and
    vcpkg's stock `x64-windows-static-md` triplet.
16. **Colored logging on Windows.** Use spdlog's Windows color sink when `stderr` is a console, and the `std::cerr` sink
    otherwise.
17. **Replace the test shims with portable helpers.** `test_platform.h` reimplements a few POSIX functions; its
    `strptime` covers only the formats the tests use. The project's C++14 default rules out `std::filesystem`, so this
    means portable test helpers instead.
18. **`nv-attestation-cli` and the Rust SDK on Windows.** Neither has been built. `nv-attestation-sdk-sys/build.rs`
    hard-codes `/usr/include/nvat.h`. bindgen should be unaffected by `NVAT_API`, an attribute macro it does not emit, but
    that has not been tested.

### Open questions for the maintainers

- Should Windows be a supported platform (CI and released binaries), or a community-maintained build?
- Is vcpkg acceptable as the Windows source of dependencies, and where should the manifest live?
- Should `NVAT_OPENSSL_NO_CONFIG` default to `ON` on Linux too (item 3)?
- What should the DLL be called and how should it be versioned (item 13)?
- Should Linux move to xmlsec 1.3, so both platforms test the same xmlsec (item 14)?
