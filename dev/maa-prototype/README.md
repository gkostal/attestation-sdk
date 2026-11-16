# NVAT for MAA: offline NVIDIA GPU (Rubin) appraisal through `libnvat`

This directory holds everything needed to build and verify the **prebuilt `libnvat` bundle** that MAA's
EnclaveHost links against: `libnvat.so.2` for the Linux EnclaveHost and `nvat.dll` for the Windows EnclaveHost
(see [BUILD-WINDOWS.md](./BUILD-WINDOWS.md)), plus the C ABI they rely on. MAA hands `libnvat` a CMW collection
(GPU evidence) and answers every collateral question - CoRIMs and OCSP responses - from its own store,
so native code never touches the network or the filesystem.

```
MAA EH native code                              libnvat.so.2 (statically linked OpenSSL, curl, ...)
 nvat_verify_call_options_set_collateral_callback ─┐
 nvat_local_corim_verifier_verify_cmw_ex(...)  ────┼─► appraise CMW ─► EAR JSON (ear_status per GPU)
        ▲                                          │
        └──── nvat_collateral_cb_t(kind, key) ◄────┘  CORIM <rimId>  |  OCSP_RESPONSE <issuerKeyHash>_<serial>
```

## C ABI additions (`nv-attestation-sdk-cpp/include/nvat.h.in`)

| Function / type | Purpose |
|---|---|
| `nvat_byte_buf_t`, `nvat_byte_buf_create`, `nvat_byte_buf_free` | libnvat-owned byte buffer to return binary collateral across the ABI. The callback allocates it with `nvat_byte_buf_create`; **libnvat frees it** after the callback returns. |
| `nvat_collateral_kind_t` | `NVAT_COLLATERAL_KIND_CORIM = 1`, `NVAT_COLLATERAL_KIND_OCSP_RESPONSE = 2` |
| `nvat_collateral_cb_t` | `nvat_rc_t cb(void* user_data, nvat_collateral_kind_t kind, const char* lookup_key, nvat_byte_buf_t* out)`. Return `NVAT_RC_OK` + buffer, or **`NVAT_RC_CACHE_OBJECT_NOT_FOUND`** (the existing code 14 - no new return code) when the caller's store does not have the item. Any other code (`NVAT_RC_BAD_ARGUMENT`, `NVAT_RC_INTERNAL_ERROR`, ...) is a failed lookup and is treated like "not found". |
| `nvat_verify_call_options_t` + `_create/_free` | Per-call options; read-only during a call (may be shared by concurrent calls). |
| `..._set_collateral_callback(options, cb, user_data)` | Installs the callback. With it, a verify call performs **no libcurl and no file I/O** - whatever the verifier's CoRIM store / OCSP client are configured with. |
| `..._set_require_ocsp_nonce(options, bool)` | default `true`. Cached OCSP responses cannot echo a nonce: callers using the callback set `false`. |
| `..._set_enforce_ocsp_next_update(options, bool)` | default `true`. |
| `..._set_verification_time(options, int64 epoch_seconds)` | default `0` = wall clock. Negative is rejected (`NVAT_RC_BAD_ARGUMENT`). |
| `nvat_local_corim_verifier_set_device_identity_roots(verifier, const char* const* pems, size_t n)` | *Replaces* the device-identity trust anchors (default: NVIDIA Device Identity CA). Needs `n >= 1` parseable PEM certificates, otherwise `NVAT_RC_BAD_ARGUMENT` and nothing changes. Configuration call - not concurrent with verification. |
| `nvat_local_corim_verifier_verify_cmw_ex(verifier, cmw, len, format, call_options, ear_signing_options, out_jwt, out_json)` | Like `nvat_local_corim_verifier_verify_cmw` (which is now `..._ex` with `call_options == NULL`: legacy behavior exactly). The shared verifier is never modified, so concurrent calls with different options / callbacks are safe. |

### Lookup keys passed to the callback

* **`NVAT_COLLATERAL_KIND_CORIM`** - the canonical RIM id: for the evidence's rim-locator
  `https://rim.attestation.nvidia.com/v1/rim/<id>` the key is `<id>`, e.g. `GR100_081D_9900230000`,
  `NV_GPU_DRIVER_GR100_620.54`. An empty id, or one containing `/`, `\`, `..`, `?`, `#` or a control
  character, is rejected (`BadArgument`, `fetched:false`) without asking the callback. A locator with any other
  allowlisted prefix is passed through as the raw URL. The CoRIM store's URL **allowlist still runs on the raw
  locator first**. Result bytes: raw CBOR/COSE CoRIM, or the RIM-service JSON envelope (first non-blank byte `{`).
* **`NVAT_COLLATERAL_KIND_OCSP_RESPONSE`** - `"<issuerKeyHash>_<serial>"`:
  * `issuerKeyHash` = SHA-256 of the issuer's public key (the `CertID.issuerKeyHash` of a **SHA-256 CertID**),
    64 **lower-case hex** digits;
  * `serial` = the certificate serial number as **lower-case hex with all leading zeros removed** (`0` for zero),
    e.g. serial `0x02C2F9F3…` → `2c2f9f3…`;
  * example: `65129acf8647f4285e8d07c09c5320949aacff2b8dd3917540b15d8833813f52_410a3021db2466fe7c`.
  * Asked only for chain certificates that have an AIA OCSP responder (the leaf and root of the Rubin chain have
    none: reported `ocsp_crl_status:"not_checked"`). The DER `OCSPResponse` is verified (responder signature and chain to the
    verifier's trust anchors via `OCSP_basic_verify`) and need not carry a nonce.

### Option semantics

* **`verification_time`** (epoch seconds, 0 = now) replaces "now" for (1) per-certificate `expired`, (2) the OCSP
  response's `ocsp_crl_response_expired` (`nextUpdate < time`), and (3) validating the OCSP responder's certificate chain
  (a per-call copy of the trust store with `X509_VERIFY_PARAM_set_time`; the shared state is never touched). Device-chain
  anchoring itself never checks validity periods (unchanged: expiry is *reported* per cert, via (1)). The EAR's own
  `iat/nbf/exp` always use the system clock. `thisUpdate` is not compared with the time; a response without
  `nextUpdate` counts as valid for one hour after `thisUpdate`.
* **`enforce_ocsp_next_update`** (call-options default `true`; legacy default is *not enforced*): an OCSP response past
  its `nextUpdate` (relative to `verification_time`) makes the chain untrusted → `signature_verified:false` →
  `ear_status:"contraindicated"`. With `false` the expiry is still reported (`ocsp_crl_response_expired:true`) but
  accepted.
* **`require_ocsp_nonce`** (call-options default `true`; legacy requires it): with `true`, every cached response is
  untrusted (`ocsp_nonce_matches:false`); set `false` for cached/pre-fetched responses.
* Callback installed ⇒ OCSP responses are requested whenever revocation checking is on
  (`nvat_local_corim_verifier_set_verify_revocation`, default on), **even if the verifier was created without an OCSP
  client**. With revocation off there are no OCSP lookups.

CMW `hints` records may be `application/json` or any RFC 6838 `application/*+json` type (MAA tunnels
`application/vnd.microsoft.maa.x-ms-runtime+json`); they survive parse/serialize untouched and the EAR input digest
is computed over the exact submitted bytes. The Blackwell FSP firmware-version hint is only read from plain
`application/json` hints.

### Symbol hygiene

`-DNVAT_HIDE_INTERNAL_SYMBOLS=ON` (Linux, off by default; incompatible with `BUILD_TESTING`, whose tests link internal
symbols) builds with hidden visibility and the linker version script `nv-attestation-sdk-cpp/nvat.lds`
(`global: nvat_*; local: *;`) plus `--exclude-libs,ALL`, so the statically linked OpenSSL 3.6.4, curl, libxml2, xmlsec,
spdlog, zcbor and regorus never interpose on the host's OpenSSL. `nvat.h` marks every public function `NVAT_API`:
default visibility on GCC/Clang, `dllexport` / `dllimport` on Windows (`NVAT_EXPORTS` while building the DLL), and
nothing for static builds (`NVAT_STATIC`). On Windows the DLL exports exactly those functions.

### OpenSSL configuration

`NVAT_OPENSSL_NO_CONFIG` (on by default when OpenSSL is private to libnvat: built from source, or on Windows) makes
`nvat_sdk_init` initialize OpenSSL with `OPENSSL_INIT_NO_LOAD_CONFIG`: libnvat's OpenSSL never reads `OPENSSL_CONF` (the
host's configuration for its own OpenSSL) or its compiled-in `OPENSSLDIR` (a build-machine path).

## Building the bundle

```powershell
.\dev\maa-prototype\build-bundle.ps1 -OutDir C:\src\nvat-bundle        # full: build, unit tests, bundle, self-test
.\dev\maa-prototype\build-bundle.ps1 -OutDir C:\src\nvat-bundle -SkipTests
```

Needs Docker (Linux engine), python with `cryptography`, git. Everything C++ builds in Ubuntu 22.04 containers
(`nvat-maa-build:22.04`, work volume `nvat-maa-work` caching sources + build trees, so re-runs are fast). If
`files.pythonhosted.org` is unreachable (e.g. behind a package-feed proxy) pass `-PipIndexUrl` (default: `$env:PIP_INDEX_URL`,
else the host's pip config). The script:

1. captures **live** OCSP responses (`capture_ocsp.py`; offline, earlier captures under `fixtures\ocsp` are reused);
2. builds libnvat (Release, shared, `USE_SYSTEM_DEPS=OFF`) with default visibility, runs the whole `ctest -L unit`
   suite (`container/run-unit-tests.sh`; the tests that need live NVIDIA services/service key and fail on the
   *unmodified* baseline too are listed in `container/live-service-tests.txt` - any other failure fails the build) and
   re-runs the collateral tests with `docker run --network none`;
3. builds libnvat again with hidden symbols and **fails unless** `nm -D --defined-only` lists only `nvat_*` symbols,
   exactly the functions declared in `nvat.h`, and `DT_NEEDED` is only libc/libm/libstdc++/libgcc_s (OpenSSL, curl, libxml2,
   zlib are static; zlib comes from a PIC build in the image);
4. runs the bundled C program `selftest/smoke` offline (`--network none`) in
   `mcr.microsoft.com/dotnet/runtime-deps:8.0-jammy-amd64` for each scenario below, checks the EARs
   (`selftest/check_ear.py`), and checks that a host-loaded `libcrypto.so.3` still wins `EVP_sha256`;
5. writes `manifest.json`.

### Bundle layout

The Linux part (the Windows part, under `lib\win-x64\` and `win-x64\`, is described in [BUILD-WINDOWS.md](./BUILD-WINDOWS.md);
both platforms share `include\nvat.h` and `fixtures\`):

```
include/nvat.h                          generated header (from nvat.h.in)
lib/linux-x64/libnvat.so.2              SONAME libnvat.so.2 (no libnvat.so symlink: Windows hosts cannot create it)
ldd.txt                                 resolved dependencies (libc, libm, libstdc++, libgcc_s only)
symbols/{nm-exported,nm-imported,needed}.txt
fixtures/corim/GR100_081D_9900230000.cbor            from rubin_vbios_example.diag   (key = RIM id)
fixtures/corim/NV_GPU_DRIVER_GR100_620.54.cbor       from rubin_driver_example.diag
fixtures/cmw/rubin_evidence.cmw.json                 golden Rubin CMW
fixtures/ocsp/<issuerKeyHash>_<serial>.der           live GOOD responses, named by lookup key (4 files, see below)
fixtures/ocsp-revoked/<same>.der + test-responder.pem  REVOKED(keyCompromise) variants signed by a TEST responder
fixtures/ocsp-index.json                             subject, serial, thisUpdate/nextUpdate, sha256 per response
selftest/{smoke,smoke.c,check_ear.py}, ear-<scenario>.json, <scenario>.log
build-info.json                         toolchain + static dependency versions, max GLIBC/GLIBCXX symbol versions
manifest.json                           every file with sha256 and size; NVAT git commit; build date
README.md                               this file
```

**Four OCSP files, not three:** the golden `rubin_evidence.cmw.json` embeds a different GR100 BROM and leaf
(BROM serial `410A3021DB2466FE7C`) than `sample_attestation_data/gpu/rubinCertChain.txt` (BROM serial
`418F2E55A169F0B0E3`); the GR1XX Identity and Provisioner ICA certificates are shared. A store seeded for the golden
CMW needs `…_410a3021db2466fe7c`; `…_418f2e55a169f0b0e3` is there for the chain file.

The live responses have `nextUpdate = thisUpdate + 24 h`. The unit tests and self-test therefore pin
`verification_time` just after the response's own `thisUpdate`; a host replaying these static fixtures should set
`enforce_ocsp_next_update=false` (or refresh them with `capture_ocsp.py`).

## Verified verdict matrix

Produced by `selftest/smoke` (and, with the same expectations, by `test_capi_collateral_cb.cpp`); EAR path
`submods.gpu_0.ear_verifier_claims.ear_nvidia_evidence.cert_chain[]` is root-first: `[root, GR1XX Identity, ICA, BROM, leaf]`.

| Scenario | OCSP certs (Identity, ICA, BROM) | `signature_verified` | `ear_status` (submod and top level) |
|---|---|---|---|
| cached GOOD, CoRIMs from callback, nonce off, pinned time in window | `ocsp_crl_status:"good"`, `ocsp_response_status:true`, `ocsp_nonce_matches:false`, `ocsp_crl_response_expired:false` | `true` | **`affirming`** |
| OCSP missing (callback → not found) | `ocsp_crl_status:"error"` (also leaf), `ocsp_response_status:false` | `false` | `contraindicated`; return code is still `NVAT_RC_OK` |
| OCSP REVOKED, real chain, test responder | `ocsp_crl_status:"revoked"`, `cert_check_status:"revoked"`, `ocsp_response_status:false` (responder not trusted by NVIDIA roots), `revocation_reason:"keyCompromise"` | `false` | `contraindicated` |
| OCSP REVOKED, test-CA chain trusted via `set_device_identity_roots` | leaf: `"revoked"`, `ocsp_response_status:true`; ICA `"good"` | `false` | `contraindicated` (unit test) |
| OCSP expired (`verification_time` > `nextUpdate`), enforcement on | `"good"`, `ocsp_crl_response_expired:true` | `false` | `contraindicated` |
| same, enforcement off | `"good"`, `ocsp_crl_response_expired:true` | `true` | `affirming` |
| CoRIM missing | unaffected | `true` | `contraindicated`; `ear_nvidia_rims[i]`: `fetched:false`, `error.code:104` |
| tampered evidence | - | `false` | `contraindicated` (unit test) |
| 2 GPUs (`gpu_0`, `gpu_1`) | per item | per item | per submod, top level = worst (unit test) |

NVIDIA's real certificates cannot be revoked, so "revoked" against the real chain can only be exercised with a
response signed by a test responder. OpenSSL rejects it (the responder is not anchored at NVIDIA's roots) - libnvat
still reports the status it read, flags the response as not valid and the appraisal is `contraindicated`. The test-CA
unit test shows the same response accepted when its root *is* trusted.

### EAR excerpts

Affirming (offline, cached OCSP):

```json
{ "ear_status": "affirming",
  "ear_nvidia_inputs": { "digests": [ { "alg": "sha-256", "val": "OxfXVfZGOBYKXOEzs-y-OECte4iNTNs5xKVD5wXVB-I" } ] },
  "submods": { "gpu_0": { "ear_status": "affirming",
    "ear_verifier_claims": {
      "ear_nvidia_evidence": { "signature_verified": true, "cert_chain": [
        { "cert_check_status": "valid", "expired": false, "ocsp_crl_status": "not_checked", "ocsp_nonce_matches": false, "ocsp_response_status": false, "ocsp_crl_response_expired": false, "expiration_date": "9999-12-31T23:59:59Z" },
        { "cert_check_status": "valid", "expired": false, "ocsp_crl_status": "good", "ocsp_response_status": true, "ocsp_nonce_matches": false,
          "ocsp_crl_response_expired": false, "ocsp_response_produced_at": "2026-11-12T22:18:44Z", "ocsp_crl_response_expiration_date": "2026-11-13T22:18:44Z", "expiration_date": "9999-12-31T23:59:59Z" },
        "… ICA and BROM identical in shape …",
        { "cert_check_status": "valid", "expired": false, "ocsp_crl_status": "not_checked", "…": "leaf" } ] },
      "ear_nvidia_rims": [
        { "fetched": true, "parsed": true, "signature_verified": false, "id": "example-rubin-vbios-GR100_081D_9900230000", "locator": "https://rim.attestation.nvidia.com/v1/rim/GR100_081D_9900230000" },
        { "fetched": true, "parsed": true, "signature_verified": false, "id": "example-rubin-driver-GR100_620.54",       "locator": "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GR100_620.54" } ] } } } }
```

OCSP missing - the walk starts at the certificate nearest the root and stops at the first failed lookup; every certificate
that was not successfully checked is marked `error`:

```json
{ "ear_status": "contraindicated",
  "submods": { "gpu_0": { "ear_status": "contraindicated",
    "ear_verifier_claims": { "ear_nvidia_evidence": { "signature_verified": false, "cert_chain": [
      { "ocsp_crl_status": "not_checked", "…": "root" },
      { "cert_check_status": "valid", "ocsp_crl_status": "error", "ocsp_response_status": false, "ocsp_nonce_matches": false, "ocsp_crl_response_expired": false },
      { "…": "ICA, BROM and leaf identical: ocsp_crl_status error" } ] } } } } }
```

OCSP revoked (real chain, test responder), each of the three AIA certificates:

```json
{ "cert_check_status": "revoked", "expired": false, "ocsp_crl_status": "revoked", "ocsp_response_status": false,
  "ocsp_nonce_matches": false, "revocation_reason": "keyCompromise",
  "ocsp_response_revoked_at": "2026-11-12T21:18:44Z", "ocsp_response_produced_at": "2026-11-12T22:18:43Z",
  "ocsp_crl_response_expired": false, "ocsp_crl_response_expiration_date": "2036-11-09T22:18:44Z" }
```

Complete outputs: `selftest/ear-<scenario>.json` in the bundle.

## Tests

* `unit-tests/test_capi_collateral_cb.cpp` (`CApiCollateralCbTest.*`): the matrix above through the C ABI, the lookup-key
  format (cross-checked against an independent python implementation), argument validation, a 5-lookups-exactly
  assertion for the golden run (with a *decoy* network configuration that would break any I/O outside the callback),
  `+json` hints + exact-bytes input digest, legacy equivalence, and 8 threads × 5 calls on one shared verifier with
  different callback contexts.
* `test_corim_store.cpp` (collateral lookup, key derivation, allowlist, envelope), `nv_x509_test.cpp`
  (`all_certs_trusted` options), `test_cmw.cpp` (`+json` hints), `test_local_corim_verifier.cpp` (`+json` hints are not
  the FSP firmware hint).
* Fixtures: real captured OCSP responses in `sample_attestation_data/gpu/rubin_ocsp/`; REVOKED variants and a complete
  test device-identity PKI (Root → ICA → leaf, delegated responders, GOOD and REVOKED responses) are generated at
  test-prep time by `unit-tests/testdata/ocsp_fixtures/generate_test_ocsp_fixtures.py` (python `cryptography`).
  No test depends on the wall clock.

Run just the new tests in the container: `bash /scripts/test.sh -R CApiCollateralCb` (see `container/`).

Sanitizer runs (not part of `build-bundle.ps1`): `container/build.sh asan|tsan` builds `build-asan` / `build-tsan`; run with
`BUILD_DIR=build-asan bash /scripts/test.sh ...`. On kernels with high-entropy ASLR clang-14 sanitizers crash at startup:
use `--repeat until-pass:6` for ASan, and for TSan start the container with `--security-opt seccomp=unconfined` and run the
build and tests under `setarch x86_64 -R`. ASan (+LeakSanitizer): 153 related tests clean. TSan: the 8-thread test reports only a
false positive inside the *uninstrumented* static OpenSSL 3.6 RCU hash table (`alloc_new_value` / `match_key`, reached from
`anchor_device_chain`); with `TSAN_OPTIONS=suppressions=` (`race:alloc_new_value`, `race:match_key`) 34 tests are clean.

## Deviations from the design document

* "Not found" is the existing `NVAT_RC_CACHE_OBJECT_NOT_FOUND` (14); no `NVAT_RC_COLLATERAL_NOT_FOUND`.
* The CMW hints consumer is `extract_firmware_version_hint` in `src/corim_verify.cpp`, not `blackwell_fsp.cpp`.
* `OcspVerifyOptions` (already plumbed through `generate_per_cert_status` / `collect_ocsp_responses` / COSE) carries the per-call
  nonce / nextUpdate / time policy; the trust store used by `OCSP_basic_verify` is copied per call when a time is pinned.
* The golden CMW's chain differs from `rubinCertChain.txt` (see above): four OCSP fixtures.
