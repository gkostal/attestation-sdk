# Offline C ABI verification

`nvat_local_corim_verifier_verify_cmw_ex` extends the existing C API without
changing legacy verification defaults. A null call-options handle is equivalent
to `nvat_local_corim_verifier_verify_cmw`. Non-null options default to requiring
OCSP nonce matching and enforcing OCSP `nextUpdate` freshness. Cached responses
have no request nonce, so cached-response callers must explicitly disable the
nonce requirement.

```c
nvat_corim_store_t store = NULL;
nvat_local_corim_verifier_t verifier = NULL;
nvat_verify_call_options_t options = NULL;
nvat_str_t ear = NULL;
nvat_corim_store_create(&store, NULL, NULL);
nvat_local_corim_verifier_create(&verifier, &store, NULL); /* consumes store */
nvat_local_corim_verifier_set_verify_evidence_signature(verifier, true);
nvat_local_corim_verifier_set_verify_rim_signature(verifier, false); /* unsigned test RIMs */
nvat_local_corim_verifier_set_verify_revocation(verifier, true);
nvat_verify_call_options_create(&options);
nvat_verify_call_options_set_collateral_callback(options, lookup, request_context);
nvat_verify_call_options_set_require_ocsp_nonce(options, false);
nvat_verify_call_options_set_verification_time(options, 1794577830); /* fixture replay only */
nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw_ex(
    verifier, cmw, cmw_len, NVAT_CMW_FORMAT_JSON, options, NULL, NULL, &ear);
/* Read ear via nvat_str_get_data / nvat_str_length; check rc first. */
nvat_str_free(&ear);
nvat_verify_call_options_free(&options);
nvat_local_corim_verifier_free(&verifier);
```

Check every return code in production. Initialize the SDK once, before concurrent
verification. Do not disable RIM signatures or freshness in a production verifier.
Serialized lazy initialization on a request thread (e.g. `std::call_once`) is
supported; the public ABI tests initialize on a worker thread. Options and logger
handles retain shared ownership and may be kept until after `nvat_sdk_shutdown`,
then freed. Callback user data must remain alive while its logger is reachable.

## Callback and ownership

`lookup(user_data, kind, key, &buffer)` is synchronous. On success allocate the
buffer with `nvat_byte_buf_create`; libnvat takes ownership and always frees it,
including on callback errors. Absent collateral returns
`NVAT_RC_COLLATERAL_NOT_FOUND` with a null buffer. Keys and user data are borrowed.
An empty successful buffer is processed as invalid collateral, never a fallback
to native fetching.

* CoRIM keys: the canonical ID from NVIDIA `/v1/rim/<id>` URLs; other allowlisted
  URLs are passed intact. Raw URLs are authorized **before** rewrites. Empty,
  traversal, escaped, slash/backslash, query and fragment IDs are rejected.
* OCSP keys: lowercase SHA-256 `issuerKeyHash` from the OCSP CertID, underscore,
  lowercase even-length serial hex. This is **not** a certificate thumbprint.
* Callback CoRIM values may be raw CBOR/COSE or a RIM-service JSON envelope.
* OCSP values must be DER RFC 6960 OCSPResponse. Responder signature, authorized
  certificate chain, matching SHA-256 CertID and timestamps are verified with
  OpenSSL. Future statuses fail even when `nextUpdate` enforcement is disabled.
  Certs without an AIA responder (and the chain root) are `not_checked`.

Installing a callback disables native network/filesystem fetches for that call.
Both the shared CoRIM cache and configured HTTP/cache OCSP client are bypassed;
callback results never enter these caches. Each call snapshots verifier
configuration under a mutex and uses its own trust stores and OCSP client.
Different callers may concurrently share one verifier with unrelated callbacks,
user data, verification times and policy settings. Configuration setters are
serialized with snapshot creation. Do not mutate/free options while in use, or
free the verifier while calls are active.

Missing/corrupt/revoked/expired OCSP produces a well-formed contraindicated EAR,
not a bundle-fatal error. Missing CoRIM also contraindicates the item. Malformed
CMW returns `NVAT_RC_EVIDENCE_MALFORMED` and no EAR. Generic JSON and vendor
`application/*+json` hints are accepted; Blackwell firmware hints are read only
from `application/json`.

## Fixtures and validation

Fixtures are committed in `unit-tests/testdata/offline-collateral`. Real Rubin
OCSP capture metadata includes SHA-256 checksums, lookup keys and a pinned time
within all three validity windows. `expired_verification_time` lies after every
`nextUpdate`. No test depends on today's date or live NVIDIA services.

The CMW's embedded certificate chain is authoritative: its BROM serial is
`410a3021db2466fe7c`, whereas the separate `gpu/rubinCertChain.txt` sample uses
`418f2e55a169f0b0e3`. The bundle retains a genuine response for both; the replay
metadata selects the CMW chain. `rubin-cmw-cert-chain.pem` is extracted from the
unmodified CMW and is also the source of the synthetic DTI-bearing certificates.

Synthetic fixtures replace the original Rubin signing chain with a **test-only**
root, ICA and SPDM-signing leaf; the DTI extensions and measurements are retained,
and the transcript is re-signed. The leaf has signed GOOD and REVOKED responses.
`nvat_local_corim_verifier_set_device_identity_roots` explicitly replaces device
roots to test this chain. Never install this root outside tests.

```sh
cmake -S nv-attestation-sdk-cpp -B build -DBUILD_TESTING=ON \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build --target nvat-offline-cabi-tests -j6
ctest --test-dir build -R '^nvat-offline-cabi-tests$' --output-on-failure
nm -D --defined-only build/libnvat.so.2
bash nv-attestation-sdk-cpp/scripts/validate-offline-cabi.sh build
```

The public ABI test executable links the real shared library using only `nvat.h`.
The validation script also compiles/runs a C caller, traces a fresh verification
process (rejecting every file/network syscall between the verification markers),
and runs with the system OpenSSL library preloaded. SDK initialization completes
libc's lazy timezone initialization before the offline call boundary.
Existing white-box C++ tests use a private static SDK copy because Linux shared
builds now expose only `nvat_*` C API symbols. The build remains Ubuntu 22.04
compatible and statically links its private OpenSSL/curl/XML/Rust dependencies.

To deliberately refresh fixtures, run `scripts/capture-rubin-ocsp.sh` with the
testdata root and a build-tree working directory (delete old `cert*.der` captures
first). To regenerate the test CA, compile `scripts/generate-offline-fixtures.cpp`
against OpenSSL and nlohmann/json and pass the testdata root and offline fixture
directory. Regeneration changes CA keys/signatures and metadata; test execution
never regenerates or downloads the committed replay fixtures.
