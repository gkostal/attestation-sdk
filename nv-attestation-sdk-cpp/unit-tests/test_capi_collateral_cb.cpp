/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Offline verification through the C ABI: nvat_local_corim_verifier_verify_cmw_ex with a
// per-call collateral callback (CoRIMs + cached OCSP responses), OCSP nonce / nextUpdate
// policy and a pinned verification time.
//
// Hermetic: every CoRIM and OCSP response comes from the callback, so this suite also
// passes in a container without a network (see dev/maa-prototype/README.md). Fixtures:
//  - sample_attestation_data/gpu/rubin_ocsp/*.der      real NVIDIA OCSP responses (GOOD)
//  - ocsp_fixtures/generated/rubin_ocsp_revoked/*.der  REVOKED, signed by a test responder
//  - ocsp_fixtures/generated/test_ca/                  test device-identity PKI + responses
// No test depends on the wall clock: the pinned verification time is derived from the
// response's own thisUpdate / nextUpdate.

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ocsp.h>

#include <nlohmann/json.hpp>

#include "gtest/gtest.h"

#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/utils.h"
#include "nvat.h"

namespace {

using nlohmann::json;
using nvattestation::Error;

constexpr const char *kRubinCmwPath =
    "testdata/sample_attestation_data/rubin_evidence.cmw.json";
constexpr const char *kRubinChainPath =
    "testdata/sample_attestation_data/gpu/rubinCertChain.txt";
constexpr const char *kRubinVbiosCorimPath =
    "testdata/sample_rims/corim/rubin_vbios_example.cbor";
constexpr const char *kRubinDriverCorimPath =
    "testdata/sample_rims/corim/rubin_driver_example.cbor";
constexpr const char *kRubinOcspDir =
    "testdata/sample_attestation_data/gpu/rubin_ocsp";
constexpr const char *kRubinRevokedOcspDir =
    "testdata/ocsp_fixtures/generated/rubin_ocsp_revoked";
constexpr const char *kTestCaDir = "testdata/ocsp_fixtures/generated/test_ca";

constexpr const char *kVbiosRimId = "GR100_081D_9900230000";
constexpr const char *kDriverRimId = "NV_GPU_DRIVER_GR100_620.54";
constexpr const char *kVbiosUrl =
    "https://rim.attestation.nvidia.com/v1/rim/GR100_081D_9900230000";
constexpr const char *kDriverUrl =
    "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GR100_620.54";

// Lookup keys (issuerKeyHash_serial) of the AIA-bearing certificates of the Rubin chains, as
// written by dev/maa-prototype/capture_ocsp.py (an independent implementation of the documented
// format). The golden CMW embeds a different GR100 BROM/leaf than
// sample_attestation_data/gpu/rubinCertChain.txt; ICA and Identity are shared.
constexpr const char *kOcspKeyBrom =
    "65129acf8647f4285e8d07c09c5320949aacff2b8dd3917540b15d8833813f52_410a3021db2466fe7c";
constexpr const char *kOcspKeyBromChainFile =
    "65129acf8647f4285e8d07c09c5320949aacff2b8dd3917540b15d8833813f52_418f2e55a169f0b0e3";
constexpr const char *kOcspKeyIca =
    "115a377933f4e800ffcb8543a33536375173f75c66e1dd02db5f849fff113f27_"
    "44d719c02afb194c5c0bc7497c2e81bf";
constexpr const char *kOcspKeyIdentity =
    "6f0264e4bce92d49cd76d17f79e2719ea1972af859fbae04eb2516b8317a8e9e_"
    "2c2f9f328f20749cda9060e7d165256";

// Rubin chain, root first, as it appears in the EAR's cert_chain array.
constexpr size_t kRootIndex = 0;
constexpr size_t kIdentityIndex = 1;
constexpr size_t kIcaIndex = 2;
constexpr size_t kBromIndex = 3;
constexpr size_t kLeafIndex = 4;

using Bytes = std::vector<uint8_t>;

Bytes load_bytes(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        ADD_FAILURE() << "cannot read fixture " << path;
        return {};
    }
    return Bytes(std::istreambuf_iterator<char>(in),
                 std::istreambuf_iterator<char>());
}

std::string load_text(const std::string &path) {
    const Bytes bytes = load_bytes(path);
    return std::string(bytes.begin(), bytes.end());
}

std::string base64url(const Bytes &bytes) {
    std::string encoded;
    EXPECT_EQ(nvattestation::encode_base64url(bytes, encoded), Error::Ok);
    return encoded;
}

struct OcspTimes {
    time_t this_update = 0;
    time_t next_update = 0;
};

time_t asn1_to_epoch(const ASN1_TIME *time_value) {
    struct tm parsed {};
    EXPECT_EQ(ASN1_TIME_to_tm(time_value, &parsed), 1);
    return timegm(&parsed);
}

OcspTimes read_ocsp_times(const Bytes &der) {
    const unsigned char *cursor = der.data();
    nvattestation::nv_unique_ptr<OCSP_RESPONSE> response(
        d2i_OCSP_RESPONSE(nullptr, &cursor, static_cast<long>(der.size())));
    OcspTimes times;
    if (!response) {
        ADD_FAILURE() << "fixture is not an OCSPResponse";
        return times;
    }
    nvattestation::nv_unique_ptr<OCSP_BASICRESP> basic(OCSP_response_get1_basic(response.get()));
    if (!basic || OCSP_resp_count(basic.get()) < 1) {
        ADD_FAILURE() << "fixture has no basic response";
        return times;
    }
    OCSP_SINGLERESP *single = OCSP_resp_get0(basic.get(), 0);
    ASN1_GENERALIZEDTIME *this_update = nullptr;
    ASN1_GENERALIZEDTIME *next_update = nullptr;
    OCSP_single_get0_status(single, nullptr, nullptr, &this_update, &next_update);
    times.this_update = asn1_to_epoch(this_update);
    times.next_update = asn1_to_epoch(next_update);
    return times;
}

// ---------------------------------------------------------------------------------
// Collateral store: a thread-safe request log + the callback handed to libnvat.

class CollateralStore {
  public:
    std::map<std::string, Bytes> corims;
    std::map<std::string, Bytes> ocsp;
    // When set, the callback reports this code (and no buffer) for every request.
    nvat_rc_t forced_rc = NVAT_RC_OK;
    // When set, a successful lookup returns OK *without* allocating a buffer.
    bool return_ok_without_buffer = false;

    static nvat_rc_t Callback(void *user_data, nvat_collateral_kind_t kind,
                              const char *lookup_key, nvat_byte_buf_t *out) {
        auto *self = static_cast<CollateralStore *>(user_data);
        std::lock_guard<std::mutex> lock(self->m_mutex);
        self->m_requests.emplace_back(kind, lookup_key);
        if (*out != nullptr) {
            ADD_FAILURE() << "libnvat must pass *out_collateral == NULL";
        }
        if (self->forced_rc != NVAT_RC_OK) {
            return self->forced_rc;
        }
        const auto &source = kind == NVAT_COLLATERAL_KIND_CORIM ? self->corims : self->ocsp;
        auto found = source.find(lookup_key);
        if (found == source.end()) {
            return NVAT_RC_CACHE_OBJECT_NOT_FOUND;
        }
        if (self->return_ok_without_buffer) {
            return NVAT_RC_OK;
        }
        return nvat_byte_buf_create(out, found->second.data(), found->second.size());
    }

    std::vector<std::pair<nvat_collateral_kind_t, std::string>> requests() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_requests;
    }

    std::multiset<std::string> requested_keys(nvat_collateral_kind_t kind) const {
        std::multiset<std::string> keys;
        for (const auto &request : requests()) {
            if (request.first == kind) {
                keys.insert(request.second);
            }
        }
        return keys;
    }

  private:
    mutable std::mutex m_mutex;
    std::vector<std::pair<nvat_collateral_kind_t, std::string>> m_requests;
};

void load_real_good_ocsp(CollateralStore &store) {
    for (const char *key : {kOcspKeyBrom, kOcspKeyIca, kOcspKeyIdentity}) {
        store.ocsp[key] = load_bytes(std::string(kRubinOcspDir) + "/" + key + ".der");
    }
}

void load_rubin_corims(CollateralStore &store) {
    store.corims[kVbiosRimId] = load_bytes(kRubinVbiosCorimPath);
    store.corims[kDriverRimId] = load_bytes(kRubinDriverCorimPath);
}

// The window every pinned time in this suite is taken from: just after the latest
// thisUpdate of the three real responses, and past the earliest nextUpdate.
struct RealOcspWindow {
    time_t latest_this_update = 0;
    time_t earliest_next_update = 0;
    time_t latest_next_update = 0;
};

RealOcspWindow real_ocsp_window() {
    RealOcspWindow window;
    window.earliest_next_update = std::numeric_limits<time_t>::max();
    for (const char *key : {kOcspKeyBrom, kOcspKeyIca, kOcspKeyIdentity}) {
        const OcspTimes times =
            read_ocsp_times(load_bytes(std::string(kRubinOcspDir) + "/" + key + ".der"));
        window.latest_this_update = std::max(window.latest_this_update, times.this_update);
        window.earliest_next_update = std::min(window.earliest_next_update, times.next_update);
        window.latest_next_update = std::max(window.latest_next_update, times.next_update);
    }
    return window;
}

// ---------------------------------------------------------------------------------
// RAII handles over the C ABI.

class Verifier {
  public:
    enum class Mode {
        // No OCSP client (what an embedding host without network access creates).
        kNoOcspClient,
        // Real AIA OCSP client + CoRIM rewrites that would fail (missing file / refused
        // connection): any libnvat I/O that bypasses the callback breaks the verdict.
        kDecoyNetworkConfiguration,
    };

    explicit Verifier(Mode mode = Mode::kNoOcspClient) {
        EXPECT_EQ(nvat_corim_store_create(&m_store, nullptr, nullptr), NVAT_RC_OK);
        if (mode == Mode::kDecoyNetworkConfiguration) {
            EXPECT_EQ(nvat_corim_store_add_url_rewrite(
                          m_store, kVbiosUrl, "file:///nonexistent/nvat-test/vbios.cbor"),
                      NVAT_RC_OK);
            EXPECT_EQ(nvat_corim_store_add_url_rewrite(m_store, kDriverUrl,
                                                       "https://127.0.0.1:9/driver"),
                      NVAT_RC_OK);
            const char *patterns[] = {"http://ocsp.ndis.nvidia.com"};
            const char *replacements[] = {"http://127.0.0.1:9"};
            EXPECT_EQ(nvat_ocsp_client_create_aia(&m_ocsp, nullptr, nullptr, nullptr,
                                                  patterns, replacements, 1, nullptr),
                      NVAT_RC_OK);
        }
        EXPECT_EQ(nvat_local_corim_verifier_create(&m_verifier, &m_store, m_ocsp),
                  NVAT_RC_OK);
        EXPECT_EQ(nvat_local_corim_verifier_set_verify_rim_signature(m_verifier, false),
                  NVAT_RC_OK);
        EXPECT_EQ(nvat_local_corim_verifier_set_verify_revocation(m_verifier, true),
                  NVAT_RC_OK);
    }
    ~Verifier() {
        nvat_local_corim_verifier_free(&m_verifier);
        nvat_corim_store_free(&m_store);  // NULL after a successful create
        nvat_ocsp_client_free(&m_ocsp);
    }
    Verifier(const Verifier &) = delete;
    Verifier &operator=(const Verifier &) = delete;

    nvat_local_corim_verifier_t get() const { return m_verifier; }

  private:
    nvat_corim_store_t m_store = nullptr;
    nvat_ocsp_client_t m_ocsp = nullptr;
    nvat_local_corim_verifier_t m_verifier = nullptr;
};

class CallOptions {
  public:
    CallOptions(CollateralStore *store, bool require_nonce, bool enforce_next_update,
                int64_t verification_time) {
        EXPECT_EQ(nvat_verify_call_options_create(&m_options), NVAT_RC_OK);
        if (store != nullptr) {
            EXPECT_EQ(nvat_verify_call_options_set_collateral_callback(
                          m_options, &CollateralStore::Callback, store),
                      NVAT_RC_OK);
        }
        EXPECT_EQ(nvat_verify_call_options_set_require_ocsp_nonce(m_options, require_nonce),
                  NVAT_RC_OK);
        EXPECT_EQ(nvat_verify_call_options_set_enforce_ocsp_next_update(m_options,
                                                                        enforce_next_update),
                  NVAT_RC_OK);
        EXPECT_EQ(nvat_verify_call_options_set_verification_time(m_options, verification_time),
                  NVAT_RC_OK);
    }
    ~CallOptions() { nvat_verify_call_options_free(&m_options); }
    CallOptions(const CallOptions &) = delete;
    CallOptions &operator=(const CallOptions &) = delete;

    nvat_verify_call_options_t get() const { return m_options; }

  private:
    nvat_verify_call_options_t m_options = nullptr;
};

// The settings of the MAA-style offline call: cached OCSP (no nonce), nextUpdate enforced,
// verification time pinned inside the captured responses' window.
std::unique_ptr<CallOptions> offline_options(CollateralStore *store, time_t pinned_time,
                                             bool enforce_next_update = true) {
    return std::unique_ptr<CallOptions>(new CallOptions(
        store, /*require_nonce=*/false, enforce_next_update, static_cast<int64_t>(pinned_time)));
}

struct Outcome {
    nvat_rc_t rc = NVAT_RC_UNKNOWN;
    json ear = json::object();
};

Outcome verify_ex(const Verifier &verifier, const std::string &cmw,
                  const nvat_verify_call_options_t options) {
    Outcome outcome;
    nvat_str_t ear_json = nullptr;
    outcome.rc = nvat_local_corim_verifier_verify_cmw_ex(
        verifier.get(), reinterpret_cast<const uint8_t *>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, options, nullptr, nullptr, &ear_json);
    if (ear_json != nullptr) {
        char *data = nullptr;
        size_t length = 0;
        if (nvat_str_get_data(ear_json, &data) == NVAT_RC_OK &&
            nvat_str_length(ear_json, &length) == NVAT_RC_OK) {
            outcome.ear = json::parse(std::string(data, length), nullptr, false);
        }
        nvat_str_free(&ear_json);
    }
    return outcome;
}

// Copies of nested EAR members; a missing member yields an empty object rather than touching a
// missing key of a const json (undefined behavior), so a failing test reports instead of crashing.
json member(const json &parent, const char *key) {
    return parent.is_object() && parent.contains(key) ? json(parent.at(key)) : json::object();
}

json submod(const json &ear, const char *label = "gpu_0") {
    return member(member(ear, "submods"), label);
}

json evidence_claims(const json &ear, const char *label = "gpu_0") {
    return member(member(submod(ear, label), "ear_verifier_claims"), "ear_nvidia_evidence");
}

json cert_chain(const json &ear, const char *label = "gpu_0") {
    return member(evidence_claims(ear, label), "cert_chain");
}

std::string status_of(const json &ear, const char *label = "gpu_0") {
    const json status = member(submod(ear, label), "ear_status");
    return status.is_string() ? status.get<std::string>() : "<missing>";
}

json rim_results(const json &ear, const char *label = "gpu_0") {
    return member(member(submod(ear, label), "ear_verifier_claims"), "ear_nvidia_rims");
}

std::string read_rubin_cmw() { return load_text(kRubinCmwPath); }

// ---------------------------------------------------------------------------------
// Basics: byte buffers, option handles, argument validation.

TEST(CApiCollateralCbTest, ByteBufCreateAndFree) {
    const Bytes payload = {1, 2, 3, 4, 5};
    nvat_byte_buf_t buf = nullptr;
    ASSERT_EQ(nvat_byte_buf_create(&buf, payload.data(), payload.size()), NVAT_RC_OK);
    ASSERT_NE(buf, nullptr);
    nvat_byte_buf_free(&buf);
    EXPECT_EQ(buf, nullptr);
    nvat_byte_buf_free(&buf);  // idempotent
    nvat_byte_buf_free(nullptr);

    ASSERT_EQ(nvat_byte_buf_create(&buf, nullptr, 0), NVAT_RC_OK);  // empty buffer is allowed
    nvat_byte_buf_free(&buf);

    EXPECT_EQ(nvat_byte_buf_create(nullptr, payload.data(), payload.size()),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_byte_buf_create(&buf, nullptr, 3), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(buf, nullptr);
}

TEST(CApiCollateralCbTest, CallOptionsArgumentValidation) {
    nvat_verify_call_options_t options = nullptr;
    EXPECT_EQ(nvat_verify_call_options_create(nullptr), NVAT_RC_BAD_ARGUMENT);
    ASSERT_EQ(nvat_verify_call_options_create(&options), NVAT_RC_OK);
    EXPECT_EQ(nvat_verify_call_options_set_verification_time(options, -1), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_call_options_set_verification_time(options, 0), NVAT_RC_OK);
    EXPECT_EQ(nvat_verify_call_options_set_collateral_callback(nullptr, nullptr, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_call_options_set_require_ocsp_nonce(nullptr, true), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_call_options_set_enforce_ocsp_next_update(nullptr, true),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_call_options_set_verification_time(nullptr, 5), NVAT_RC_BAD_ARGUMENT);
    nvat_verify_call_options_free(&options);
    EXPECT_EQ(options, nullptr);
    nvat_verify_call_options_free(&options);
    nvat_verify_call_options_free(nullptr);
}

TEST(CApiCollateralCbTest, VerifyCmwExRejectsNullArguments) {
    Verifier verifier;
    const std::string cmw = read_rubin_cmw();
    const auto *data = reinterpret_cast<const uint8_t *>(cmw.data());
    nvat_str_t out = nullptr;
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw_ex(nullptr, data, cmw.size(),
                                                      NVAT_CMW_FORMAT_JSON, nullptr, nullptr,
                                                      nullptr, &out),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw_ex(verifier.get(), nullptr, 0,
                                                      NVAT_CMW_FORMAT_JSON, nullptr, nullptr,
                                                      nullptr, &out),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(out, nullptr);
}

TEST(CApiCollateralCbTest, SetDeviceIdentityRootsValidatesArguments) {
    Verifier verifier;
    const std::string garbage = "-----BEGIN CERTIFICATE-----\nnot a cert\n-----END CERTIFICATE-----\n";
    const char *bad_roots[] = {garbage.c_str()};
    const char *null_entry[] = {nullptr};
    EXPECT_EQ(nvat_local_corim_verifier_set_device_identity_roots(nullptr, bad_roots, 1),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_set_device_identity_roots(verifier.get(), nullptr, 1),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_set_device_identity_roots(verifier.get(), bad_roots, 0),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_set_device_identity_roots(verifier.get(), null_entry, 1),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_set_device_identity_roots(verifier.get(), bad_roots, 1),
              NVAT_RC_BAD_ARGUMENT);

    // A rejected replacement leaves the built-in NVIDIA root in place: the golden
    // evidence still anchors and affirms.
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "affirming");
}

// ---------------------------------------------------------------------------------
// OCSP lookup key.

// Lookup keys of a PEM chain's certificates (leaf first), as libnvat derives them: each
// certificate paired with the next one as its issuer, SHA-256 CertID.
std::vector<std::string> lookup_keys_of_chain(const std::string &chain_pem) {
    std::vector<nvattestation::nv_unique_ptr<X509>> certs;
    size_t cursor = 0;
    const std::string end_marker = "-----END CERTIFICATE-----";
    for (size_t end = chain_pem.find(end_marker, cursor); end != std::string::npos;
         end = chain_pem.find(end_marker, cursor)) {
        certs.push_back(nvattestation::x509_from_cert_string(
            chain_pem.substr(cursor, end + end_marker.size() - cursor)));
        EXPECT_NE(certs.back(), nullptr);
        cursor = end + end_marker.size();
    }
    std::vector<std::string> keys;
    for (size_t i = 0; i + 1 < certs.size(); ++i) {
        nvattestation::nv_unique_ptr<OCSP_CERTID> cert_id;
        EXPECT_EQ(nvattestation::NvHttpOcspClient::create_cert_id(
                      nvattestation::OcspCertIdHashAlgorithm::Sha256, certs[i].get(),
                      certs[i + 1].get(), cert_id),
                  Error::Ok);
        std::string key;
        EXPECT_EQ(nvattestation::ocsp_collateral_lookup_key(cert_id.get(), key), Error::Ok);
        keys.push_back(key);
    }
    return keys;
}

TEST(CApiCollateralCbTest, OcspLookupKeyIsIssuerKeyHashAndSerialInLowerHex) {
    // Documented format: "<SHA-256 issuerKeyHash lower hex>_<serial lower hex, no leading zeros>".
    const std::vector<std::string> chain_file_keys = lookup_keys_of_chain(load_text(kRubinChainPath));
    ASSERT_EQ(chain_file_keys.size(), 4U);
    for (const std::string &key : chain_file_keys) {
        // 64 hex digits, underscore, then hex without leading zeros.
        ASSERT_GT(key.size(), 66U);
        EXPECT_EQ(key[64], '_');
        EXPECT_EQ(key.find_first_not_of("0123456789abcdef_"), std::string::npos) << key;
        EXPECT_NE(key[65], '0') << key;
    }
    // [leaf (no AIA), BROM, ICA, Identity]; the root is the last certificate.
    EXPECT_EQ(chain_file_keys[1], kOcspKeyBromChainFile);
    EXPECT_EQ(chain_file_keys[2], kOcspKeyIca);
    EXPECT_EQ(chain_file_keys[3], kOcspKeyIdentity);
    // Serial 0x02c2f9f3... loses its leading zero nibble.
    EXPECT_EQ(chain_file_keys[3].substr(65, 2), "2c");

    // The golden CMW's own chain (a different BROM/leaf than the chain file).
    const json cmw = json::parse(read_rubin_cmw());
    Bytes pem;
    ASSERT_EQ(nvattestation::decode_base64url(cmw["gpu_0"]["certificate"][1].get<std::string>(), pem),
              Error::Ok);
    const std::vector<std::string> cmw_keys =
        lookup_keys_of_chain(std::string(pem.begin(), pem.end()));
    ASSERT_EQ(cmw_keys.size(), 4U);
    EXPECT_EQ(cmw_keys[1], kOcspKeyBrom);
    EXPECT_EQ(cmw_keys[2], kOcspKeyIca);
    EXPECT_EQ(cmw_keys[3], kOcspKeyIdentity);
}

// ---------------------------------------------------------------------------------
// (a) Golden offline appraisal.

TEST(CApiCollateralCbTest, OfflineGoldenRubinIsAffirmingWithCachedOcsp) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    const RealOcspWindow window = real_ocsp_window();
    ASSERT_GT(window.latest_this_update, 0);

    // Decoy network configuration: if libnvat bypassed the callback for the CoRIMs
    // (file / https rewrite) or for OCSP (AIA client -> 127.0.0.1:9) the verdict would fail.
    Verifier verifier(Verifier::Mode::kDecoyNetworkConfiguration);
    const auto options = offline_options(&store, window.latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(outcome.ear["ear_status"], "affirming");
    EXPECT_EQ(status_of(outcome.ear), "affirming");

    json chain = cert_chain(outcome.ear);
    ASSERT_EQ(chain.size(), 5U);
    for (size_t index : {kIdentityIndex, kIcaIndex, kBromIndex}) {
        json cert = chain[index];
        EXPECT_EQ(cert["ocsp_crl_status"], "good") << index;
        EXPECT_EQ(cert["ocsp_response_status"], true) << index;
        EXPECT_EQ(cert["ocsp_nonce_matches"], false) << index;
        EXPECT_EQ(cert["ocsp_crl_response_expired"], false) << index;
        EXPECT_EQ(cert["cert_check_status"], "valid") << index;
        EXPECT_TRUE(cert.contains("ocsp_response_produced_at")) << index;
        EXPECT_TRUE(cert.contains("ocsp_crl_response_expiration_date")) << index;
    }
    // The root and the leaf have no AIA OCSP responder.
    EXPECT_EQ(chain[kRootIndex]["ocsp_crl_status"], "not_checked");
    EXPECT_EQ(chain[kLeafIndex]["ocsp_crl_status"], "not_checked");
    EXPECT_EQ(evidence_claims(outcome.ear)["signature_verified"], true);

    json rims = submod(outcome.ear)["ear_verifier_claims"]["ear_nvidia_rims"];
    ASSERT_EQ(rims.size(), 2U);
    for (json rim : rims) {
        EXPECT_EQ(rim["fetched"], true);
        EXPECT_EQ(rim["parsed"], true);
        EXPECT_FALSE(rim.contains("error"));
    }

    // Exactly the expected collateral requests -- nothing else was asked for.
    EXPECT_EQ(store.requested_keys(NVAT_COLLATERAL_KIND_CORIM),
              (std::multiset<std::string>{kVbiosRimId, kDriverRimId}));
    EXPECT_EQ(store.requested_keys(NVAT_COLLATERAL_KIND_OCSP_RESPONSE),
              (std::multiset<std::string>{kOcspKeyBrom, kOcspKeyIca, kOcspKeyIdentity}));
    EXPECT_EQ(store.requests().size(), 5U);
}

// Cached responses can never echo a per-request nonce; nonce checking is on by default.
TEST(CApiCollateralCbTest, CachedOcspIsRejectedWhileOcspNonceIsRequired) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    Verifier verifier;
    CallOptions options(&store, /*require_nonce=*/true, /*enforce_next_update=*/true,
                        static_cast<int64_t>(real_ocsp_window().latest_this_update + 300));
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options.get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    EXPECT_EQ(cert_chain(outcome.ear)[kBromIndex]["ocsp_crl_status"], "good");
    EXPECT_EQ(cert_chain(outcome.ear)[kBromIndex]["ocsp_nonce_matches"], false);
    EXPECT_EQ(evidence_claims(outcome.ear)["signature_verified"], false);
}

// Without revocation checking there are no OCSP lookups at all.
TEST(CApiCollateralCbTest, RevocationDisabledAsksForNoOcspResponses) {
    CollateralStore store;
    load_rubin_corims(store);
    Verifier verifier;
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier.get(), false),
              NVAT_RC_OK);
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "affirming");
    EXPECT_TRUE(store.requested_keys(NVAT_COLLATERAL_KIND_OCSP_RESPONSE).empty());
    EXPECT_EQ(store.requested_keys(NVAT_COLLATERAL_KIND_CORIM).size(), 2U);
}

// ---------------------------------------------------------------------------------
// (b) Missing OCSP.

TEST(CApiCollateralCbTest, MissingOcspIsContraindicatedWithErrorStatusNotAFailure) {
    CollateralStore store;
    load_rubin_corims(store);  // no OCSP at all
    Verifier verifier;
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK) << "appraisal findings are results, not return codes";
    EXPECT_EQ(outcome.ear["ear_status"], "contraindicated");
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    json chain = cert_chain(outcome.ear);
    ASSERT_EQ(chain.size(), 5U);
    // The first lookup (the certificate nearest the root) failed; the walk stops there and every
    // certificate that was not (successfully) checked is marked "error".
    for (size_t index : {kIdentityIndex, kIcaIndex, kBromIndex}) {
        EXPECT_EQ(chain[index]["ocsp_crl_status"], "error") << index;
        EXPECT_EQ(chain[index]["ocsp_response_status"], false) << index;
    }
    EXPECT_EQ(chain[kRootIndex]["ocsp_crl_status"], "not_checked");
    EXPECT_EQ(evidence_claims(outcome.ear)["signature_verified"], false);
    // The CoRIMs were still fetched and matched.
    json rims = rim_results(outcome.ear);
    for (json rim : rims) {
        EXPECT_EQ(rim["fetched"], true);
    }
}

TEST(CApiCollateralCbTest, OneMissingOcspResponseLeavesTheEarlierCertsGood) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    store.ocsp.erase(kOcspKeyBrom);  // the certificate nearest the leaf
    Verifier verifier;
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    json chain = cert_chain(outcome.ear);
    EXPECT_EQ(chain[kIdentityIndex]["ocsp_crl_status"], "good");
    EXPECT_EQ(chain[kIcaIndex]["ocsp_crl_status"], "good");
    EXPECT_EQ(chain[kBromIndex]["ocsp_crl_status"], "error");
    EXPECT_EQ(chain[kLeafIndex]["ocsp_crl_status"], "error");
}

TEST(CApiCollateralCbTest, CallbackFailuresAreTreatedLikeMissingCollateral) {
    const std::string cmw = read_rubin_cmw();
    for (nvat_rc_t code : {static_cast<nvat_rc_t>(NVAT_RC_INTERNAL_ERROR),
                           static_cast<nvat_rc_t>(NVAT_RC_BAD_ARGUMENT)}) {
        CollateralStore store;
        store.forced_rc = code;
        Verifier verifier;
        const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
        Outcome outcome = verify_ex(verifier, cmw, options->get());
        ASSERT_EQ(outcome.rc, NVAT_RC_OK) << code;
        EXPECT_EQ(status_of(outcome.ear), "contraindicated") << code;
        EXPECT_EQ(cert_chain(outcome.ear)[kBromIndex]["ocsp_crl_status"], "error") << code;
        json rims = rim_results(outcome.ear);
        for (json rim : rims) {
            EXPECT_EQ(rim["fetched"], false) << code;
        }
    }
    // OK without a buffer is a contract violation, handled as a failed lookup.
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    store.return_ok_without_buffer = true;
    Verifier verifier;
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, cmw, options->get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
}

// ---------------------------------------------------------------------------------
// (c) Missing CoRIM.

TEST(CApiCollateralCbTest, MissingCorimIsContraindicatedAndNotFetched) {
    CollateralStore store;
    load_real_good_ocsp(store);
    store.corims[kVbiosRimId] = load_bytes(kRubinVbiosCorimPath);  // driver CoRIM absent
    Verifier verifier;
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    json rims = submod(outcome.ear)["ear_verifier_claims"]["ear_nvidia_rims"];
    ASSERT_EQ(rims.size(), 2U);
    EXPECT_EQ(rims[0]["fetched"], true);
    EXPECT_EQ(rims[1]["fetched"], false);
    EXPECT_EQ(rims[1]["locator"], kDriverUrl);
    EXPECT_EQ(rims[1]["error"]["code"], NVAT_RC_RIM_NOT_FOUND);
    // The error is also surfaced in the submod's error details.
    EXPECT_TRUE(submod(outcome.ear).contains("ear_nvidia_error_details"));
}

// ---------------------------------------------------------------------------------
// (d) Revoked.

// NVIDIA's real certificates cannot be revoked; a REVOKED response signed by a test responder
// is not trusted by NVIDIA's roots. libnvat reports the status it read but flags the response
// as not valid, and the appraisal is contraindicated.
TEST(CApiCollateralCbTest, RevokedResponseFromTestResponderIsReportedButNotTrusted) {
    CollateralStore store;
    load_rubin_corims(store);
    for (const char *key : {kOcspKeyBrom, kOcspKeyIca, kOcspKeyIdentity}) {
        store.ocsp[key] = load_bytes(std::string(kRubinRevokedOcspDir) + "/" + key + ".der");
    }
    Verifier verifier;
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(outcome.ear["ear_status"], "contraindicated");
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    json chain = cert_chain(outcome.ear);
    for (size_t index : {kIdentityIndex, kIcaIndex, kBromIndex}) {
        json cert = chain[index];
        EXPECT_EQ(cert["ocsp_crl_status"], "revoked") << index;
        EXPECT_EQ(cert["ocsp_response_status"], false) << index;  // signer not trusted
        EXPECT_EQ(cert["cert_check_status"], "revoked") << index;
        EXPECT_EQ(cert["revocation_reason"], "keyCompromise") << index;
        EXPECT_TRUE(cert.contains("ocsp_response_revoked_at")) << index;
    }
    EXPECT_EQ(evidence_claims(outcome.ear)["signature_verified"], false);
}

class TestCaScenario {
  public:
    TestCaScenario() {
        const json manifest = json::parse(load_text(std::string(kTestCaDir) + "/manifest.json"));
        leaf_key = manifest["leaf_key"].get<std::string>();
        ica_key = manifest["ica_key"].get<std::string>();
        this_update = manifest["this_update_epoch"].get<int64_t>();
        next_update = manifest["next_update_epoch"].get<int64_t>();
        root_pem = load_text(std::string(kTestCaDir) + "/root.pem");
        chain_pem = load_text(std::string(kTestCaDir) + "/chain.pem");
    }

    // The golden Rubin item with its certificate chain swapped for the test chain. The SPDM
    // signature will not verify against the test leaf (so the verdict is contraindicated) but
    // the chain's OCSP claims are collected before that, which is what these tests inspect.
    std::string cmw() const {
        json root = json::parse(read_rubin_cmw());
        root["gpu_0"]["certificate"][1] =
            base64url(Bytes(chain_pem.begin(), chain_pem.end()));
        return root.dump();
    }

    void load_responses(CollateralStore &store, const char *set) const {
        for (const std::string &key : {leaf_key, ica_key}) {
            store.ocsp[key] = load_bytes(std::string(kTestCaDir) + "/" + set + "/" + key + ".der");
        }
    }

    void trust_test_root(const Verifier &verifier) const {
        const char *roots[] = {root_pem.c_str()};
        ASSERT_EQ(nvat_local_corim_verifier_set_device_identity_roots(verifier.get(), roots, 1),
                  NVAT_RC_OK);
    }

    std::string leaf_key, ica_key, root_pem, chain_pem;
    int64_t this_update = 0, next_update = 0;
};

// Real OpenSSL OCSP_basic_verify accepts a delegated responder issued by the right CA ...
TEST(CApiCollateralCbTest, TestCaGoodResponsesAreVerifiedByOpenSsl) {
    const TestCaScenario scenario;
    CollateralStore store;
    load_rubin_corims(store);
    scenario.load_responses(store, "good");
    Verifier verifier;
    scenario.trust_test_root(verifier);
    const CallOptions options(&store, false, true, scenario.this_update + 300);
    Outcome outcome = verify_ex(verifier, scenario.cmw(), options.get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    json chain = cert_chain(outcome.ear);
    ASSERT_EQ(chain.size(), 3U);  // root, ICA, leaf
    EXPECT_EQ(chain[0]["ocsp_crl_status"], "not_checked");
    for (size_t index : {size_t{1}, size_t{2}}) {
        EXPECT_EQ(chain[index]["ocsp_crl_status"], "good") << index;
        EXPECT_EQ(chain[index]["ocsp_response_status"], true) << index;
        EXPECT_EQ(chain[index]["cert_check_status"], "valid") << index;
        EXPECT_EQ(chain[index]["ocsp_crl_response_expired"], false) << index;
    }
    EXPECT_EQ(store.requested_keys(NVAT_COLLATERAL_KIND_OCSP_RESPONSE),
              (std::multiset<std::string>{scenario.ica_key, scenario.leaf_key}));
}

// ... and a REVOKED(keyCompromise) response from a trusted responder is a trusted "revoked".
TEST(CApiCollateralCbTest, TestCaRevokedLeafIsRevokedByATrustedResponder) {
    const TestCaScenario scenario;
    CollateralStore store;
    load_rubin_corims(store);
    scenario.load_responses(store, "revoked");
    Verifier verifier;
    scenario.trust_test_root(verifier);
    const CallOptions options(&store, false, true, scenario.this_update + 300);
    Outcome outcome = verify_ex(verifier, scenario.cmw(), options.get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    json chain = cert_chain(outcome.ear);
    ASSERT_EQ(chain.size(), 3U);
    EXPECT_EQ(chain[1]["ocsp_crl_status"], "good");  // the ICA
    json leaf = chain[2];
    EXPECT_EQ(leaf["ocsp_crl_status"], "revoked");
    EXPECT_EQ(leaf["ocsp_response_status"], true);  // the response itself is authentic
    EXPECT_EQ(leaf["cert_check_status"], "revoked");
    EXPECT_EQ(leaf["revocation_reason"], "keyCompromise");
    EXPECT_EQ(leaf["ocsp_response_revoked_at"], "2025-12-31T23:00:00Z");
    EXPECT_EQ(evidence_claims(outcome.ear)["signature_verified"], false);
}

// The same responses against the default (NVIDIA) root: the chain does not anchor.
TEST(CApiCollateralCbTest, TestCaChainDoesNotAnchorToTheNvidiaRoot) {
    const TestCaScenario scenario;
    CollateralStore store;
    load_rubin_corims(store);
    scenario.load_responses(store, "good");
    Verifier verifier;
    const CallOptions options(&store, false, true, scenario.this_update + 300);
    Outcome outcome = verify_ex(verifier, scenario.cmw(), options.get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    EXPECT_TRUE(store.requested_keys(NVAT_COLLATERAL_KIND_OCSP_RESPONSE).empty());
}

// The responder chain is validated at the pinned time: a responder certificate is valid
// 2020..2099, so a pinned time outside that window must fail OCSP_basic_verify.
TEST(CApiCollateralCbTest, ResponderChainIsValidatedAtThePinnedVerificationTime) {
    const TestCaScenario scenario;
    CollateralStore store;
    load_rubin_corims(store);
    scenario.load_responses(store, "good");
    Verifier verifier;
    scenario.trust_test_root(verifier);
    const int64_t before_pki_existed = 1262304000 - 86400 * 365;  // 2008
    const CallOptions options(&store, false, /*enforce_next_update=*/false, before_pki_existed);
    Outcome outcome = verify_ex(verifier, scenario.cmw(), options.get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    for (size_t index : {size_t{1}, size_t{2}}) {
        EXPECT_EQ(cert_chain(outcome.ear)[index]["ocsp_response_status"], false) << index;
    }
}

// ---------------------------------------------------------------------------------
// (e) Expiry of the cached response, relative to the pinned verification time.

TEST(CApiCollateralCbTest, ExpiredOcspIsContraindicatedWhenNextUpdateIsEnforced) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    const RealOcspWindow window = real_ocsp_window();
    Verifier verifier;
    const auto options = offline_options(&store, window.latest_next_update + 3600, true);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    for (size_t index : {kIdentityIndex, kIcaIndex, kBromIndex}) {
        json cert = cert_chain(outcome.ear)[index];
        EXPECT_EQ(cert["ocsp_crl_status"], "good") << index;
        EXPECT_EQ(cert["ocsp_response_status"], true) << index;
        EXPECT_EQ(cert["ocsp_crl_response_expired"], true) << index;
    }
    EXPECT_EQ(evidence_claims(outcome.ear)["signature_verified"], false);
}

TEST(CApiCollateralCbTest, ExpiredOcspIsReportedButAcceptedWhenNextUpdateIsNotEnforced) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    const RealOcspWindow window = real_ocsp_window();
    Verifier verifier;
    const auto options = offline_options(&store, window.latest_next_update + 3600, false);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "affirming");
    for (size_t index : {kIdentityIndex, kIcaIndex, kBromIndex}) {
        EXPECT_EQ(cert_chain(outcome.ear)[index]["ocsp_crl_response_expired"], true) << index;
        EXPECT_EQ(cert_chain(outcome.ear)[index]["ocsp_crl_status"], "good") << index;
    }
}

// The boundary: one second before the earliest nextUpdate every response is still fresh.
TEST(CApiCollateralCbTest, ResponsesAreFreshUpToTheirNextUpdate) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    const RealOcspWindow window = real_ocsp_window();
    Verifier verifier;
    const auto options = offline_options(&store, window.earliest_next_update - 1, true);
    Outcome outcome = verify_ex(verifier, read_rubin_cmw(), options->get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "affirming");
}

// ---------------------------------------------------------------------------------
// (f) Tampered evidence, (g) multi-GPU.

TEST(CApiCollateralCbTest, TamperedEvidenceIsContraindicated) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    json root = json::parse(read_rubin_cmw());
    Bytes evidence;
    ASSERT_EQ(nvattestation::decode_base64url(root["gpu_0"]["evidence"][1].get<std::string>(),
                                              evidence),
              Error::Ok);
    ASSERT_FALSE(evidence.empty());
    evidence.back() ^= 0xFF;
    root["gpu_0"]["evidence"][1] = base64url(evidence);

    Verifier verifier;
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, root.dump(), options->get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(outcome.ear["ear_status"], "contraindicated");
    EXPECT_EQ(status_of(outcome.ear), "contraindicated");
    EXPECT_EQ(evidence_claims(outcome.ear)["signature_verified"], false);
}

TEST(CApiCollateralCbTest, MultiGpuCmwAppraisesEveryItemOffline) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    json root = json::parse(read_rubin_cmw());
    root["gpu_1"] = root["gpu_0"];

    Verifier verifier(Verifier::Mode::kDecoyNetworkConfiguration);
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, root.dump(), options->get());

    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    ASSERT_EQ(outcome.ear["submods"].size(), 2U);
    EXPECT_EQ(status_of(outcome.ear, "gpu_0"), "affirming");
    EXPECT_EQ(status_of(outcome.ear, "gpu_1"), "affirming");
    EXPECT_EQ(outcome.ear["ear_status"], "affirming");
    // Each item asks for its own CoRIMs and OCSP responses.
    EXPECT_EQ(store.requested_keys(NVAT_COLLATERAL_KIND_CORIM).count(kVbiosRimId), 2U);
    EXPECT_EQ(store.requested_keys(NVAT_COLLATERAL_KIND_OCSP_RESPONSE).count(kOcspKeyBrom), 2U);
}

TEST(CApiCollateralCbTest, OneBadGpuDoesNotSpoilTheOthers) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);
    json root = json::parse(read_rubin_cmw());
    root["gpu_1"] = root["gpu_0"];
    Bytes evidence;
    ASSERT_EQ(nvattestation::decode_base64url(root["gpu_1"]["evidence"][1].get<std::string>(),
                                              evidence),
              Error::Ok);
    evidence.back() ^= 0xFF;
    root["gpu_1"]["evidence"][1] = base64url(evidence);

    Verifier verifier;
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, root.dump(), options->get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear, "gpu_0"), "affirming");
    EXPECT_EQ(status_of(outcome.ear, "gpu_1"), "contraindicated");
    EXPECT_EQ(outcome.ear["ear_status"], "contraindicated");
}

// ---------------------------------------------------------------------------------
// (h) Legacy behavior is unchanged.

std::string stripped_volatile_fields(json ear) {
    for (const char *name : {"iat", "nbf", "exp", "jti"}) {
        ear.erase(name);
    }
    return ear.dump();
}

TEST(CApiCollateralCbTest, VerifyCmwExWithoutOptionsMatchesLegacyVerifyCmw) {
    // CoRIMs through file:// rewrites, no revocation: the legacy path end to end.
    char vbios_path[PATH_MAX];
    char driver_path[PATH_MAX];
    ASSERT_NE(::realpath(kRubinVbiosCorimPath, vbios_path), nullptr);
    ASSERT_NE(::realpath(kRubinDriverCorimPath, driver_path), nullptr);
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_corim_store_add_url_rewrite(store, kVbiosUrl,
                                               (std::string("file://") + vbios_path).c_str()),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_corim_store_add_url_rewrite(store, kDriverUrl,
                                               (std::string("file://") + driver_path).c_str()),
              NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_rim_signature(verifier, false), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false), NVAT_RC_OK);

    const std::string cmw = read_rubin_cmw();
    const auto *data = reinterpret_cast<const uint8_t *>(cmw.data());
    nvat_str_t legacy = nullptr;
    nvat_str_t extended = nullptr;
    nvat_str_t extended_default_options = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_verify_cmw(verifier, data, cmw.size(),
                                                   NVAT_CMW_FORMAT_JSON, nullptr, nullptr,
                                                   &legacy),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_verify_cmw_ex(verifier, data, cmw.size(),
                                                      NVAT_CMW_FORMAT_JSON, nullptr, nullptr,
                                                      nullptr, &extended),
              NVAT_RC_OK);
    // Options with no callback: the legacy file:// path is used; revocation is off.
    CallOptions plain(nullptr, true, true, 0);
    ASSERT_EQ(nvat_local_corim_verifier_verify_cmw_ex(verifier, data, cmw.size(),
                                                      NVAT_CMW_FORMAT_JSON, plain.get(), nullptr,
                                                      nullptr, &extended_default_options),
              NVAT_RC_OK);

    auto text = [](nvat_str_t value) {
        char *chars = nullptr;
        size_t length = 0;
        EXPECT_EQ(nvat_str_get_data(value, &chars), NVAT_RC_OK);
        EXPECT_EQ(nvat_str_length(value, &length), NVAT_RC_OK);
        return json::parse(std::string(chars, length));
    };
    const json legacy_json = text(legacy);
    EXPECT_EQ(legacy_json["ear_status"], "affirming");
    EXPECT_EQ(stripped_volatile_fields(legacy_json), stripped_volatile_fields(text(extended)));
    EXPECT_EQ(stripped_volatile_fields(legacy_json),
              stripped_volatile_fields(text(extended_default_options)));

    nvat_str_free(&legacy);
    nvat_str_free(&extended);
    nvat_str_free(&extended_default_options);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

// ---------------------------------------------------------------------------------
// MAA tunnels x-ms-runtime in an application/*+json hints record.

TEST(CApiCollateralCbTest, VendorJsonHintsFlowThroughAndDigestCoversTheExactSubmittedBytes) {
    CollateralStore store;
    load_rubin_corims(store);
    load_real_good_ocsp(store);

    const std::string runtime_blob = R"({"x-ms-runtime":{"jwk":{"kty":"RSA"}}})";
    json root = json::parse(read_rubin_cmw());
    root["gpu_0"]["hints"] = json::array(
        {"application/vnd.microsoft.maa.x-ms-runtime+json",
         base64url(Bytes(runtime_blob.begin(), runtime_blob.end()))});
    // Pretty-printed with a trailing newline: the digest must cover these exact bytes, not a
    // canonical re-serialization.
    const std::string submitted = root.dump(3) + "\n";

    Verifier verifier;
    const auto options = offline_options(&store, real_ocsp_window().latest_this_update + 300);
    Outcome outcome = verify_ex(verifier, submitted, options->get());
    ASSERT_EQ(outcome.rc, NVAT_RC_OK);
    EXPECT_EQ(status_of(outcome.ear), "affirming");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    ASSERT_EQ(EVP_Digest(submitted.data(), submitted.size(), digest, &digest_len, EVP_sha256(),
                         nullptr),
              1);
    const std::string expected = base64url(Bytes(digest, digest + digest_len));
    json digests = outcome.ear["ear_nvidia_inputs"]["digests"];
    ASSERT_EQ(digests.size(), 1U);
    EXPECT_EQ(digests[0]["alg"], "sha-256");
    EXPECT_EQ(digests[0]["val"], expected);
}

// ---------------------------------------------------------------------------------
// (i) Thread safety: one shared verifier, concurrent calls with distinct callback contexts.

TEST(CApiCollateralCbTest, SharedVerifierServesConcurrentCallsWithDistinctCallbackContexts) {
    constexpr int kThreads = 8;
    constexpr int kCallsPerThread = 5;
    const std::string cmw = read_rubin_cmw();
    const time_t pinned = real_ocsp_window().latest_this_update + 300;
    const Bytes vbios = load_bytes(kRubinVbiosCorimPath);
    const Bytes driver = load_bytes(kRubinDriverCorimPath);
    std::map<std::string, Bytes> good_ocsp;
    for (const char *key : {kOcspKeyBrom, kOcspKeyIca, kOcspKeyIdentity}) {
        good_ocsp[key] = load_bytes(std::string(kRubinOcspDir) + "/" + key + ".der");
    }

    Verifier verifier;  // shared by every thread
    struct ThreadResult {
        std::vector<nvat_rc_t> rcs;
        std::vector<std::string> statuses;
        std::vector<std::string> bromOcspStatuses;
        size_t corim_requests = 0;
        size_t ocsp_requests = 0;
    };
    std::vector<ThreadResult> results(kThreads);
    std::vector<std::unique_ptr<CollateralStore>> stores;
    for (int t = 0; t < kThreads; ++t) {
        stores.emplace_back(new CollateralStore());
        stores[t]->corims[kVbiosRimId] = vbios;
        stores[t]->corims[kDriverRimId] = driver;
        if (t % 2 == 0) {
            stores[t]->ocsp = good_ocsp;  // odd threads have no OCSP at all
        }
    }

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            for (int call = 0; call < kCallsPerThread; ++call) {
                CallOptions options(stores[t].get(), false, true, static_cast<int64_t>(pinned));
                Outcome outcome = verify_ex(verifier, cmw, options.get());
                results[t].rcs.push_back(outcome.rc);
                results[t].statuses.push_back(status_of(outcome.ear));
                json chain = cert_chain(outcome.ear);
                results[t].bromOcspStatuses.push_back(
                    chain.size() > kBromIndex && chain[kBromIndex].contains("ocsp_crl_status")
                        ? chain[kBromIndex]["ocsp_crl_status"].get<std::string>()
                        : "<none>");
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    for (int t = 0; t < kThreads; ++t) {
        const bool has_ocsp = t % 2 == 0;
        for (int call = 0; call < kCallsPerThread; ++call) {
            EXPECT_EQ(results[t].rcs[call], NVAT_RC_OK) << "thread " << t;
            EXPECT_EQ(results[t].statuses[call], has_ocsp ? "affirming" : "contraindicated")
                << "thread " << t;
            EXPECT_EQ(results[t].bromOcspStatuses[call], has_ocsp ? "good" : "error")
                << "thread " << t;
        }
        // A context only ever sees its own requests: 2 CoRIMs per call, and per call either
        // 3 OCSP lookups (all present) or 1 (the first failure ends the walk).
        const size_t corims = stores[t]->requested_keys(NVAT_COLLATERAL_KIND_CORIM).size();
        const size_t ocsp = stores[t]->requested_keys(NVAT_COLLATERAL_KIND_OCSP_RESPONSE).size();
        EXPECT_EQ(corims, 2U * kCallsPerThread) << "thread " << t;
        EXPECT_EQ(ocsp, (has_ocsp ? 3U : 1U) * kCallsPerThread) << "thread " << t;
    }
}

}  // namespace
