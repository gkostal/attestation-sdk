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

// C-API coverage for the V2 CoRIM verifier surface (CMW collection, CoRIM
// store, local CoRIM verifier, AIA OCSP client). The hermetic verify paths
// mirror test_local_corim_verifier.cpp but drive the handles through nvat.h.

#include <climits>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>

#include "jwt-cpp/traits/nlohmann-json/traits.h"

#include "gtest/gtest.h"

#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nvat_private.hpp"
#include "nv_attestation/utils.h"
#include "nvat.h"
#include "test_utils.h"

using nvattestation::readFileIntoString;

constexpr const char *kBlackwellCmwPath =
    "testdata/sample_attestation_data/blackwell_evidence.cmw.json";
constexpr const char *kRubinCmwPath =
    "testdata/sample_attestation_data/rubin_evidence.cmw.json";
constexpr const char *kRubinVbiosCorimPath =
    "testdata/sample_rims/corim/rubin_vbios_example.cbor";
constexpr const char *kRubinDriverCorimPath =
    "testdata/sample_rims/corim/rubin_driver_example.cbor";
constexpr const char *kGpuEvidenceJsonPath = "testdata/evidence_hopper_590_12.json";

constexpr const char *kRubinVbiosUrl =
    "https://rim.attestation.nvidia.com/v1/rim/"
    "GR100_081D_9900230000";
constexpr const char *kRubinDriverUrl =
    "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GR100_620.54";

static std::string file_url(const char *relative_path) {
    char resolved[PATH_MAX];
    if (::realpath(relative_path, resolved) == nullptr) {
        return "";
    }
    return "file://" + std::string(resolved);
}

static nvat_str_t verify_cmw(nvat_local_corim_verifier_t verifier,
                             const std::string &cmw, nvat_rc_t &out_rc) {
    nvat_str_t result = nullptr;
    out_rc = nvat_local_corim_verifier_verify_cmw(
        verifier, reinterpret_cast<const uint8_t *>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, nullptr, nullptr, &result);
    return result;
}

// Parses the verifier's serialized result and returns it; empty object on any
// failure so callers can assert structure without crashing.
static nlohmann::json result_json(nvat_str_t result) {
    if (result == nullptr) {
        return nlohmann::json::object();
    }
    char *data = nullptr;
    if (nvat_str_get_data(result, &data) != NVAT_RC_OK || data == nullptr) {
        return nlohmann::json::object();
    }
    return nlohmann::json::parse(data, nullptr, /*allow_exceptions=*/false);
}

TEST(CApiCorimVerifierTest, VerifyCmwBlackwellNoTocSucceeds) {
    std::string cmw;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw),
              nvattestation::Error::Ok);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);

    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    nvat_rc_t rc = NVAT_RC_OK;
    nvat_str_t result = verify_cmw(verifier, cmw, rc);
    EXPECT_EQ(rc, NVAT_RC_OK);
    nlohmann::json parsed = result_json(result);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.contains("submods"));
    EXPECT_TRUE(parsed.contains("ear_status"));

    nvat_str_free(&result);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwRubinTocMatchesRewrittenRims) {
    std::string cmw;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw), nvattestation::Error::Ok);
    const std::string vbios_url = file_url(kRubinVbiosCorimPath);
    const std::string driver_url = file_url(kRubinDriverCorimPath);
    ASSERT_FALSE(vbios_url.empty());
    ASSERT_FALSE(driver_url.empty());

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    ASSERT_EQ(
        nvat_corim_store_add_url_rewrite(store, kRubinVbiosUrl, vbios_url.c_str()),
        NVAT_RC_OK);
    ASSERT_EQ(nvat_corim_store_add_url_rewrite(store, kRubinDriverUrl,
                                               driver_url.c_str()),
              NVAT_RC_OK);

    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    ASSERT_EQ(
        nvat_local_corim_verifier_set_verify_rim_signature(verifier, false),
        NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    nvat_rc_t rc = NVAT_RC_OK;
    nvat_str_t result = verify_cmw(verifier, cmw, rc);
    EXPECT_EQ(rc, NVAT_RC_OK);
    nlohmann::json parsed = result_json(result);
    EXPECT_EQ(parsed.value("ear_status", std::string{}), "affirming");
    ASSERT_TRUE(parsed.contains("submods"));
    ASSERT_EQ(parsed["submods"].size(), 1u);
    EXPECT_EQ(parsed["submods"]["gpu_0"]["ear_status"], "affirming");

    nvat_str_free(&result);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, CmwCollectionFromGpuEvidenceRoundTrips) {
    nvat_gpu_evidence_source_t source = nullptr;
    ASSERT_EQ(nvat_gpu_evidence_source_from_json_file(&source,
                                                      kGpuEvidenceJsonPath),
              NVAT_RC_OK);

    // The JSON evidence source validates against the nonce the fixture was
    // generated with.
    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(
                  &nonce,
                  "e97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576"),
              NVAT_RC_OK);

    nvat_gpu_evidence_t *evidences = nullptr;
    size_t num_evidences = 0;
    ASSERT_EQ(nvat_gpu_evidence_collect(source, nonce, &evidences,
                                        &num_evidences),
              NVAT_RC_OK);
    ASSERT_GT(num_evidences, 0U);

    nvat_cmw_collection_t cmw = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_gpu_evidence(&cmw, evidences,
                                                           num_evidences, nonce),
              NVAT_RC_OK);

    nvat_str_t serialized = nullptr;
    ASSERT_EQ(
        nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_JSON, &serialized),
        NVAT_RC_OK);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(serialized, &data), NVAT_RC_OK);
    nlohmann::json parsed =
        nlohmann::json::parse(data, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.is_object());
    EXPECT_TRUE(parsed.contains("__cmwc_t"));

    nvat_str_t cbor = nullptr;
    EXPECT_EQ(
        nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_CBOR, &cbor),
        NVAT_RC_FEATURE_NOT_ENABLED);

    nvat_str_free(&serialized);
    nvat_cmw_collection_free(&cmw);
    nvat_gpu_evidence_array_free(&evidences, num_evidences);
    nvat_nonce_free(&nonce);
    nvat_gpu_evidence_source_free(&source);
}

TEST(CApiCorimVerifierTest, OcspClientCreateAiaAcceptsRewrites) {
    const char *patterns[] = {"^http://ocsp\\.example\\.com"};
    const char *replacements[] = {"http://ocsp.internal.example.com"};
    nvat_ocsp_client_t client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_aia(&client, nullptr, nullptr, nullptr,
                                          patterns, replacements, 1, nullptr),
              NVAT_RC_OK);
    ASSERT_NE(client, nullptr);
    nvat_ocsp_client_free(&client);
}

TEST(CApiCorimVerifierTest, OcspClientCreateAiaRejectsBadArgs) {
    nvat_ocsp_client_t client = nullptr;
    EXPECT_EQ(nvat_ocsp_client_create_aia(nullptr, nullptr, nullptr, nullptr,
                                          nullptr, nullptr, 0, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    // num_rewrites > 0 with null arrays.
    EXPECT_EQ(nvat_ocsp_client_create_aia(&client, nullptr, nullptr, nullptr,
                                          nullptr, nullptr, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    // A null entry inside otherwise-valid arrays.
    const char *patterns[] = {nullptr};
    const char *replacements[] = {"replacement"};
    EXPECT_EQ(nvat_ocsp_client_create_aia(&client, nullptr, nullptr, nullptr,
                                          patterns, replacements, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest, OcspClientOptionsValidateAndFree) {
    EXPECT_EQ(nvat_ocsp_client_options_create_default(nullptr),
              NVAT_RC_BAD_ARGUMENT);

    nvat_ocsp_client_options_t options = nullptr;
    ASSERT_EQ(nvat_ocsp_client_options_create_default(&options), NVAT_RC_OK);
    ASSERT_NE(options, nullptr);
    EXPECT_EQ(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                  nullptr, NVAT_OCSP_CERT_ID_HASH_SHA256),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                  options, NVAT_OCSP_CERT_ID_HASH_SHA1),
              NVAT_RC_OK);
    // Not a supported hash algorithm. Keep the value within the enum's valid
    // range (0..3); loading a wider value trips UBSan before validation.
    EXPECT_EQ(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                  options,
                  static_cast<nvat_ocsp_cert_id_hash_algorithm_t>(3)),
              NVAT_RC_BAD_ARGUMENT);

    nvat_ocsp_client_options_free(&options);
    EXPECT_EQ(options, nullptr);
}

TEST(CApiCorimVerifierTest, OcspCertIdHashAlgorithmParsesNames) {
    nvat_ocsp_cert_id_hash_algorithm_t algorithm{};
    EXPECT_EQ(nvat_ocsp_cert_id_hash_algorithm_from_name("SHA384", &algorithm),
              NVAT_RC_OK);
    EXPECT_EQ(algorithm, NVAT_OCSP_CERT_ID_HASH_SHA384);
    EXPECT_EQ(nvat_ocsp_cert_id_hash_algorithm_from_name("sha-512", &algorithm),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_ocsp_cert_id_hash_algorithm_from_name(nullptr, &algorithm),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_ocsp_cert_id_hash_algorithm_from_name("sha-256", nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest,
     OcspClientExplicitNullOptionsIgnoreHashEnvironment) {
    ScopedEnvironmentVariable environment("NVAT_OCSP_CERT_ID_HASH_ALGORITHM");
    environment.set("invalid");

    nvat_ocsp_client_t default_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_default_with_options(
                  &default_client, nullptr, nullptr, nullptr, nullptr),
              NVAT_RC_OK);
    ASSERT_NE(default_client, nullptr);

    nvat_ocsp_client_t aia_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_aia(
                  &aia_client, nullptr, nullptr, nullptr, nullptr, nullptr, 0,
                  nullptr),
              NVAT_RC_OK);
    ASSERT_NE(aia_client, nullptr);

    nvat_ocsp_client_free(&aia_client);
    nvat_ocsp_client_free(&default_client);
}

TEST(CApiCorimVerifierTest,
     OcspClientConstructorsCopyOptions) {
    nvat_ocsp_client_options_t options = nullptr;
    ASSERT_EQ(nvat_ocsp_client_options_create_default(&options), NVAT_RC_OK);
    ASSERT_EQ(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                  options, NVAT_OCSP_CERT_ID_HASH_SHA384),
              NVAT_RC_OK);

    nvat_ocsp_client_t default_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_default_with_options(
                  &default_client, nullptr, nullptr, nullptr, options),
              NVAT_RC_OK);
    nvat_ocsp_client_t aia_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_aia(
                  &aia_client, nullptr, nullptr, nullptr, nullptr, nullptr, 0,
                  options),
              NVAT_RC_OK);
    nvat_ocsp_client_options_free(&options);

    auto default_cpp = std::static_pointer_cast<nvattestation::NvHttpOcspClient>(
        *nvat_ocsp_client_to_cpp(default_client));
    auto aia_cpp = std::static_pointer_cast<nvattestation::NvHttpOcspClient>(
        *nvat_ocsp_client_to_cpp(aia_client));
    EXPECT_EQ(default_cpp->cert_id_hash_algorithm(),
              nvattestation::OcspCertIdHashAlgorithm::Sha384);
    EXPECT_EQ(aia_cpp->cert_id_hash_algorithm(),
              nvattestation::OcspCertIdHashAlgorithm::Sha384);

    nvat_ocsp_client_free(&aia_client);
    nvat_ocsp_client_free(&default_client);
}

TEST(CApiCorimVerifierTest, CorimStoreRejectsBadArgs) {
    EXPECT_EQ(nvat_corim_store_create(nullptr, nullptr, nullptr),
              NVAT_RC_BAD_ARGUMENT);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    EXPECT_EQ(nvat_corim_store_add_url_rewrite(store, nullptr, "x"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_add_url_rewrite(store, "x", nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_add_url_rewrite(nullptr, "x", "y"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_add_allowed_url_prefix(store, "https://x/"),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_corim_store_add_allowed_url_prefix(store, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_add_allowed_url_prefix(nullptr, "https://x/"),
              NVAT_RC_BAD_ARGUMENT);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifierCreateAndVerifyRejectBadArgs) {
    EXPECT_EQ(nvat_local_corim_verifier_create(nullptr, nullptr, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    nvat_local_corim_verifier_t verifier = nullptr;
    EXPECT_EQ(nvat_local_corim_verifier_create(&verifier, nullptr, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    nvat_corim_store_t null_store = nullptr;
    EXPECT_EQ(nvat_local_corim_verifier_create(&verifier, &null_store, nullptr),
              NVAT_RC_BAD_ARGUMENT);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    // create() takes ownership and NULLs the store handle.
    EXPECT_EQ(store, nullptr);

    nvat_str_t result = nullptr;
    const uint8_t one_byte = 0;
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw(nullptr, &one_byte, 1,
                                                   NVAT_CMW_FORMAT_JSON,
                                                   nullptr, nullptr, &result),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw(verifier, nullptr, 0,
                                                   NVAT_CMW_FORMAT_JSON,
                                                   nullptr, nullptr, &result),
              NVAT_RC_BAD_ARGUMENT);

    const std::string garbage = "not json at all";
    nvat_rc_t rc = NVAT_RC_OK;
    nvat_str_t parse_result = verify_cmw(verifier, garbage, rc);
    EXPECT_NE(rc, NVAT_RC_OK);
    nvat_str_free(&parse_result);

    const uint8_t byte = 0;
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw(verifier, &byte, 1,
                                                   NVAT_CMW_FORMAT_CBOR,
                                                   nullptr, nullptr, &result),
              NVAT_RC_FEATURE_NOT_ENABLED);
    nvat_str_free(&result);

    EXPECT_EQ(
        nvat_local_corim_verifier_set_verify_revocation(nullptr, true),
        NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(
        nvat_local_corim_verifier_set_verify_rim_signature(nullptr, true),
        NVAT_RC_BAD_ARGUMENT);
    const uint8_t coev = 0xa0;
    EXPECT_EQ(nvat_local_corim_verifier_set_backup_spdm_coev(nullptr, &coev, 1),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_add_backup_rim_locator(nullptr,
                                                               "https://x/"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(
        nvat_local_corim_verifier_add_backup_rim_locator(verifier, nullptr),
        NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_add_backup_rim_locator(verifier, ""),
              NVAT_RC_BAD_ARGUMENT);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, GpuEvidenceSourceFromJsonFileRejectsMissingFile) {
    nvat_gpu_evidence_source_t source = nullptr;
    EXPECT_NE(nvat_gpu_evidence_source_from_json_file(
                  &source, "testdata/does_not_exist_evidence.json"),
              NVAT_RC_OK);
    EXPECT_EQ(source, nullptr);
    EXPECT_EQ(nvat_gpu_evidence_source_from_json_file(nullptr, "x.json"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_gpu_evidence_source_from_json_file(&source, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest, CmwCollectionCreateRejectsBadArgs) {
    nvat_gpu_evidence_t null_array[] = {nullptr};

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_create(&nonce, 32), NVAT_RC_OK);

    nvat_cmw_collection_t cmw = nullptr;
    EXPECT_EQ(nvat_cmw_collection_create_from_gpu_evidence(nullptr, null_array,
                                                           1, nonce),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_gpu_evidence(&cmw, nullptr, 0,
                                                           nonce),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_gpu_evidence(&cmw, null_array, 1,
                                                           nullptr),
              NVAT_RC_BAD_ARGUMENT);
    // Non-null array carrying a null element.
    EXPECT_EQ(nvat_cmw_collection_create_from_gpu_evidence(&cmw, null_array, 1,
                                                           nonce),
              NVAT_RC_BAD_ARGUMENT);

    nvat_nonce_free(&nonce);
}

TEST(CApiCorimVerifierTest, CmwCollectionSerializeRejectsBadArgs) {
    nvat_str_t out = nullptr;
    EXPECT_EQ(nvat_cmw_collection_serialize(nullptr, NVAT_CMW_FORMAT_JSON, &out),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest, CmwCollectionFromSpdmTranscriptRoundTrips) {
    const std::string transcript = "raw-spdm-transcript-bytes";
    const std::string cert_pem =
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const auto *transcript_bytes =
        reinterpret_cast<const uint8_t *>(transcript.data());
    const auto *cert_bytes = reinterpret_cast<const uint8_t *>(cert_pem.data());

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_create(&nonce, 32), NVAT_RC_OK);

    // With a nonce.
    nvat_cmw_collection_t cmw = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw, "device_0", transcript_bytes, transcript.size(),
                  cert_bytes, cert_pem.size(), nonce),
              NVAT_RC_OK);

    nvat_str_t serialized = nullptr;
    ASSERT_EQ(
        nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_JSON, &serialized),
        NVAT_RC_OK);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(serialized, &data), NVAT_RC_OK);
    nlohmann::json parsed =
        nlohmann::json::parse(data, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.contains("__cmwc_t"));

    // A non-null collection with a null output pointer is rejected.
    EXPECT_EQ(nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_JSON, nullptr),
              NVAT_RC_BAD_ARGUMENT);

    nvat_str_free(&serialized);
    nvat_cmw_collection_free(&cmw);

    // Without a nonce (optional-nonce branch).
    nvat_cmw_collection_t cmw_no_nonce = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw_no_nonce, "device_0", transcript_bytes, transcript.size(),
                  cert_bytes, cert_pem.size(), nullptr),
              NVAT_RC_OK);
    nvat_cmw_collection_free(&cmw_no_nonce);

    nvat_nonce_free(&nonce);
}

TEST(CApiCorimVerifierTest, CmwCollectionFromSpdmTranscriptRejectsBadArgs) {
    const uint8_t bytes[] = {0x01};
    nvat_cmw_collection_t cmw = nullptr;
    EXPECT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  nullptr, "d", bytes, 1, bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw, nullptr, bytes, 1, bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw, "d", nullptr, 0, bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw, "d", bytes, 1, nullptr, 0, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

static std::vector<uint8_t> read_binary_fixture(const char *path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

TEST(CApiCorimVerifierTest, CmwCollectionFromEatRoundTrips) {
    const std::vector<uint8_t> token =
        read_binary_fixture("testdata/sample_rims/eat/full_signed.cbor");
    ASSERT_FALSE(token.empty());

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_create(&nonce, 32), NVAT_RC_OK);

    nvat_cmw_collection_t cmw = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_eat(
                  &cmw, "device_0", token.data(), token.size(), nonce),
              NVAT_RC_OK);

    nvat_str_t serialized = nullptr;
    ASSERT_EQ(
        nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_JSON, &serialized),
        NVAT_RC_OK);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(serialized, &data), NVAT_RC_OK);
    nlohmann::json parsed =
        nlohmann::json::parse(data, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    ASSERT_TRUE(parsed.contains("device_0"));
    EXPECT_EQ(parsed["device_0"]["evidence"][0], "application/eat+cwt");

    nvat_str_free(&serialized);
    nvat_cmw_collection_free(&cmw);

    nvat_cmw_collection_t cmw_no_nonce = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_eat(&cmw_no_nonce, "device_0",
                                                  token.data(), token.size(),
                                                  nullptr),
              NVAT_RC_OK);
    nvat_cmw_collection_free(&cmw_no_nonce);

    nvat_nonce_free(&nonce);
}

TEST(CApiCorimVerifierTest, CmwCollectionFromEatRejectsBadArgs) {
    const uint8_t bytes[] = {0x01};
    nvat_cmw_collection_t cmw = nullptr;
    EXPECT_EQ(nvat_cmw_collection_create_from_eat(nullptr, "d", bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_eat(&cmw, nullptr, bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_eat(&cmw, "d", nullptr, 0, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_eat(&cmw, "d", bytes, 0, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest, VerifierBackupSettersAcceptInputs) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    const uint8_t coev[] = {0xa0};  // Minimal valid CBOR: empty map.
    EXPECT_EQ(nvat_local_corim_verifier_set_backup_spdm_coev(verifier, coev, 1),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_local_corim_verifier_add_backup_rim_locator(
                  verifier, "https://example.com/rim1"),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

// The algorithms select which digests of the CMW input land in
// ear_nvidia_inputs; an empty list disables the computation entirely.
TEST(CApiCorimVerifierTest, SetDefaultHashAlgorithmsAcceptsEveryAlgorithm) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    const nvat_hash_algorithm_t algs[] = {NVAT_HASH_ALGORITHM_SHA256,
                                          NVAT_HASH_ALGORITHM_SHA384,
                                          NVAT_HASH_ALGORITHM_SHA512};
    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(verifier,
                                                                    algs, 3),
              NVAT_RC_OK);
    // Empty list is the documented way to switch the digests off.
    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(verifier,
                                                                    nullptr, 0),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, SetDefaultHashAlgorithmsRejectsBadArgs) {
    const nvat_hash_algorithm_t algs[] = {NVAT_HASH_ALGORITHM_SHA256};
    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(nullptr,
                                                                    algs, 1),
              NVAT_RC_BAD_ARGUMENT);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(verifier,
                                                                    nullptr, 2),
              NVAT_RC_BAD_ARGUMENT);
    // Not an IANA Named Information registry ID the SDK maps. Must stay within
    // the enum's value range (0..15 for enumerators up to 8): loading a wider
    // value through the enum type is undefined behaviour and trips UBSan.
    const nvat_hash_algorithm_t unknown[] = {
        static_cast<nvat_hash_algorithm_t>(9)};
    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(verifier,
                                                                    unknown, 1),
              NVAT_RC_BAD_ARGUMENT);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

namespace {

struct OfflineCollateralStore {
    std::map<std::string, std::vector<uint8_t>> corims;
    std::map<std::string, std::vector<uint8_t>> ocsp_responses;
};

nvat_rc_t test_collateral_callback(void *user_data,
                                   nvat_collateral_kind_t kind,
                                   const char *lookup_key,
                                   nvat_byte_buf_t *out_collateral) {
    if (user_data == nullptr || lookup_key == nullptr || out_collateral == nullptr) {
        return NVAT_RC_BAD_ARGUMENT;
    }
    *out_collateral = nullptr;
    const auto *store = static_cast<const OfflineCollateralStore *>(user_data);
    const std::map<std::string, std::vector<uint8_t>> *map_ptr = nullptr;
    if (kind == NVAT_COLLATERAL_KIND_CORIM) {
        map_ptr = &store->corims;
    } else if (kind == NVAT_COLLATERAL_KIND_OCSP_RESPONSE) {
        map_ptr = &store->ocsp_responses;
    } else {
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto it = map_ptr->find(lookup_key);
    if (it == map_ptr->end()) {
        return NVAT_RC_COLLATERAL_NOT_FOUND;
    }
    return nvat_byte_buf_create(out_collateral, it->second.data(), it->second.size());
}

OfflineCollateralStore load_rubin_offline_store() {
    OfflineCollateralStore store;
    store.corims["GR100_081D_9900230000"] = read_binary_fixture(kRubinVbiosCorimPath);
    store.corims["NV_GPU_DRIVER_GR100_620.54"] = read_binary_fixture(kRubinDriverCorimPath);

    const char *ocsp_keys[] = {
        "65129acf8647f4285e8d07c09c5320949aacff2b8dd3917540b15d8833813f52_410a3021db2466fe7c",
        "115a377933f4e800ffcb8543a33536375173f75c66e1dd02db5f849fff113f27_44d719c02afb194c5c0bc7497c2e81bf",
        "6f0264e4bce92d49cd76d17f79e2719ea1972af859fbae04eb2516b8317a8e9e_02c2f9f328f20749cda9060e7d165256",
    };
    for (const char *key : ocsp_keys) {
        std::string path = std::string("testdata/sample_attestation_data/ocsp/") + key + ".der";
        store.ocsp_responses[key] = read_binary_fixture(path.c_str());
    }
    return store;
}

} // namespace

TEST(CApiCorimVerifierTest, VerifyCmwExOfflineCallbackCachedOcspAndVendorJsonHintsAffirming) {
    std::string cmw_str;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_str), nvattestation::Error::Ok);

    // Inject MAA vendor +json hints to confirm cmw.cpp accepts application/*+json.
    nlohmann::json cmw_json = nlohmann::json::parse(cmw_str);
    std::string runtime_payload = R"({"keys":[],"foo":"bar"})";
    std::string runtime_b64url;
    ASSERT_EQ(nvattestation::encode_base64url(
                  std::vector<uint8_t>(runtime_payload.begin(), runtime_payload.end()),
                  runtime_b64url),
              nvattestation::Error::Ok);
    cmw_json["gpu_0"]["hints"] = nlohmann::json::array({
        "application/vnd.microsoft.maa.x-ms-runtime+json",
        runtime_b64url
    });
    const std::string modified_cmw = cmw_json.dump();

    OfflineCollateralStore collateral = load_rubin_offline_store();
    ASSERT_FALSE(collateral.corims["GR100_081D_9900230000"].empty());
    ASSERT_EQ(collateral.ocsp_responses.size(), 3u);
    for (const auto &kv : collateral.ocsp_responses) {
        ASSERT_FALSE(kv.second.empty()) << "Missing OCSP fixture: " << kv.first;
    }

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_rim_signature(verifier, false), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, true), NVAT_RC_OK);

    nvat_verify_call_options_t call_opts = nullptr;
    ASSERT_EQ(nvat_verify_call_options_create(&call_opts), NVAT_RC_OK);
    ASSERT_EQ(nvat_verify_call_options_set_collateral_callback(
                  call_opts, test_collateral_callback, &collateral),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_verify_call_options_set_require_ocsp_nonce(call_opts, false), NVAT_RC_OK);
    ASSERT_EQ(nvat_verify_call_options_set_enforce_ocsp_next_update(call_opts, true), NVAT_RC_OK);
    // Inside [Nov 12 20:04:22 2026 GMT .. Nov 13 20:04:21 2026 GMT].
    ASSERT_EQ(nvat_verify_call_options_set_verification_time(call_opts, 1794516000), NVAT_RC_OK);

    nvat_str_t ear_str = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_verify_cmw_ex(
                  verifier,
                  reinterpret_cast<const uint8_t *>(modified_cmw.data()),
                  modified_cmw.size(),
                  NVAT_CMW_FORMAT_JSON,
                  call_opts,
                  nullptr,
                  nullptr,
                  &ear_str),
              NVAT_RC_OK);

    nlohmann::json ear = result_json(ear_str);
    EXPECT_EQ(ear.value("ear_status", std::string{}), "affirming");
    const auto &gpu0 = ear["submods"]["gpu_0"];
    EXPECT_EQ(gpu0.value("ear_status", std::string{}), "affirming");
    const auto &chain = gpu0["ear_verifier_claims"]["ear_nvidia_evidence"]["cert_chain"];
    ASSERT_EQ(chain.size(), 5u);
    for (size_t idx : {1u, 2u, 3u}) {
        EXPECT_EQ(chain[idx]["ocsp_crl_status"], "good");
        EXPECT_EQ(chain[idx]["ocsp_nonce_matches"], false);
        EXPECT_EQ(chain[idx]["ocsp_crl_response_expired"], false);
    }

    // Past nextUpdate with enforce_ocsp_next_update = true -> contraindicated.
    nvat_str_free(&ear_str);
    ASSERT_EQ(nvat_verify_call_options_set_verification_time(call_opts, 1794603600), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_verify_cmw_ex(
                  verifier,
                  reinterpret_cast<const uint8_t *>(modified_cmw.data()),
                  modified_cmw.size(),
                  NVAT_CMW_FORMAT_JSON,
                  call_opts,
                  nullptr,
                  nullptr,
                  &ear_str),
              NVAT_RC_OK);
    ear = result_json(ear_str);
    EXPECT_EQ(ear.value("ear_status", std::string{}), "contraindicated");
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_verifier_claims"]["ear_nvidia_evidence"]["cert_chain"][1]["ocsp_crl_response_expired"], true);

    // Disabling enforce_ocsp_next_update allows static replay past nextUpdate.
    nvat_str_free(&ear_str);
    ASSERT_EQ(nvat_verify_call_options_set_enforce_ocsp_next_update(call_opts, false), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_verify_cmw_ex(
                  verifier,
                  reinterpret_cast<const uint8_t *>(modified_cmw.data()),
                  modified_cmw.size(),
                  NVAT_CMW_FORMAT_JSON,
                  call_opts,
                  nullptr,
                  nullptr,
                  &ear_str),
              NVAT_RC_OK);
    ear = result_json(ear_str);
    EXPECT_EQ(ear.value("ear_status", std::string{}), "affirming");

    // Missing OCSP in callback -> contraindicated + ocsp_crl_status = "error".
    nvat_str_free(&ear_str);
    collateral.ocsp_responses.clear();
    ASSERT_EQ(nvat_local_corim_verifier_verify_cmw_ex(
                  verifier,
                  reinterpret_cast<const uint8_t *>(modified_cmw.data()),
                  modified_cmw.size(),
                  NVAT_CMW_FORMAT_JSON,
                  call_opts,
                  nullptr,
                  nullptr,
                  &ear_str),
              NVAT_RC_OK);
    ear = result_json(ear_str);
    EXPECT_EQ(ear.value("ear_status", std::string{}), "contraindicated");
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_verifier_claims"]["ear_nvidia_evidence"]["cert_chain"][1]["ocsp_crl_status"], "error");

    nvat_str_free(&ear_str);
    nvat_verify_call_options_free(&call_opts);
    nvat_local_corim_verifier_free(&verifier);
}

TEST(CApiCorimVerifierTest, VerifyCmwExCustomRootWithRevokedDerOcspContraindicated) {
    // Generate an in-memory EC P-384 Root CA -> Leaf (with AIA OCSP URL),
    // sign a minimal CWT EAT CMW item, and supply a real signed REVOKED DER OCSPResponse.
    auto make_ec_key = []() {
        nvattestation::nv_unique_ptr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        EVP_PKEY *raw = nullptr;
        if (pctx && EVP_PKEY_keygen_init(pctx.get()) == 1 &&
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_secp384r1) == 1) {
            EVP_PKEY_keygen(pctx.get(), &raw);
        }
        return nvattestation::nv_unique_ptr<EVP_PKEY>(raw);
    };

    auto add_ext = [](X509 *cert, X509 *issuer, int nid, const char *val) {
        X509V3_CTX vctx;
        X509V3_set_ctx_nodb(&vctx);
        X509V3_set_ctx(&vctx, issuer, cert, nullptr, nullptr, 0);
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &vctx, nid, const_cast<char *>(val));
        ASSERT_NE(ext, nullptr);
        ASSERT_EQ(X509_add_ext(cert, ext, -1), 1);
        X509_EXTENSION_free(ext);
    };

    auto to_pem = [](X509 *cert) {
        nvattestation::nv_unique_ptr<BIO> bio(BIO_new(BIO_s_mem()));
        PEM_write_bio_X509(bio.get(), cert);
        const char *ptr = nullptr;
        long len = BIO_get_mem_data(bio.get(), &ptr);
        return std::string(ptr, static_cast<size_t>(len));
    };

    auto root_key = make_ec_key();
    auto leaf_key = make_ec_key();
    ASSERT_NE(root_key.get(), nullptr);
    ASSERT_NE(leaf_key.get(), nullptr);

    nvattestation::nv_unique_ptr<X509> root_cert(X509_new());
    X509_set_version(root_cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(root_cert.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(root_cert.get()), -3600);
    X509_gmtime_adj(X509_get_notAfter(root_cert.get()), 86400 * 365);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(root_cert.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("Test Device Root CA"), -1, -1, 0);
    X509_set_issuer_name(root_cert.get(), X509_get_subject_name(root_cert.get()));
    X509_set_pubkey(root_cert.get(), root_key.get());
    add_ext(root_cert.get(), root_cert.get(), NID_basic_constraints, "critical,CA:TRUE");
    add_ext(root_cert.get(), root_cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
    add_ext(root_cert.get(), root_cert.get(), NID_subject_key_identifier, "hash");
    ASSERT_GT(X509_sign(root_cert.get(), root_key.get(), EVP_sha384()), 0);

    nvattestation::nv_unique_ptr<X509> leaf_cert(X509_new());
    X509_set_version(leaf_cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(leaf_cert.get()), 42);
    X509_gmtime_adj(X509_get_notBefore(leaf_cert.get()), -3600);
    X509_gmtime_adj(X509_get_notAfter(leaf_cert.get()), 86400 * 365);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(leaf_cert.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("Test Device Leaf"), -1, -1, 0);
    X509_set_issuer_name(leaf_cert.get(), X509_get_subject_name(root_cert.get()));
    X509_set_pubkey(leaf_cert.get(), leaf_key.get());
    add_ext(leaf_cert.get(), root_cert.get(), NID_basic_constraints, "critical,CA:FALSE");
    add_ext(leaf_cert.get(), root_cert.get(), NID_key_usage, "critical,digitalSignature");
    add_ext(leaf_cert.get(), root_cert.get(), NID_authority_key_identifier, "keyid:always");
    add_ext(leaf_cert.get(), root_cert.get(), NID_info_access, "OCSP;URI:http://ocsp.example.test");
    ASSERT_GT(X509_sign(leaf_cert.get(), root_key.get(), EVP_sha384()), 0);

    // Build a signed DER OCSPResponse marking leaf_cert REVOKED (keyCompromise).
    std::string lookup_key;
    nvattestation::nv_unique_ptr<OCSP_CERTID> cert_id;
    ASSERT_EQ(nvattestation::CallbackOcspClient::compute_cert_lookup_key(
                  leaf_cert.get(), root_cert.get(), lookup_key, cert_id),
              nvattestation::Error::Ok);

    nvattestation::nv_unique_ptr<OCSP_BASICRESP> bresp(OCSP_BASICRESP_new());
    nvattestation::nv_unique_ptr<ASN1_TIME> thisupd(ASN1_TIME_adj(nullptr, time(nullptr), 0, -60));
    nvattestation::nv_unique_ptr<ASN1_TIME> nextupd(ASN1_TIME_adj(nullptr, time(nullptr), 1, 0));
    nvattestation::nv_unique_ptr<ASN1_TIME> revtime(ASN1_TIME_adj(nullptr, time(nullptr), 0, -120));
    ASSERT_NE(OCSP_basic_add1_status(bresp.get(), cert_id.get(), V_OCSP_CERTSTATUS_REVOKED,
                                     OCSP_REVOKED_STATUS_KEYCOMPROMISE,
                                     revtime.get(), thisupd.get(), nextupd.get()),
              nullptr);
    ASSERT_EQ(OCSP_basic_sign(bresp.get(), root_cert.get(), root_key.get(), EVP_sha384(), nullptr, 0), 1);
    nvattestation::nv_unique_ptr<OCSP_RESPONSE> oresp(
        OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bresp.get()));
    unsigned char *der_ptr = nullptr;
    int der_len = i2d_OCSP_RESPONSE(oresp.get(), &der_ptr);
    ASSERT_GT(der_len, 0);
    std::vector<uint8_t> revoked_der(der_ptr, der_ptr + der_len);
    OPENSSL_free(der_ptr);

    // Use Rubin SPDM transcript bytes with our test chain (signature verification off
    // so appraisal runs cert_chain + OCSP and reports the REVOKED cert status).
    std::string rubin_cmw_str;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, rubin_cmw_str), nvattestation::Error::Ok);
    nlohmann::json cmw_json = nlohmann::json::parse(rubin_cmw_str);
    const std::string root_pem = to_pem(root_cert.get());
    const std::string chain_pem = to_pem(leaf_cert.get()) + root_pem;
    std::string chain_b64url;
    ASSERT_EQ(nvattestation::encode_base64url(
                  std::vector<uint8_t>(chain_pem.begin(), chain_pem.end()), chain_b64url),
              nvattestation::Error::Ok);
    cmw_json["gpu_0"]["certificate"] = nlohmann::json::array({
        "application/vnd.nvidia.pem-cert-chain", chain_b64url
    });
    const std::string test_cmw = cmw_json.dump();

    OfflineCollateralStore collateral = load_rubin_offline_store();
    collateral.ocsp_responses.clear();
    collateral.ocsp_responses[lookup_key] = std::move(revoked_der);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr), NVAT_RC_OK);
    const char *roots[] = {root_pem.c_str()};
    ASSERT_EQ(nvat_local_corim_verifier_set_device_identity_roots(verifier, roots, 1), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_evidence_signature(verifier, false), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_rim_signature(verifier, false), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, true), NVAT_RC_OK);

    nvat_verify_call_options_t call_opts = nullptr;
    ASSERT_EQ(nvat_verify_call_options_create(&call_opts), NVAT_RC_OK);
    ASSERT_EQ(nvat_verify_call_options_set_collateral_callback(
                  call_opts, test_collateral_callback, &collateral),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_verify_call_options_set_require_ocsp_nonce(call_opts, false), NVAT_RC_OK);

    nvat_str_t ear_str = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_verify_cmw_ex(
                  verifier,
                  reinterpret_cast<const uint8_t *>(test_cmw.data()),
                  test_cmw.size(),
                  NVAT_CMW_FORMAT_JSON,
                  call_opts,
                  nullptr,
                  nullptr,
                  &ear_str),
              NVAT_RC_OK);

    nlohmann::json ear = result_json(ear_str);
    EXPECT_EQ(ear.value("ear_status", std::string{}), "contraindicated");
    const auto &chain = ear["submods"]["gpu_0"]["ear_verifier_claims"]["ear_nvidia_evidence"]["cert_chain"];
    ASSERT_EQ(chain.size(), 2u);
    EXPECT_EQ(chain[1]["cert_check_status"], "revoked");
    EXPECT_EQ(chain[1]["ocsp_crl_status"], "revoked");
    EXPECT_EQ(chain[1]["revocation_reason"], "keyCompromise");

    nvat_str_free(&ear_str);
    nvat_verify_call_options_free(&call_opts);
    nvat_local_corim_verifier_free(&verifier);
}

TEST(CApiCorimVerifierTest, VerifyCmwDiscardsResultAndRejectsEmptyInput) {
    std::string cmw;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw),
              nvattestation::Error::Ok);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    // Both out_ear_jwt/out_ear_json null discards the EAR result.
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw(
                  verifier, reinterpret_cast<const uint8_t *>(cmw.data()),
                  cmw.size(), NVAT_CMW_FORMAT_JSON, nullptr, nullptr, nullptr),
              NVAT_RC_OK);

    // Non-null pointer with zero length reaches the parser and fails there.
    const uint8_t byte = 0;
    nvat_str_t result = nullptr;
    EXPECT_NE(nvat_local_corim_verifier_verify_cmw(
                  verifier, &byte, 0, NVAT_CMW_FORMAT_JSON, nullptr, nullptr,
                  &result),
              NVAT_RC_OK);
    nvat_str_free(&result);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwNullSigningOptionsProducesUnsignedEar) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false), NVAT_RC_OK);

    std::string cmw;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw), nvattestation::Error::Ok);

    nvat_str_t result = nullptr;
    nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw(
        verifier, reinterpret_cast<const uint8_t *>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, nullptr, &result, nullptr);
    ASSERT_EQ(rc, NVAT_RC_OK);
    ASSERT_NE(result, nullptr);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(result, &data), NVAT_RC_OK);
    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(std::string(data));
    EXPECT_EQ(decoded.get_algorithm(), "none");
    nvat_str_free(&result);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwSigningOptionsProducesSignedEar) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false), NVAT_RC_OK);

    std::string cmw;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw), nvattestation::Error::Ok);
    std::string private_key_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/ec_p384_private.pem", private_key_pem),
              nvattestation::Error::Ok);

    nvat_detached_eat_options_t options = nullptr;
    ASSERT_EQ(nvat_detached_eat_options_create(&options, private_key_pem.c_str(), "test-issuer", "test-kid"),
              NVAT_RC_OK);

    nvat_str_t result = nullptr;
    nvat_str_t result_json = nullptr;
    nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw(
        verifier, reinterpret_cast<const uint8_t *>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, options, &result, &result_json);
    ASSERT_EQ(rc, NVAT_RC_OK);
    ASSERT_NE(result, nullptr);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(result, &data), NVAT_RC_OK);
    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(std::string(data));
    EXPECT_EQ(decoded.get_algorithm(), "ES384");
    nvat_str_free(&result);

    // out_ear_json carries the same claims as unsigned JSON, no JWT decode needed.
    ASSERT_NE(result_json, nullptr);
    char *json_data = nullptr;
    ASSERT_EQ(nvat_str_get_data(result_json, &json_data), NVAT_RC_OK);
    nlohmann::json parsed =
        nlohmann::json::parse(std::string(json_data), nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.contains("submods"));
    EXPECT_TRUE(parsed.contains("ear_status"));
    nvat_str_free(&result_json);

    nvat_detached_eat_options_free(&options);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, StoreAndVerifierAcceptInjectedDependencies) {
    nvat_http_options_t http = nullptr;
    ASSERT_EQ(nvat_http_options_create_default(&http), NVAT_RC_OK);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, "service-key", http), NVAT_RC_OK);

    const char *patterns[] = {"^http://a"};
    const char *replacements[] = {"http://b"};
    nvat_ocsp_client_t ocsp = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_aia(&ocsp, nullptr, nullptr, http,
                                          patterns, replacements, 1, nullptr),
              NVAT_RC_OK);

    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, ocsp),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_ocsp_client_free(&ocsp);
    nvat_corim_store_free(&store);
    nvat_http_options_free(&http);
}

TEST(CApiCorimVerifierTest, VerifierSettingsAcceptToggles) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    EXPECT_EQ(nvat_local_corim_verifier_set_verify_rim_signature(verifier, true),
              NVAT_RC_OK);
    EXPECT_EQ(
        nvat_local_corim_verifier_set_verify_rim_signature(verifier, false),
        NVAT_RC_OK);
    EXPECT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, true),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

// The C enum values are IANA NI registry IDs; this pins the C-to-C++ mapping
// so a renumbering cannot silently emit the wrong algorithm.
TEST(CApiCorimVerifierTest, InputHashAlgorithmsSelectEmittedDigests) {
    std::string cmw;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw),
              nvattestation::Error::Ok);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    const nvat_hash_algorithm_t algs[] = {NVAT_HASH_ALGORITHM_SHA384,
                                          NVAT_HASH_ALGORITHM_SHA512};
    ASSERT_EQ(
        nvat_local_corim_verifier_set_default_hash_algorithms(verifier, algs, 2),
        NVAT_RC_OK);

    nvat_rc_t rc = NVAT_RC_OK;
    nvat_str_t result = verify_cmw(verifier, cmw, rc);
    EXPECT_EQ(rc, NVAT_RC_OK);
    nlohmann::json parsed = result_json(result);
    ASSERT_TRUE(parsed.contains("ear_nvidia_inputs"));
    const auto& digests = parsed["ear_nvidia_inputs"]["digests"];
    ASSERT_EQ(digests.size(), 2U);
    EXPECT_EQ(digests[0]["alg"].get<std::string>(), "sha-384");
    EXPECT_EQ(digests[1]["alg"].get<std::string>(), "sha-512");

    nvat_str_free(&result);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, EnableInMemoryCacheOnStore) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    ASSERT_NE(store, nullptr);

    EXPECT_EQ(nvat_corim_store_enable_in_memory_cache(store, 1024 * 1024, 3600),
              NVAT_RC_OK);

    EXPECT_NE(nvat_corim_store_enable_in_memory_cache(store, 0, 3600), NVAT_RC_OK);
    EXPECT_NE(nvat_corim_store_enable_in_memory_cache(store, 1024 * 1024, -1), NVAT_RC_OK);

    nvat_corim_store_free(&store);
    EXPECT_EQ(store, nullptr);
}
