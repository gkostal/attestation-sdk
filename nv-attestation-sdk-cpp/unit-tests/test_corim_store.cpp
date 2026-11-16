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

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

#include <nlohmann/json.hpp>

#include "local_https_test_server.h"
#include "test_platform.h"
#include "nv_attestation/corim_evidence/corim_store.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_http.h"
#include "nv_attestation/utils.h"

namespace nvattestation {
namespace {

constexpr const char *kNvidiaRimPrefix =
    "https://rim.attestation.nvidia.com/";

class TempFile {
  public:
    explicit TempFile(const std::string &contents) {
        std::string path_template = nvat_test_temp_dir() + "/nvat_corim_store_XXXXXX";
        std::vector<char> buf(path_template.begin(), path_template.end());
        buf.push_back('\0');
        int fd = ::mkstemp(buf.data());
        if (fd < 0) {
            throw std::system_error(errno, std::generic_category(), "mkstemp");
        }
        ::close(fd);
        m_path = buf.data();
        std::ofstream out(m_path, std::ios::binary);
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }
    ~TempFile() { std::remove(m_path.c_str()); }
    const std::string &path() const { return m_path; }

  private:
    std::string m_path;
};

TEST(CorimStoreTest, RawNonHttpsRejected) {
    CorimStore store;
    std::vector<uint8_t> body;
    EXPECT_EQ(store.fetch("file:///etc/passwd", body), Error::BadArgument);
    EXPECT_EQ(store.fetch("http://example.com/rim", body),
              Error::BadArgument);
    EXPECT_EQ(store.fetch("ftp://example.com/rim", body),
              Error::BadArgument);
}

// ---- per-call collateral (ICollateralProvider) ----------------------------

class MapCollateral : public ICollateralProvider {
  public:
    std::map<std::string, std::vector<uint8_t>> corims;
    Error failure = Error::Ok;  // returned for every lookup when not Ok
    mutable std::vector<std::pair<CollateralKind, std::string>> requests;

    Error get_collateral(CollateralKind kind, const std::string &key,
                         std::vector<uint8_t> &out) const override {
        requests.emplace_back(kind, key);
        if (failure != Error::Ok) {
            return failure;
        }
        auto found = corims.find(key);
        if (found == corims.end()) {
            return Error::CacheObjectNotFound;
        }
        out = found->second;
        return Error::Ok;
    }
};

constexpr const char *kVbiosLocator =
    "https://rim.attestation.nvidia.com/v1/rim/GR100_081D_9900230000";

Error fetch_collateral(const CorimStore &store, const std::string &url,
                       const ICollateralProvider *collateral,
                       std::vector<uint8_t> &out_corim,
                       std::vector<uint8_t> *out_coev = nullptr,
                       bool *out_coev_present = nullptr) {
    std::vector<uint8_t> coev;
    bool coev_present = false;
    std::string coev_sha;
    Error err = store.fetch_with_coev(url, out_corim, coev, coev_present,
                                      coev_sha, nullptr, collateral);
    if (out_coev != nullptr) {
        *out_coev = coev;
    }
    if (out_coev_present != nullptr) {
        *out_coev_present = coev_present;
    }
    return err;
}

TEST(RimLookupKeyTest, ExtractsCanonicalRimId) {
    std::string key;
    ASSERT_EQ(rim_lookup_key_from_locator(kVbiosLocator, key), Error::Ok);
    EXPECT_EQ(key, "GR100_081D_9900230000");
    ASSERT_EQ(rim_lookup_key_from_locator(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "NV_GPU_DRIVER_GR100_620.54",
                  key),
              Error::Ok);
    EXPECT_EQ(key, "NV_GPU_DRIVER_GR100_620.54");
}

TEST(RimLookupKeyTest, RejectsMalformedIds) {
    const std::string prefix = "https://rim.attestation.nvidia.com/v1/rim/";
    for (const std::string &bad :
         {std::string(), std::string("a/b"), std::string("a\\b"),
          std::string(".."), std::string("a..b"), std::string("../x"),
          std::string("x/"), std::string("id?x=1"), std::string("id#frag"),
          std::string("id\n"), std::string("id\x01")}) {
        std::string key = "unchanged";
        EXPECT_EQ(rim_lookup_key_from_locator(prefix + bad, key),
                  Error::BadArgument)
            << "id: " << bad;
    }
}

TEST(RimLookupKeyTest, OtherLocatorsPassThroughUnchanged) {
    std::string key;
    ASSERT_EQ(rim_lookup_key_from_locator("https://rim.example.org/v9/x/y", key),
              Error::Ok);
    EXPECT_EQ(key, "https://rim.example.org/v9/x/y");
    // Only the exact NVIDIA RIM-service prefix is canonicalized.
    ASSERT_EQ(rim_lookup_key_from_locator(
                  "https://rim.attestation.nvidia.com/v2/rim/X", key),
              Error::Ok);
    EXPECT_EQ(key, "https://rim.attestation.nvidia.com/v2/rim/X");
}

TEST(CorimStoreCollateralTest, ServesRawCorimBytesByCanonicalId) {
    MapCollateral collateral;
    collateral.corims["GR100_081D_9900230000"] = {0xD9, 0x01, 0xF5, 0x01, 0x02};
    CorimStore store;
    std::vector<uint8_t> corim;
    bool coev_present = true;
    ASSERT_EQ(fetch_collateral(store, kVbiosLocator, &collateral, corim, nullptr,
                               &coev_present),
              Error::Ok);
    EXPECT_EQ(corim, collateral.corims["GR100_081D_9900230000"]);
    EXPECT_FALSE(coev_present);
    ASSERT_EQ(collateral.requests.size(), 1U);
    EXPECT_EQ(collateral.requests[0].first, CollateralKind::Corim);
    EXPECT_EQ(collateral.requests[0].second, "GR100_081D_9900230000");
}

TEST(CorimStoreCollateralTest, UnwrapsRimServiceJsonEnvelope) {
    const std::vector<uint8_t> rim = {1, 2, 3, 4};
    const std::vector<uint8_t> coev = {9, 8, 7};
    std::string rim_b64, coev_b64;
    ASSERT_EQ(encode_base64(rim, rim_b64), Error::Ok);
    ASSERT_EQ(encode_base64(coev, coev_b64), Error::Ok);
    const std::string envelope = "\n  {\"rim\":\"" + rim_b64 + "\",\"coev\":\"" +
                                 coev_b64 + "\",\"coev_sha256\":\"abc\"}";
    MapCollateral collateral;
    collateral.corims["GR100_081D_9900230000"] =
        std::vector<uint8_t>(envelope.begin(), envelope.end());

    CorimStore store;
    std::vector<uint8_t> out_rim, out_coev;
    bool coev_present = false;
    ASSERT_EQ(fetch_collateral(store, kVbiosLocator, &collateral, out_rim,
                               &out_coev, &coev_present),
              Error::Ok);
    EXPECT_EQ(out_rim, rim);
    EXPECT_TRUE(coev_present);
    EXPECT_EQ(out_coev, coev);
}

TEST(CorimStoreCollateralTest, MalformedEnvelopeIsAnInternalRimError) {
    MapCollateral collateral;
    collateral.corims["GR100_081D_9900230000"] = {'{', 'n', 'o', 't', ' ', 'j'};
    CorimStore store;
    std::vector<uint8_t> corim;
    EXPECT_EQ(fetch_collateral(store, kVbiosLocator, &collateral, corim),
              Error::RimInternalError);
}

TEST(CorimStoreCollateralTest, MissingCollateralIsRimNotFound) {
    MapCollateral collateral;
    CorimStore store;
    std::vector<uint8_t> corim;
    EXPECT_EQ(fetch_collateral(store, kVbiosLocator, &collateral, corim),
              Error::RimNotFound);
    // A store that "has" the key but with no bytes is the same as absent.
    collateral.corims["GR100_081D_9900230000"] = {};
    EXPECT_EQ(fetch_collateral(store, kVbiosLocator, &collateral, corim),
              Error::RimNotFound);
}

TEST(CorimStoreCollateralTest, LookupFailureIsAnInternalRimError) {
    MapCollateral collateral;
    collateral.failure = Error::InternalError;
    CorimStore store;
    std::vector<uint8_t> corim;
    EXPECT_EQ(fetch_collateral(store, kVbiosLocator, &collateral, corim),
              Error::RimInternalError);
}

// The allowlist vets the raw URL before the collateral store is ever asked.
TEST(CorimStoreCollateralTest, AllowlistStillEnforcedAndProviderNotAsked) {
    MapCollateral collateral;
    collateral.corims["anything"] = {1};
    CorimStore store;
    std::vector<uint8_t> corim;
    EXPECT_EQ(fetch_collateral(store, "https://attacker.example.com/anything",
                               &collateral, corim),
              Error::BadArgument);
    EXPECT_EQ(fetch_collateral(store, "file:///etc/passwd", &collateral, corim),
              Error::BadArgument);
    EXPECT_TRUE(collateral.requests.empty());
}

TEST(CorimStoreCollateralTest, MalformedRimIdIsRejectedWithoutALookup) {
    MapCollateral collateral;
    CorimStore store;
    std::vector<uint8_t> corim;
    EXPECT_EQ(fetch_collateral(store,
                               "https://rim.attestation.nvidia.com/v1/rim/../../etc/passwd",
                               &collateral, corim),
              Error::BadArgument);
    EXPECT_EQ(fetch_collateral(store, "https://rim.attestation.nvidia.com/v1/rim/",
                               &collateral, corim),
              Error::BadArgument);
    EXPECT_TRUE(collateral.requests.empty());
}

// With a collateral provider there is no rewrite, no file read, no HTTP and no
// shared cache: a stale/other-call cache entry must not satisfy the lookup, and
// the provider's bytes must not be written into the shared cache.
TEST(CorimStoreCollateralTest, BypassesRewritesFilesAndSharedCache) {
    CorimStore store;
    // A rewrite to a missing file would make a legacy fetch fail.
    ASSERT_EQ(store.add_url_rewrite(kVbiosLocator,
                                    "file:///nonexistent/nvat-test/vbios.cbor"),
              Error::Ok);
    auto cache = std::make_shared<NvCache>(
        std::make_shared<NvCacheOptions>(1 << 20, 3600));
    store.set_cache(cache);

    MapCollateral collateral;
    collateral.corims["GR100_081D_9900230000"] = {0xAA, 0xBB};
    std::vector<uint8_t> corim;
    ASSERT_EQ(fetch_collateral(store, kVbiosLocator, &collateral, corim),
              Error::Ok);
    EXPECT_EQ(corim, (std::vector<uint8_t>{0xAA, 0xBB}));

    std::shared_ptr<void> cached;
    EXPECT_NE(cache->get("file:///nonexistent/nvat-test/vbios.cbor", cached),
              Error::Ok);
    // Legacy path (no provider) still tries the rewritten file and fails.
    EXPECT_EQ(fetch_collateral(store, kVbiosLocator, nullptr, corim),
              Error::RimNotFound);
}

TEST(CorimStoreTest, RawHttpsOutsideAllowlistRejected) {
    CorimStore store;
    std::vector<uint8_t> body;
    // https but pointed at an arbitrary host: the verifier must not
    // honor it, even with no rewrites configured.
    EXPECT_EQ(store.fetch("https://attacker.example.com/anything", body),
              Error::BadArgument);
    // Also reject a URL whose host is the allowlist prefix's host but
    // not under the trailing-slash path boundary.
    EXPECT_EQ(store.fetch("https://rim.attestation.nvidia.com.evil/x",
                            body),
              Error::BadArgument);
}

TEST(CorimStoreTest, EffectiveUrlIsRawUrlOnAllowlistRejection) {
    // out_effective_url must still hold a usable value (the raw URL) on
    // the allowlist-rejection path, since callers log it on fetch failure.
    CorimStore store;
    std::vector<uint8_t> body;
    std::string effective = "not-yet-set";
    EXPECT_EQ(store.fetch("https://attacker.example.com/anything", body,
                            &effective),
              Error::BadArgument);
    EXPECT_EQ(effective, "https://attacker.example.com/anything");

    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = false;
    std::string coev_sha256;
    std::string coev_effective = "not-yet-set";
    EXPECT_EQ(store.fetch_with_coev("https://attacker.example.com/anything",
                                      corim_bytes, coev_bytes, coev_present,
                                      coev_sha256, &coev_effective),
              Error::BadArgument);
    EXPECT_EQ(coev_effective, "https://attacker.example.com/anything");
}

TEST(CorimStoreTest, EmptyPatternRejected) {
    CorimStore store;
    EXPECT_EQ(store.add_url_rewrite("", "https://anywhere/"),
              Error::BadArgument);
}

TEST(CorimStoreTest, RewriteToFileReadsBytes) {
    const std::string contents = "RIM-BYTES-12345";
    TempFile tmp(contents);

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(
                  std::string(kNvidiaRimPrefix) + "foo",
                  "file://" + tmp.path()),
              Error::Ok);
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(std::string(kNvidiaRimPrefix) + "foo", body),
              Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), contents);
}

// appraise_item calls fetch_with_coev unconditionally, so it must support
// file:// fixtures the same as fetch().
TEST(CorimStoreTest, FetchWithCoevRewriteToFileReadsBytesNoCoev) {
    const std::string contents = "RIM-BYTES-12345";
    TempFile tmp(contents);

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(
                  std::string(kNvidiaRimPrefix) + "foo",
                  "file://" + tmp.path()),
              Error::Ok);
    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = true; // must be reset to false
    std::string coev_sha256 = "not-yet-set"; // must be reset to empty
    ASSERT_EQ(store.fetch_with_coev(std::string(kNvidiaRimPrefix) + "foo",
                                     corim_bytes, coev_bytes, coev_present,
                                     coev_sha256),
              Error::Ok);
    EXPECT_EQ(std::string(corim_bytes.begin(), corim_bytes.end()), contents);
    EXPECT_FALSE(coev_present);
    EXPECT_TRUE(coev_bytes.empty());
    EXPECT_TRUE(coev_sha256.empty());
}

TEST(CorimStoreTest, FirstMatchWins) {
    const std::string winner_contents = "WINNER";
    const std::string loser_contents = "LOSER";
    TempFile winner(winner_contents);
    TempFile loser(loser_contents);

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(std::string(kNvidiaRimPrefix) + "a",
                                      "file://" + winner.path()),
              Error::Ok);
    // Second rule overlaps but should never fire. Drop the trailing
    // '/' from the prefix so PATTERN and REPLACEMENT both end without
    // one (matching-slash rule).
    std::string broader_pattern = kNvidiaRimPrefix;
    if (!broader_pattern.empty() && broader_pattern.back() == '/') {
        broader_pattern.pop_back();
    }
    ASSERT_EQ(store.add_url_rewrite(broader_pattern,
                                      "file://" + loser.path()),
              Error::Ok);

    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(std::string(kNvidiaRimPrefix) + "a", body),
              Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), winner_contents);
}

TEST(CorimStoreTest, NonMatchingRulesLeaveSchemeIntact) {
    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite("https://other.example.com/",
                                      "file:///nonexistent/"),
              Error::Ok);
    std::vector<uint8_t> body;
    std::string effective;
    store.fetch(std::string(kNvidiaRimPrefix) + "rim", body, &effective);
    // Non-matching rule: effective URL must equal the raw input (no rewrite).
    EXPECT_EQ(effective, std::string(kNvidiaRimPrefix) + "rim");
}

TEST(CorimStoreTest, MismatchedTrailingSlashRejected) {
    CorimStore store;
    EXPECT_EQ(store.add_url_rewrite("https://a/", "file:///b"),
              Error::BadArgument);
    EXPECT_EQ(store.add_url_rewrite("https://a", "file:///b/"),
              Error::BadArgument);
    EXPECT_EQ(store.add_url_rewrite("https://a/", "file:///b/"),
              Error::Ok);
    EXPECT_EQ(store.add_url_rewrite("https://a", "file:///b"),
              Error::Ok);
}

TEST(CorimStoreTest, RewriteMustProduceKnownScheme) {
    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(kNvidiaRimPrefix, "ftp://elsewhere/"),
              Error::Ok);
    std::vector<uint8_t> body;
    EXPECT_EQ(store.fetch(std::string(kNvidiaRimPrefix) + "foo", body),
              Error::BadArgument);
}

TEST(CorimStoreTest, RewriteToHttpSchemeAccepted) {
    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(kNvidiaRimPrefix, "http://127.0.0.1:9/"),
              Error::Ok);
    std::vector<uint8_t> body;
    std::string effective;
    // Nothing listens on discard port 9, so the fetch fails at the transport
    // layer -- but the http:// scheme must be dispatched, not rejected like the
    // ftp:// case in RewriteMustProduceKnownScheme.
    Error err = store.fetch(std::string(kNvidiaRimPrefix) + "foo", body,
                            &effective);
    EXPECT_EQ(effective, "http://127.0.0.1:9/foo");
    EXPECT_NE(err, Error::BadArgument);
}

TEST(CorimStoreTest, FilePostRewriteNotFound) {
    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(kNvidiaRimPrefix,
                                      "file:///definitely/not/here/"),
              Error::Ok);
    std::vector<uint8_t> body;
    EXPECT_EQ(store.fetch(std::string(kNvidiaRimPrefix) + "foo", body),
              Error::RimNotFound);
}

TEST(CorimStoreTest, AllowlistPrefixMustBeHttps) {
    CorimStore store;
    EXPECT_EQ(store.add_allowed_url_prefix("file:///etc/"),
              Error::BadArgument);
    EXPECT_EQ(store.add_allowed_url_prefix("http://mirror.example.com/"),
              Error::BadArgument);
    EXPECT_EQ(store.add_allowed_url_prefix("https://mirror.example.com/"),
              Error::Ok);
}

TEST(CorimStoreTest, AddedAllowlistPrefixIsHonored) {
    const std::string contents = "MIRROR-RIM";
    TempFile tmp(contents);

    CorimStore store;
    // A URL outside the built-in NVIDIA prefix is rejected until allowlisted.
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch("https://mirror.example.com/rim", body),
              Error::BadArgument);

    ASSERT_EQ(store.add_allowed_url_prefix("https://mirror.example.com/"),
              Error::Ok);
    ASSERT_EQ(store.add_url_rewrite("https://mirror.example.com/rim",
                                      "file://" + tmp.path()),
              Error::Ok);
    ASSERT_EQ(store.fetch("https://mirror.example.com/rim", body),
              Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), contents);
}


// === HTTPS content-type integration tests ===
// Spins up a local HTTPS server so the https:// dispatch path exercises a
// real Content-Type header rather than assuming any given response is CoRIM.

class CorimStoreHttpsTest : public ::testing::Test {
  protected:
    static LocalHttpsTestServer m_server;
    static bool m_setup_ok;

    static void SetUpTestSuite() { m_setup_ok = m_server.start(); }
    static void TearDownTestSuite() { m_server.stop(); }

    void SetUp() override {
        ASSERT_TRUE(m_setup_ok) << "HTTPS test server not available";
    }

    CorimStore make_store() const {
        HttpOptions options;
        options.set_tls_ca_cert(m_server.cert_path("tls_ca_cert.pem"));
        options.set_max_retry_count(0);
        CorimStore store(options);
        Error err = store.add_allowed_url_prefix(m_server.url());
        EXPECT_EQ(err, Error::Ok);
        return store;
    }

    std::string server_url() const { return m_server.url(); }
};

LocalHttpsTestServer CorimStoreHttpsTest::m_server;
bool CorimStoreHttpsTest::m_setup_ok = false;

TEST_F(CorimStoreHttpsTest, JsonRimServiceResponseIsUnwrapped) {
    CorimStore store = make_store();
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(server_url() + "rim-service", body), Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), "CORIM-BYTES-FROM-SERVICE");
}

TEST_F(CorimStoreHttpsTest, CorimCborContentTypePassesThroughRawBytes) {
    CorimStore store = make_store();
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(server_url() + "corim-cbor", body), Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), "CORIM-BYTES-CBOR");
}

TEST_F(CorimStoreHttpsTest, CorimCoseContentTypePassesThroughRawBytes) {
    CorimStore store = make_store();
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(server_url() + "corim-cose", body), Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), "CORIM-BYTES-COSE");
}

TEST_F(CorimStoreHttpsTest, UnexpectedContentTypeRejected) {
    CorimStore store = make_store();
    std::vector<uint8_t> body;
    EXPECT_EQ(store.fetch(server_url() + "unexpected-content-type", body),
              Error::RimInvalidSchema);
}

// === fetch_with_coev ===

TEST_F(CorimStoreHttpsTest, FetchWithCoevExtractsBothPayloads) {
    CorimStore store = make_store();
    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = false;
    std::string coev_sha256;
    Error err = store.fetch_with_coev(server_url() + "rim-service-with-coev",
                                       corim_bytes, coev_bytes, coev_present,
                                       coev_sha256);

    EXPECT_EQ(err, Error::Ok);
    EXPECT_EQ(corim_bytes, (std::vector<uint8_t>{0x01, 0x02, 0x03}));
    EXPECT_TRUE(coev_present);
    EXPECT_EQ(coev_bytes, (std::vector<uint8_t>{0xAA, 0xBB}));
    EXPECT_EQ(coev_sha256, "unused");
}

TEST_F(CorimStoreHttpsTest, FetchWithCoevAbsentIsNotAnError) {
    CorimStore store = make_store();
    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = true; // must be reset to false by fetch_with_coev
    std::string coev_sha256 = "not-yet-set";
    Error err = store.fetch_with_coev(server_url() + "rim-service-no-coev",
                                       corim_bytes, coev_bytes, coev_present,
                                       coev_sha256);

    EXPECT_EQ(err, Error::Ok);
    EXPECT_FALSE(coev_present);
    EXPECT_TRUE(coev_bytes.empty());
    EXPECT_TRUE(coev_sha256.empty());
}

TEST_F(CorimStoreHttpsTest, FetchWithCoevRejectsInvalidCoevBase64) {
    CorimStore store = make_store();
    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = false;
    std::string coev_sha256;
    Error err = store.fetch_with_coev(
        server_url() + "rim-service-with-invalid-coev-base64", corim_bytes,
        coev_bytes, coev_present, coev_sha256);

    EXPECT_EQ(err, Error::RimInternalError);
}

// === ends_with utility ===

TEST(EndsWithTest, BasicSuffix) {
    EXPECT_TRUE(ends_with("nvidia.com", ".com"));
    EXPECT_TRUE(ends_with(".nvidia.com", ".nvidia.com"));
    EXPECT_TRUE(ends_with("rim.attestation.nvidia.com", ".nvidia.com"));
    EXPECT_FALSE(ends_with("notnvidia.com", ".nvidia.com"));
    EXPECT_FALSE(ends_with("nvidia.com.evil", ".nvidia.com"));
    EXPECT_TRUE(ends_with("", ""));
    EXPECT_FALSE(ends_with("", ".nvidia.com"));
}

// === Service-key domain + scheme scoping (indirect, via CorimStore) ===
// The credential must only be forwarded to https://*.nvidia.com targets.

// === Service-key domain scoping ===

TEST_F(CorimStoreHttpsTest, ServiceKeyNotSentToNonNvidiaDomain) {
    HttpOptions options;
    options.set_tls_ca_cert(m_server.cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);

    NvHttpClient client;
    ASSERT_EQ(NvHttpClient::create(client, "super-secret-key", options), Error::Ok);

    NvRequest req(server_url() + "echo-headers", NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string body;
    ASSERT_EQ(client.do_request_as_string(req, status, body), Error::Ok);
    ASSERT_EQ(status, 200);

    auto j = nlohmann::json::parse(body);
    // Headers are lowercased by Python's http.server; check both casings to be safe.
    const auto& headers = j.at("headers");
    EXPECT_FALSE(headers.contains("authorization"))
        << "Service key was leaked to a non-NVIDIA domain";
    EXPECT_FALSE(headers.contains("Authorization"))
        << "Service key was leaked to a non-NVIDIA domain";
}

} // namespace
} // namespace nvattestation
