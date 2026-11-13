// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Deliberately use only nvat.h: this executable tests the actual shared C ABI.
#include "nvat.h"
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdlib>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <unistd.h>

namespace {
using Json = nlohmann::json;
const std::string kFixtures = "testdata/offline-collateral/";

std::string read(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Missing fixture: " + path);
    return {std::istreambuf_iterator<char>(in), {}};
}
std::string b64(const std::string& bytes) {
    static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    unsigned int acc = 0, bits = 0;
    for (unsigned char c : bytes) {
        acc = (acc << 8) | c;
        bits += 8;
        while (bits >= 6) { bits -= 6; out += digits[(acc >> bits) & 63]; }
    }
    if (bits) out += digits[(acc << (6 - bits)) & 63];
    return out;
}
struct Context {
    std::map<std::string, std::string> corim;
    std::map<std::string, std::string> ocsp;
    std::vector<std::pair<nvat_collateral_kind_t, std::string>> requests;
    std::mutex mutex;
    void load(bool synthetic = false, bool revoked = false) {
        corim["GR100_081D_9900230000"] = read(kFixtures + "rubin_vbios_example.cbor");
        corim["NV_GPU_DRIVER_GR100_620.54"] = read(kFixtures + "rubin_driver_example.cbor");
        auto metadata = Json::parse(read(kFixtures + (synthetic ? "synthetic-metadata.json" : "rubin-metadata.json")));
        if (synthetic) {
            std::string subdir = revoked ? "synthetic-revoked/" : "synthetic-good/";
            for (const char* field : {"synthetic_leaf_key", "synthetic_ica_key"}) {
                std::string key = metadata[field];
                ocsp[key] = read(kFixtures + subdir + key + ".der");
            }
        } else {
            for (const auto& cert : metadata["responses"]) {
                std::string key = cert["lookup_key"];
                ocsp[key] = read(kFixtures + "ocsp/" + key + ".der");
            }
        }
    }
    static nvat_rc_t callback(void* ptr, nvat_collateral_kind_t kind,
                              const char* key, nvat_byte_buf_t* out) {
        if (!ptr || !key || !out) return NVAT_RC_BAD_ARGUMENT;
        *out = nullptr;
        auto& ctx = *static_cast<Context*>(ptr);
        std::lock_guard<std::mutex> lock(ctx.mutex);
        ctx.requests.emplace_back(kind, key);
        auto& entries = kind == NVAT_COLLATERAL_KIND_CORIM ? ctx.corim : ctx.ocsp;
        auto it = entries.find(key);
        if (it == entries.end()) return NVAT_RC_COLLATERAL_NOT_FOUND;
        return nvat_byte_buf_create(out,
            reinterpret_cast<const uint8_t*>(it->second.data()), it->second.size());
    }
};
struct Options {
    nvat_verify_call_options_t handle = nullptr;
    Options(Context& context, bool synthetic = false) {
        EXPECT_EQ(nvat_verify_call_options_create(&handle), NVAT_RC_OK);
        EXPECT_EQ(nvat_verify_call_options_set_collateral_callback(handle, Context::callback, &context), NVAT_RC_OK);
        EXPECT_EQ(nvat_verify_call_options_set_require_ocsp_nonce(handle, false), NVAT_RC_OK);
        auto metadata = Json::parse(read(kFixtures + (synthetic ? "synthetic-metadata.json" : "rubin-metadata.json")));
        EXPECT_EQ(nvat_verify_call_options_set_verification_time(handle,
            metadata["verification_time"].get<int64_t>()), NVAT_RC_OK);
    }
    ~Options() { nvat_verify_call_options_free(&handle); }
};
struct Verifier {
    nvat_local_corim_verifier_t handle = nullptr;
    explicit Verifier(bool synthetic = false, bool cached_file_rewrites = false,
                      bool configured_http_client = false) {
        nvat_corim_store_t store = nullptr;
        EXPECT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
        EXPECT_EQ(nvat_corim_store_enable_in_memory_cache(store, 1024 * 1024, 3600), NVAT_RC_OK);
        if (cached_file_rewrites) {
            char cwd[4096];
            EXPECT_NE(getcwd(cwd, sizeof(cwd)), nullptr);
            for (auto entry : {
                std::make_pair("GR100_081D_9900230000", "rubin_vbios_example.cbor"),
                std::make_pair("NV_GPU_DRIVER_GR100_620.54", "rubin_driver_example.cbor")}) {
                std::string url = std::string("https://rim.attestation.nvidia.com/v1/rim/") + entry.first;
                std::string file = std::string("file://") + cwd + "/" + kFixtures + entry.second;
                EXPECT_EQ(nvat_corim_store_add_url_rewrite(store, url.c_str(), file.c_str()), NVAT_RC_OK);
            }
        } else {
            // If callback routing ever falls through, the call must not read
            // this path (or try to use it as a callback lookup key).
            EXPECT_EQ(nvat_corim_store_add_url_rewrite(store,
                "https://rim.attestation.nvidia.com/", "file:///nvat-must-never-be-read/"), NVAT_RC_OK);
        }
        nvat_ocsp_client_t http = nullptr, cached = nullptr;
        if (configured_http_client) {
            EXPECT_EQ(nvat_ocsp_client_create_default(&http,
                "http://127.0.0.1:9", nullptr, nullptr), NVAT_RC_OK);
            EXPECT_EQ(nvat_ocsp_client_create_cached(&cached, http,
                1024 * 1024, 3600), NVAT_RC_OK);
        }
        EXPECT_EQ(nvat_local_corim_verifier_create(&handle, &store, cached), NVAT_RC_OK);
        nvat_ocsp_client_free(&cached);
        nvat_ocsp_client_free(&http);
        EXPECT_EQ(store, nullptr);
        EXPECT_EQ(nvat_local_corim_verifier_set_verify_rim_signature(handle, false), NVAT_RC_OK);
        EXPECT_EQ(nvat_local_corim_verifier_set_verify_evidence_signature(handle, true), NVAT_RC_OK);
        EXPECT_EQ(nvat_local_corim_verifier_set_verify_revocation(handle, true), NVAT_RC_OK);
        if (synthetic) {
            std::string root = read(kFixtures + "test-root.pem");
            const char* roots[] = {root.c_str()};
            EXPECT_EQ(nvat_local_corim_verifier_set_device_identity_roots(handle, roots, 1), NVAT_RC_OK);
        }
    }
    ~Verifier() { nvat_local_corim_verifier_free(&handle); }
};
std::string evidence(bool synthetic = false) {
    return read(synthetic ? kFixtures + "synthetic_evidence.cmw.json" :
        "testdata/sample_attestation_data/rubin_evidence.cmw.json");
}
Json verify(nvat_local_corim_verifier_t verifier, const std::string& cmw,
             nvat_verify_call_options_t options) {
    nvat_str_t output = nullptr;
    nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw_ex(verifier,
        reinterpret_cast<const uint8_t*>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, options, nullptr, nullptr, &output);
    EXPECT_EQ(rc, NVAT_RC_OK) << nvat_rc_to_string(rc);
    if (!output) return Json::object();
    char* data = nullptr;
    size_t size = 0;
    EXPECT_EQ(nvat_str_get_data(output, &data), NVAT_RC_OK);
    EXPECT_EQ(nvat_str_length(output, &size), NVAT_RC_OK);
    Json result = Json::parse(data, data + size);
    nvat_str_free(&output);
    return result;
}
Json& detail(Json& ear) {
    return ear["submods"]["gpu_0"]["ear_verifier_claims"]["ear_nvidia_evidence"];
}
size_t count_status(Json& ear, const char* status) {
    size_t count = 0;
    for (const auto& cert : detail(ear)["cert_chain"])
        if (cert.value("ocsp_crl_status", "") == status) ++count;
    return count;
}

TEST(OfflineCAbi, RubinGoodCachedOcspAffirms) {
    Context ctx; ctx.load();
    Options options(ctx); Verifier verifier;
    Json ear = verify(verifier.handle, evidence(), options.handle);
    EXPECT_EQ(ear["ear_status"], "affirming") << ear.dump(2);
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_status"], "affirming");
    EXPECT_EQ(detail(ear)["signature_verified"], true);
    EXPECT_EQ(count_status(ear, "good"), 3u);
    EXPECT_EQ(count_status(ear, "not_checked"), 2u);
    for (const auto& cert : detail(ear)["cert_chain"]) {
        if (cert.value("ocsp_crl_status", "") == "good") {
            EXPECT_EQ(cert["ocsp_nonce_matches"], false);
            EXPECT_EQ(cert["ocsp_crl_response_expired"], false);
            EXPECT_EQ(cert["ocsp_response_status"], true);
        }
    }
    EXPECT_EQ(ctx.requests.size(), 5u);
}
TEST(OfflineCAbi, MissingAndCorruptOcspContraindicate) {
    for (bool corrupt : {false, true}) {
        Context ctx; ctx.load();
        if (corrupt) for (auto& pair : ctx.ocsp) pair.second = "not DER";
        else ctx.ocsp.clear();
        Options options(ctx); Verifier verifier;
        Json ear = verify(verifier.handle, evidence(), options.handle);
        EXPECT_EQ(ear["submods"]["gpu_0"]["ear_status"], "contraindicated");
        EXPECT_EQ(detail(ear)["signature_verified"], false);
        EXPECT_GT(count_status(ear, "error"), 0u);
        EXPECT_EQ(count_status(ear, "not_checked"), 2u);
    }
}
TEST(OfflineCAbi, WrongCertIdAndTamperedOcspFailClosed) {
    for (bool tampered : {false, true}) {
        Context ctx; ctx.load();
        auto first = ctx.ocsp.begin(), second = std::next(first);
        if (tampered) first->second[first->second.size() / 4] ^= 0x80;
        else first->second = second->second;
        Options options(ctx); Verifier verifier;
        Json ear = verify(verifier.handle, evidence(), options.handle);
        EXPECT_EQ(ear["ear_status"], "contraindicated");
        EXPECT_EQ(detail(ear)["signature_verified"], false);
        EXPECT_GT(count_status(ear, "error"), 0u);
    }
}
TEST(OfflineCAbi, ExpiredOcspAndReplayOptOut) {
    Context ctx; ctx.load(); Options options(ctx); Verifier verifier;
    auto metadata = Json::parse(read(kFixtures + "rubin-metadata.json"));
    ASSERT_EQ(nvat_verify_call_options_set_verification_time(options.handle,
        metadata["expired_verification_time"].get<int64_t>()), NVAT_RC_OK);
    Json expired = verify(verifier.handle, evidence(), options.handle);
    EXPECT_EQ(expired["ear_status"], "contraindicated");
    EXPECT_EQ(detail(expired)["signature_verified"], false);
    EXPECT_EQ(count_status(expired, "good"), 3u);
    size_t count = 0;
    for (const auto& cert : detail(expired)["cert_chain"])
        if (cert.value("ocsp_crl_response_expired", false)) ++count;
    EXPECT_EQ(count, 3u);
    ASSERT_EQ(nvat_verify_call_options_set_enforce_ocsp_next_update(options.handle, false), NVAT_RC_OK);
    Json replay = verify(verifier.handle, evidence(), options.handle);
    EXPECT_EQ(replay["ear_status"], "affirming");
    EXPECT_EQ(detail(replay)["signature_verified"], true);
}
TEST(OfflineCAbi, DefaultNonceRequirementAndFutureStatusFailClosed) {
    Context ctx; ctx.load(); Options options(ctx); Verifier verifier;
    ASSERT_EQ(nvat_verify_call_options_set_require_ocsp_nonce(options.handle, true), NVAT_RC_OK);
    Json nonce = verify(verifier.handle, evidence(), options.handle);
    EXPECT_EQ(nonce["ear_status"], "contraindicated");
    EXPECT_EQ(count_status(nonce, "good"), 3u);
    ASSERT_EQ(nvat_verify_call_options_set_require_ocsp_nonce(options.handle, false), NVAT_RC_OK);
    auto metadata = Json::parse(read(kFixtures + "rubin-metadata.json"));
    ASSERT_EQ(nvat_verify_call_options_set_verification_time(options.handle,
        metadata["verification_time"].get<int64_t>() - 86400), NVAT_RC_OK);
    EXPECT_EQ(verify(verifier.handle, evidence(), options.handle)["ear_status"], "contraindicated");
}
TEST(OfflineCAbi, MissingCorimAndJsonEnvelope) {
    Context ctx; ctx.load(); Options options(ctx); Verifier verifier;
    std::string saved = ctx.corim.begin()->second;
    std::string encoded = b64(saved);
    for (char& c : encoded) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    encoded.append((4 - encoded.size() % 4) % 4, '=');
    ctx.corim.begin()->second = Json{{"rim", encoded}}.dump();
    Json envelope = verify(verifier.handle, evidence(), options.handle);
    EXPECT_EQ(envelope["ear_status"], "affirming");
    ctx.corim.clear();
    Json missing = verify(verifier.handle, evidence(), options.handle);
    EXPECT_EQ(missing["ear_status"], "contraindicated");
    for (const auto& rim : missing["submods"]["gpu_0"]["ear_verifier_claims"]["ear_nvidia_rims"])
        EXPECT_EQ(rim["fetched"], false);
}
TEST(OfflineCAbi, CallbackIsolationConcurrentAndWarmSharedCache) {
    Context good; good.load(); Context missing; missing.load(); missing.corim.clear();
    Context missing_ocsp; missing_ocsp.load(); missing_ocsp.ocsp.clear();
    Verifier verifier(false, true);
    std::string cmw = evidence();
    const int64_t expired_time = Json::parse(read(kFixtures + "rubin-metadata.json"))
        ["expired_verification_time"].get<int64_t>();
    // Populate the shared store cache through the legacy native file path.
    EXPECT_EQ(verify(verifier.handle, cmw, nullptr)["ear_status"], "affirming");
    std::vector<std::future<Json>> calls;
    for (int i = 0; i < 12; ++i) {
        calls.push_back(std::async(std::launch::async, [&, i] {
            Options options(i % 4 == 1 ? missing : (i % 4 == 2 ? missing_ocsp : good));
            if (i % 4 == 3) {
                EXPECT_EQ(nvat_verify_call_options_set_verification_time(
                    options.handle, expired_time), NVAT_RC_OK);
            }
            return verify(verifier.handle, cmw, options.handle);
        }));
    }
    for (size_t i = 0; i < calls.size(); ++i)
        EXPECT_EQ(calls[i].get()["ear_status"], i % 4 ? "contraindicated" : "affirming");
    EXPECT_EQ(verify(verifier.handle, cmw, nullptr)["ear_status"], "affirming");
    EXPECT_EQ(good.requests.size(), 30u);
    EXPECT_EQ(missing.requests.size(), 15u);
    EXPECT_EQ(missing_ocsp.requests.size(), 9u);
}
TEST(OfflineCAbi, SyntheticGoodAndGenuinelySignedRevoked) {
    for (bool revoked : {false, true}) {
        Context ctx; ctx.load(true, revoked);
        Options options(ctx, true); Verifier verifier(true);
        Json ear = verify(verifier.handle, evidence(true), options.handle);
        EXPECT_EQ(ear["ear_status"], revoked ? "contraindicated" : "affirming") << ear.dump(2);
        EXPECT_EQ(detail(ear)["signature_verified"], !revoked);
        EXPECT_EQ(count_status(ear, "revoked"), revoked ? 1u : 0u);
        if (revoked) {
            for (const auto& cert : detail(ear)["cert_chain"]) {
                if (cert.value("ocsp_crl_status", "") == "revoked") {
                    EXPECT_EQ(cert["cert_check_status"], "revoked");
                    EXPECT_EQ(cert["ocsp_response_status"], true);
                    EXPECT_TRUE(cert.contains("ocsp_response_revoked_at"));
                }
            }
        }
    }
}
TEST(OfflineCAbi, RootReplacementRejectsBadRootsAtomically) {
    Context ctx; ctx.load(true);
    Options options(ctx, true); Verifier verifier(true);
    const char* invalid[] = {"not a PEM"};
    EXPECT_EQ(nvat_local_corim_verifier_set_device_identity_roots(verifier.handle, invalid, 1), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_set_device_identity_roots(verifier.handle, invalid, 0), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(verify(verifier.handle, evidence(true), options.handle)["ear_status"], "affirming");
    Verifier production;
    EXPECT_EQ(verify(production.handle, evidence(true), options.handle)["ear_status"], "contraindicated");
}
TEST(OfflineCAbi, MalformedCmwAndInvalidArguments) {
    Context ctx; ctx.load(); Options options(ctx); Verifier verifier;
    for (const std::string malformed : {"not json", "{}", "[]", "{\"gpu_0\":{}}"}) {
        nvat_str_t output = reinterpret_cast<nvat_str_t>(uintptr_t(1));
        EXPECT_EQ(nvat_local_corim_verifier_verify_cmw_ex(verifier.handle,
            reinterpret_cast<const uint8_t*>(malformed.data()), malformed.size(),
            NVAT_CMW_FORMAT_JSON, options.handle, nullptr, nullptr, &output),
            NVAT_RC_EVIDENCE_MALFORMED);
        EXPECT_EQ(output, nullptr);
    }
    EXPECT_EQ(nvat_verify_call_options_create(nullptr), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_call_options_set_collateral_callback(options.handle, nullptr, nullptr), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_call_options_set_verification_time(options.handle, -1), NVAT_RC_BAD_ARGUMENT);
    nvat_byte_buf_t buf = reinterpret_cast<nvat_byte_buf_t>(uintptr_t(1));
    EXPECT_EQ(nvat_byte_buf_create(&buf, nullptr, 1), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(buf, nullptr);
    EXPECT_EQ(nvat_byte_buf_create(&buf, nullptr, 0), NVAT_RC_OK);
    nvat_byte_buf_free(&buf);
    EXPECT_EQ(buf, nullptr);
    nvat_byte_buf_free(&buf);
    nvat_verify_call_options_free(nullptr);
}
TEST(OfflineCAbi, VendorHintsAcceptedAndOtherMediaRejected) {
    Context ctx; ctx.load(); Options options(ctx); Verifier verifier;
    auto cmw = Json::parse(evidence());
    cmw["gpu_0"]["hints"] = Json::array({
        "application/vnd.microsoft.maa.x-ms-runtime+json", b64("{\"fwversion\":123,\"keys\":[]}")});
    EXPECT_EQ(verify(verifier.handle, cmw.dump(), options.handle)["ear_status"], "affirming");
    for (const char* media : {"text/plain", "application/+json", "application/a/b+json", "application/a +json"}) {
        cmw["gpu_0"]["hints"][0] = media;
        std::string bytes = cmw.dump();
        EXPECT_EQ(nvat_local_corim_verifier_verify_cmw_ex(verifier.handle,
            reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(),
            NVAT_CMW_FORMAT_JSON, options.handle, nullptr, nullptr, nullptr),
            NVAT_RC_EVIDENCE_MALFORMED);
    }
}
TEST(OfflineCAbi, BlackwellVendorHintsAreNotFirmwareHints) {
    Context ctx; Options options(ctx); Verifier verifier;
    auto cmw = Json::parse(read("testdata/sample_attestation_data/blackwell_fsp_evidence.cmw.json"));
    cmw["gpu_0"]["hints"] = Json::array({
        "application/vnd.microsoft.maa.x-ms-runtime+json", b64("{\"fwversion\":123}")});
    Json ear = verify(verifier.handle, cmw.dump(), options.handle);
    EXPECT_EQ(ear["ear_status"], "contraindicated");
    EXPECT_EQ(ear.dump().find("malformed hints record"), std::string::npos);
}
TEST(OfflineCAbi, ZeroNativeIo) {
    Context ctx; ctx.load(); Options options(ctx); Verifier verifier(false, false, true);
    const std::string cmw = evidence();
    const char begin[] = "NVAT_OFFLINE_IO_BEGIN\n";
    const char end[] = "NVAT_OFFLINE_IO_END\n";
    EXPECT_EQ(write(STDERR_FILENO, begin, sizeof(begin) - 1), sizeof(begin) - 1);
    Json ear = verify(verifier.handle, cmw, options.handle);
    EXPECT_EQ(write(STDERR_FILENO, end, sizeof(end) - 1), sizeof(end) - 1);
    EXPECT_EQ(ear["ear_status"], "affirming");
}
} // namespace

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    nvat_logger_t logger = nullptr;
    nvat_sdk_opts_t options = nullptr;
    nvat_log_callback_t log = nullptr;
    if (std::getenv("NVAT_OFFLINE_DIAGNOSTICS")) {
        log = [](nvat_log_level_t level, const char* message, const char*,
                 const char*, int, void*) {
            if (level >= NVAT_LOG_LEVEL_DEBUG) fprintf(stderr, "%s\n", message);
        };
    }
    if (nvat_logger_callback_create(&logger, log, nullptr, nullptr, nullptr) != NVAT_RC_OK ||
        nvat_sdk_opts_create(&options) != NVAT_RC_OK) return 2;
    nvat_sdk_opts_set_logger(options, logger);
    // Exercise the first-request lazy-initialization pattern, not main-thread init.
    if (std::async(std::launch::async, [&] {
            return nvat_sdk_init(options);
        }).get() != NVAT_RC_OK) return 2;
    int rc = RUN_ALL_TESTS();
    nvat_sdk_shutdown();
    nvat_sdk_opts_free(&options);
    nvat_logger_free(&logger);
    return rc;
}
