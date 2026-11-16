/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Self-test for the prebuilt libnvat bundle (dev/maa-prototype). Plain C99 against the bundle's
 * nvat.h: loads the bundle's Rubin CMW and serves every CoRIM / OCSP response to libnvat from the
 * bundle's fixtures through the collateral callback (no network, no file I/O by libnvat), then
 * prints the unsigned EAR JSON on stdout. Everything else goes to stderr.
 *
 *   smoke <bundle-dir> <scenario> --time <epoch> [--enforce 0|1] [--require-nonce 0|1]
 *
 * Scenarios: affirming | ocsp-missing | ocsp-revoked | corim-missing
 *
 * It also checks symbol hygiene in a process that has its own OpenSSL.
 *  - Linux: libcrypto.so.3 is loaded (RTLD_GLOBAL) after libnvat, and EVP_sha256 must resolve to
 *    libcrypto.so.3 -- not to libnvat -- and must not be visible through libnvat's own handle.
 *  - Windows: nothing but nvat_* may be exported by nvat.dll; with --host-openssl <libcrypto dll>
 *    (e.g. MAA's OpenSSL 1.1.1) that OpenSSL is loaded and used before and after the verification,
 *    in the same process as nvat.dll's private OpenSSL 3.
 * Exit codes: 0 ok, 2 usage/IO error, 3 symbol-hygiene failure, 4 verification call failed.
 */

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define SMOKE_PATH_MAX 4096
#else
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#define SMOKE_PATH_MAX PATH_MAX
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nvat.h"

struct context {
    const char* bundle;
    const char* scenario;
    int requests;
    int not_found;
};

static unsigned char* read_file(const char* path, size_t* out_len) {
    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }
    unsigned char* data = NULL;
    size_t capacity = 0;
    size_t length = 0;
    for (;;) {
        if (length == capacity) {
            capacity = capacity ? capacity * 2 : 65536;
            unsigned char* grown = (unsigned char*)realloc(data, capacity);
            if (grown == NULL) {
                free(data);
                fclose(file);
                return NULL;
            }
            data = grown;
        }
        size_t got = fread(data + length, 1, capacity - length, file);
        length += got;
        if (got == 0) {
            break;
        }
    }
    fclose(file);
    *out_len = length;
    return data;
}

static nvat_rc_t collateral_callback(void* user_data, nvat_collateral_kind_t kind,
                                     const char* lookup_key, nvat_byte_buf_t* out) {
    struct context* ctx = (struct context*)user_data;
    char path[SMOKE_PATH_MAX];
    ctx->requests++;

    if (kind == NVAT_COLLATERAL_KIND_CORIM) {
        /* corim-missing: the driver CoRIM is not in the (simulated) store */
        if (strcmp(ctx->scenario, "corim-missing") == 0 &&
            strncmp(lookup_key, "NV_GPU_DRIVER_", 14) == 0) {
            ctx->not_found++;
            fprintf(stderr, "[callback] CORIM %s -> not found\n", lookup_key);
            return NVAT_RC_CACHE_OBJECT_NOT_FOUND;
        }
        snprintf(path, sizeof(path), "%s/fixtures/corim/%s.cbor", ctx->bundle, lookup_key);
    } else if (kind == NVAT_COLLATERAL_KIND_OCSP_RESPONSE) {
        if (strcmp(ctx->scenario, "ocsp-missing") == 0) {
            ctx->not_found++;
            fprintf(stderr, "[callback] OCSP  %s -> not found\n", lookup_key);
            return NVAT_RC_CACHE_OBJECT_NOT_FOUND;
        }
        snprintf(path, sizeof(path), "%s/fixtures/%s/%s.der", ctx->bundle,
                 strcmp(ctx->scenario, "ocsp-revoked") == 0 ? "ocsp-revoked" : "ocsp", lookup_key);
    } else {
        return NVAT_RC_BAD_ARGUMENT;
    }

    size_t length = 0;
    unsigned char* data = read_file(path, &length);
    if (data == NULL) {
        ctx->not_found++;
        fprintf(stderr, "[callback] %s %s -> not found\n",
                kind == NVAT_COLLATERAL_KIND_CORIM ? "CORIM" : "OCSP ", lookup_key);
        return NVAT_RC_CACHE_OBJECT_NOT_FOUND;
    }
    fprintf(stderr, "[callback] %s %s -> %zu bytes\n",
            kind == NVAT_COLLATERAL_KIND_CORIM ? "CORIM" : "OCSP ", lookup_key, length);
    nvat_rc_t rc = nvat_byte_buf_create(out, data, length);
    free(data);
    return rc;
}

static void log_callback(nvat_log_level_t level, const char* message, const char* filename,
                         const char* function, int line, void* user_data) {
    (void)function;
    (void)user_data;
    fprintf(stderr, "[nvat:%d] %s (%s:%d)\n", (int)level, message, filename, line);
}

static bool should_log_callback(nvat_log_level_t level, const char* filename, const char* function,
                                int line, void* user_data) {
    (void)filename;
    (void)function;
    (void)line;
    (void)user_data;
    return level >= NVAT_LOG_LEVEL_ERROR;
}

#ifdef _WIN32
/* Nothing but nvat_* may be exported (the DLL exports only what nvat.h declares). */
static int check_symbol_hygiene(void) {
    int failed = 0;
    HMODULE nvat = GetModuleHandleA("nvat.dll");
    if (nvat == NULL) {
        fprintf(stderr, "[symbols] nvat.dll is not loaded?\n");
        return 3;
    }
    const char* hidden[] = {"EVP_sha256", "OPENSSL_init_crypto", "curl_easy_init",
                            "xmlParseMemory", "zcbor_new_decode_state", "zcbor_strnlen",
                            "regorus_engine_new"};
    for (size_t i = 0; i < sizeof(hidden) / sizeof(hidden[0]); ++i) {
        if (GetProcAddress(nvat, hidden[i]) != NULL) {
            fprintf(stderr, "[symbols] FAIL: nvat.dll exports %s\n", hidden[i]);
            failed = 1;
        }
    }
    if (GetProcAddress(nvat, "nvat_local_corim_verifier_verify_cmw_ex") == NULL) {
        fprintf(stderr, "[symbols] FAIL: nvat_local_corim_verifier_verify_cmw_ex not exported\n");
        failed = 1;
    }
    return failed ? 3 : 0;
}

/* The host's own OpenSSL (any 1.1.1 or 3.x libcrypto DLL), used through its exports only. */
typedef const char* (*openssl_version_fn)(int);
typedef const void* (*evp_sha256_fn)(void);
typedef int (*evp_digest_fn)(const void*, size_t, unsigned char*, unsigned int*, const void*, void*);

static HMODULE g_host_crypto = NULL;

static int host_openssl_sha256(const char* when) {
    if (g_host_crypto == NULL) {
        return 0;
    }
    openssl_version_fn version = (openssl_version_fn)(void (*)(void))GetProcAddress(g_host_crypto, "OpenSSL_version");
    evp_sha256_fn sha256 = (evp_sha256_fn)(void (*)(void))GetProcAddress(g_host_crypto, "EVP_sha256");
    evp_digest_fn digest = (evp_digest_fn)(void (*)(void))GetProcAddress(g_host_crypto, "EVP_Digest");
    if (version == NULL || sha256 == NULL || digest == NULL) {
        fprintf(stderr, "[symbols] FAIL: the host OpenSSL lacks OpenSSL_version/EVP_sha256/EVP_Digest\n");
        return 3;
    }
    /* SHA-256("abc") */
    static const unsigned char expected[4] = {0xba, 0x78, 0x16, 0xbf};
    unsigned char md[64];
    unsigned int md_len = 0;
    if (digest("abc", 3, md, &md_len, sha256(), NULL) != 1 || md_len != 32 ||
        memcmp(md, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "[symbols] FAIL: the host OpenSSL (%s) computed a wrong SHA-256 %s\n", version(0), when);
        return 3;
    }
    fprintf(stderr, "[symbols] host OpenSSL works %s: %s\n", when, version(0));
    return 0;
}

static int load_host_openssl(const char* dll) {
    g_host_crypto = LoadLibraryExA(dll, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (g_host_crypto == NULL) {
        fprintf(stderr, "[symbols] FAIL: cannot load the host OpenSSL %s (error %lu)\n", dll, GetLastError());
        return 3;
    }
    return host_openssl_sha256("before nvat_sdk_init");
}
#else
static int check_symbol_hygiene(void) {
    int failed = 0;

    void* nvat = dlopen("libnvat.so.2", RTLD_NOW | RTLD_NOLOAD);
    if (nvat == NULL) {
        fprintf(stderr, "[symbols] libnvat.so.2 is not loaded?\n");
        return 3;
    }
    /* Nothing but nvat_* may be visible through libnvat's own handle. */
    const char* hidden[] = {"EVP_sha256", "OPENSSL_init_crypto", "curl_easy_init",
                            "xmlParseMemory", "zcbor_new_decode_state", "spdlog_info"};
    for (size_t i = 0; i < sizeof(hidden) / sizeof(hidden[0]); ++i) {
        if (dlsym(nvat, hidden[i]) != NULL) {
            fprintf(stderr, "[symbols] FAIL: libnvat exports %s\n", hidden[i]);
            failed = 1;
        }
    }
    if (dlsym(nvat, "nvat_local_corim_verifier_verify_cmw_ex") == NULL) {
        fprintf(stderr, "[symbols] FAIL: nvat_local_corim_verifier_verify_cmw_ex not exported\n");
        failed = 1;
    }

    /* A host with its own OpenSSL: load it after libnvat and make sure it wins. */
    void* crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_GLOBAL);
    if (crypto == NULL) {
        fprintf(stderr, "[symbols] note: libcrypto.so.3 not present in this image; "
                        "interposition check skipped\n");
    } else {
        void* sym = dlsym(RTLD_DEFAULT, "EVP_sha256");
        Dl_info info;
        if (sym == NULL || dladdr(sym, &info) == 0 || info.dli_fname == NULL ||
            strstr(info.dli_fname, "libcrypto") == NULL) {
            fprintf(stderr, "[symbols] FAIL: EVP_sha256 resolves to %s\n",
                    sym && dladdr(sym, &info) && info.dli_fname ? info.dli_fname : "(null)");
            failed = 1;
        } else {
            fprintf(stderr, "[symbols] EVP_sha256 resolves to %s (host OpenSSL, not libnvat)\n",
                    info.dli_fname);
        }
    }
    return failed ? 3 : 0;
}
#endif

int main(int argc, char** argv) {
    if (argc < 5 || strcmp(argv[3], "--time") != 0) {
        fprintf(stderr, "usage: %s <bundle-dir> <affirming|ocsp-missing|ocsp-revoked|corim-missing> "
                        "--time <epoch> [--enforce 0|1] [--require-nonce 0|1] [--host-openssl <dll>]\n", argv[0]);
        return 2;
    }
    struct context ctx = {argv[1], argv[2], 0, 0};
    long long verification_time = atoll(argv[4]);
    int enforce = 1;
    int require_nonce = 0;
    const char* host_openssl = NULL;
    for (int i = 5; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--enforce") == 0) {
            enforce = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "--require-nonce") == 0) {
            require_nonce = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "--host-openssl") == 0) {
            host_openssl = argv[i + 1];
        }
    }

#ifdef _WIN32
    if (host_openssl != NULL && load_host_openssl(host_openssl) != 0) {
        return 3;
    }
#else
    if (host_openssl != NULL) {
        fprintf(stderr, "--host-openssl is Windows only\n");
        return 2;
    }
#endif

    /* libnvat's logger, routed to stderr (errors only). */
    nvat_logger_t logger = NULL;
    nvat_sdk_opts_t opts = NULL;
    if (nvat_logger_callback_create(&logger, log_callback, should_log_callback, NULL, NULL) !=
            NVAT_RC_OK ||
        nvat_sdk_opts_create(&opts) != NVAT_RC_OK) {
        return 2;
    }
    nvat_sdk_opts_set_logger(opts, logger);
    if (nvat_sdk_init(opts) != NVAT_RC_OK) {
        fprintf(stderr, "nvat_sdk_init failed\n");
        return 2;
    }

    char cmw_path[SMOKE_PATH_MAX];
    snprintf(cmw_path, sizeof(cmw_path), "%s/fixtures/cmw/rubin_evidence.cmw.json", ctx.bundle);
    size_t cmw_len = 0;
    unsigned char* cmw = read_file(cmw_path, &cmw_len);
    if (cmw == NULL) {
        fprintf(stderr, "cannot read %s\n", cmw_path);
        return 2;
    }

    nvat_corim_store_t store = NULL;
    nvat_local_corim_verifier_t verifier = NULL;
    nvat_verify_call_options_t options = NULL;
    nvat_str_t ear_json = NULL;
    if (nvat_corim_store_create(&store, NULL, NULL) != NVAT_RC_OK ||
        /* no OCSP client: revocation is served entirely by the collateral callback */
        nvat_local_corim_verifier_create(&verifier, &store, NULL) != NVAT_RC_OK ||
        nvat_local_corim_verifier_set_verify_rim_signature(verifier, false) != NVAT_RC_OK ||
        nvat_local_corim_verifier_set_verify_revocation(verifier, true) != NVAT_RC_OK ||
        nvat_verify_call_options_create(&options) != NVAT_RC_OK ||
        nvat_verify_call_options_set_collateral_callback(options, collateral_callback, &ctx) !=
            NVAT_RC_OK ||
        nvat_verify_call_options_set_require_ocsp_nonce(options, require_nonce != 0) !=
            NVAT_RC_OK ||
        nvat_verify_call_options_set_enforce_ocsp_next_update(options, enforce != 0) !=
            NVAT_RC_OK ||
        nvat_verify_call_options_set_verification_time(options, verification_time) !=
            NVAT_RC_OK) {
        fprintf(stderr, "setup failed\n");
        return 2;
    }

    nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw_ex(
        verifier, cmw, cmw_len, NVAT_CMW_FORMAT_JSON, options, NULL, NULL, &ear_json);
    fprintf(stderr, "[smoke] scenario=%s rc=%d (%s) collateral requests=%d not-found=%d\n",
            ctx.scenario, (int)rc, nvat_rc_to_string(rc), ctx.requests, ctx.not_found);
    if (rc != NVAT_RC_OK || ear_json == NULL) {
        return 4;
    }
    char* data = NULL;
    size_t length = 0;
    nvat_str_get_data(ear_json, &data);
    nvat_str_length(ear_json, &length);
    fwrite(data, 1, length, stdout);
    fputc('\n', stdout);

    int hygiene = check_symbol_hygiene();
#ifdef _WIN32
    if (hygiene == 0) {
        hygiene = host_openssl_sha256("after the verification");
    }
#endif

    nvat_str_free(&ear_json);
    nvat_verify_call_options_free(&options);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
    free(cmw);
    nvat_sdk_opts_free(&opts);
    nvat_logger_free(&logger);
    return hygiene;
}
