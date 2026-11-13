// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Test-only CA and signed Rubin-shaped transcript. Never a production trust root.
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <cctype>
#include <ctime>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>
#include <sys/stat.h>

static void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
static std::string read(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    check(in.good(), path.c_str());
    return {std::istreambuf_iterator<char>(in), {}};
}
static void write(const std::string& path, const std::string& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), bytes.size());
    check(out.good(), path.c_str());
}
static std::string b64(const std::string& bytes) {
    std::string out(4 * ((bytes.size() + 2) / 3), '\0');
    out.resize(EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
        reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
    for (char& c : out) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}
static std::string unb64(std::string text) {
    for (char& c : text) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    size_t padding = (4 - text.size() % 4) % 4;
    text.append(padding, '=');
    std::string out(text.size(), '\0');
    int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
        reinterpret_cast<const unsigned char*>(text.data()), text.size());
    check(n >= 0, "base64");
    // Account for any padding already present in the input.
    size_t count = 0;
    for (auto it = text.rbegin(); it != text.rend() && *it == '='; ++it) ++count;
    out.resize(n - count);
    return out;
}
static EVP_PKEY* key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    check(ctx && EVP_PKEY_keygen_init(ctx) == 1, "keygen init");
    check(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) == 1, "curve");
    EVP_PKEY* out = nullptr;
    check(EVP_PKEY_keygen(ctx, &out) == 1, "keygen");
    EVP_PKEY_CTX_free(ctx);
    return out;
}
static void extension(X509* cert, X509* issuer, int nid, const char* value) {
    int idx;
    while ((idx = X509_get_ext_by_NID(cert, nid, -1)) >= 0)
        X509_EXTENSION_free(X509_delete_ext(cert, idx));
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
    check(ext && X509_add_ext(cert, ext, -1) == 1, "extension");
    X509_EXTENSION_free(ext);
}
static void dates(X509* cert) {
    check(ASN1_TIME_set_string(X509_getm_notBefore(cert), "20260101000000Z") == 1, "notBefore");
    check(ASN1_TIME_set_string(X509_getm_notAfter(cert), "20400101000000Z") == 1, "notAfter");
}
static std::string pem(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    check(bio && PEM_write_bio_X509(bio, cert) == 1, "PEM");
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string out(data, len);
    BIO_free(bio);
    return out;
}
static std::string hex(const unsigned char* bytes, size_t len) {
    const char* digits = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        out += digits[bytes[i] >> 4]; out += digits[bytes[i] & 15];
    }
    return out;
}
static std::string ocsp(const std::string& dir, X509* subject, X509* issuer,
                         EVP_PKEY* issuer_key, bool revoked) {
    OCSP_CERTID* id = OCSP_cert_to_id(EVP_sha256(), subject, issuer);
    check(id, "CertID");
    ASN1_OCTET_STRING* hash = nullptr;
    ASN1_INTEGER* serial = nullptr;
    check(OCSP_id_get0_info(nullptr, nullptr, &hash, &serial, id) == 1, "CertID info");
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* serial_hex = BN_bn2hex(bn);
    std::string serial_text(serial_hex);
    for (char& c : serial_text) c = static_cast<char>(std::tolower(c));
    std::string lookup = hex(ASN1_STRING_get0_data(hash), ASN1_STRING_length(hash)) +
                         "_" + serial_text;
    OPENSSL_free(serial_hex); BN_free(bn);
    ASN1_TIME* thisupd = ASN1_TIME_new();
    ASN1_TIME* nextupd = ASN1_TIME_new();
    ASN1_TIME* revtime = ASN1_TIME_new();
    ASN1_TIME_set_string(thisupd, "20261113000000Z");
    ASN1_TIME_set_string(nextupd, "20350101000000Z");
    ASN1_TIME_set_string(revtime, "20261112000000Z");
    OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
    check(OCSP_basic_add1_status(basic, id,
        revoked ? V_OCSP_CERTSTATUS_REVOKED : V_OCSP_CERTSTATUS_GOOD,
        revoked ? OCSP_REVOKED_STATUS_KEYCOMPROMISE : 0,
        revoked ? revtime : nullptr, thisupd, nextupd), "SingleResponse");
    // producedAt comes from the signing clock; the committed fixture metadata
    // pins verification after it. Regeneration is deliberate, not test startup.
    check(OCSP_basic_sign(basic, issuer, issuer_key, EVP_sha384(), nullptr, 0) == 1, "OCSP sign");
    OCSP_RESPONSE* response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    unsigned char* data = nullptr;
    int len = i2d_OCSP_RESPONSE(response, &data);
    check(len > 0, "OCSP encode");
    write(dir + "/" + lookup + ".der", std::string(reinterpret_cast<char*>(data), len));
    OPENSSL_free(data); OCSP_RESPONSE_free(response); OCSP_BASICRESP_free(basic);
    OCSP_CERTID_free(id); ASN1_TIME_free(thisupd); ASN1_TIME_free(nextupd); ASN1_TIME_free(revtime);
    return lookup;
}
int main(int argc, char** argv) {
    try {
        check(argc == 3, "usage: generate-offline-fixtures <testdata-root> <output-dir>");
        const std::string testdata = argv[1], out = argv[2];
        mkdir(out.c_str(), 0755);
        mkdir((out + "/synthetic-good").c_str(), 0755);
        mkdir((out + "/synthetic-revoked").c_str(), 0755);
        auto cmw = nlohmann::json::parse(read(testdata + "/sample_attestation_data/rubin_evidence.cmw.json"));
        std::string original = unb64(cmw["gpu_0"]["certificate"][1].get<std::string>());
        write(out + "/rubin-cmw-cert-chain.pem", original);
        BIO* chain_bio = BIO_new_mem_buf(original.data(), original.size());
        X509* leaf = PEM_read_bio_X509(chain_bio, nullptr, nullptr, nullptr);
        X509* ica = PEM_read_bio_X509(chain_bio, nullptr, nullptr, nullptr);
        check(leaf && ica, "Rubin certs");
        BIO_free(chain_bio);
        EVP_PKEY* root_key = key(); EVP_PKEY* ica_key = key(); EVP_PKEY* leaf_key = key();
        X509* root = X509_new();
        X509_set_version(root, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(root), 1);
        X509_NAME* name = X509_get_subject_name(root);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("NVAT OFFLINE TEST ROOT - NOT PRODUCTION"), -1, -1, 0);
        X509_set_issuer_name(root, name);
        X509_set_pubkey(root, root_key);
        dates(root);
        extension(root, root, NID_basic_constraints, "critical,CA:TRUE");
        extension(root, root, NID_key_usage, "critical,keyCertSign,cRLSign");
        extension(root, root, NID_subject_key_identifier, "hash");
        check(X509_sign(root, root_key, EVP_sha384()) > 0, "root sign");
        X509_set_issuer_name(ica, X509_get_subject_name(root));
        X509_set_pubkey(ica, ica_key);
        ASN1_INTEGER_set(X509_get_serialNumber(ica), 2);
        dates(ica);
        extension(ica, root, NID_subject_key_identifier, "hash");
        extension(ica, root, NID_authority_key_identifier, "keyid:always");
        check(X509_sign(ica, root_key, EVP_sha384()) > 0, "ICA sign");
        X509_set_issuer_name(leaf, X509_get_subject_name(ica));
        X509_set_pubkey(leaf, leaf_key);
        ASN1_INTEGER_set(X509_get_serialNumber(leaf), 3);
        dates(leaf);
        extension(leaf, ica, NID_subject_key_identifier, "hash");
        extension(leaf, ica, NID_authority_key_identifier, "keyid:always");
        extension(leaf, ica, NID_info_access, "OCSP;URI:http://ocsp.invalid.test/");
        check(X509_sign(leaf, ica_key, EVP_sha384()) > 0, "leaf sign");
        write(out + "/test-root.pem", pem(root));
        std::string transcript = unb64(cmw["gpu_0"]["evidence"][1].get<std::string>());
        check(transcript.size() > 96, "SPDM transcript");
        transcript.resize(transcript.size() - 96);
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        check(EVP_DigestSignInit(md, nullptr, EVP_sha384(), nullptr, leaf_key) == 1, "SPDM sign init");
        size_t siglen = 0;
        check(EVP_DigestSign(md, nullptr, &siglen,
            reinterpret_cast<const unsigned char*>(transcript.data()), transcript.size()) == 1, "SPDM size");
        std::vector<unsigned char> signature(siglen);
        check(EVP_DigestSign(md, signature.data(), &siglen,
            reinterpret_cast<const unsigned char*>(transcript.data()), transcript.size()) == 1, "SPDM sign");
        const unsigned char* p = signature.data();
        ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, siglen);
        check(sig, "ECDSA decode");
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(sig, &r, &s);
        unsigned char raw[96];
        check(BN_bn2binpad(r, raw, 48) == 48 && BN_bn2binpad(s, raw + 48, 48) == 48, "ECDSA raw");
        transcript.append(reinterpret_cast<char*>(raw), sizeof(raw));
        cmw["gpu_0"]["evidence"][1] = b64(transcript);
        cmw["gpu_0"]["certificate"][1] = b64(pem(leaf) + pem(ica) + pem(root));
        write(out + "/synthetic_evidence.cmw.json", cmw.dump(2) + "\n");
        std::string leaf_lookup = ocsp(out + "/synthetic-good", leaf, ica, ica_key, false);
        std::string ica_lookup = ocsp(out + "/synthetic-good", ica, root, root_key, false);
        ocsp(out + "/synthetic-revoked", leaf, ica, ica_key, true);
        ocsp(out + "/synthetic-revoked", ica, root, root_key, false);
        nlohmann::json metadata = {
            {"verification_time", time(nullptr) + 60},
            {"synthetic_leaf_key", leaf_lookup}, {"synthetic_ica_key", ica_lookup},
            {"synthetic_next_update", 2051222400},
            {"warning", "Test CA only; do not install as a production trust anchor."}};
        write(out + "/synthetic-metadata.json", metadata.dump(2) + "\n");
        ECDSA_SIG_free(sig); EVP_MD_CTX_free(md);
        X509_free(root); X509_free(ica); X509_free(leaf);
        EVP_PKEY_free(root_key); EVP_PKEY_free(ica_key); EVP_PKEY_free(leaf_key);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
