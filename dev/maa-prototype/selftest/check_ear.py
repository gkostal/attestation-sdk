#!/usr/bin/env python3
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Check the EAR printed by selftest/smoke against the documented verdict matrix.

    check_ear.py <scenario> <ear.json>

Scenarios: affirming | ocsp-missing | ocsp-revoked | corim-missing |
           ocsp-expired-enforced | ocsp-expired-not-enforced
Exit status 0 when every expectation holds.
"""

import json
import sys

ROOT, IDENTITY, ICA, BROM, LEAF = range(5)  # cert_chain is root first


def main() -> int:
    scenario, path = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8") as handle:
        ear = json.load(handle)
    gpu = ear["submods"]["gpu_0"]
    claims = gpu["ear_verifier_claims"]
    chain = claims["ear_nvidia_evidence"]["cert_chain"]
    rims = claims["ear_nvidia_rims"]
    failures = []

    def expect(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    expect(len(chain) == 5, "cert_chain has %d entries, expected 5" % len(chain))
    ocsp_certs = [chain[i] for i in (IDENTITY, ICA, BROM)]
    expect(all(rim["fetched"] for rim in rims) or scenario == "corim-missing",
           "every CoRIM should have been fetched")

    if scenario in ("affirming", "ocsp-expired-not-enforced"):
        expect(ear["ear_status"] == "affirming", "top-level ear_status %r" % ear["ear_status"])
        expect(gpu["ear_status"] == "affirming", "submod ear_status %r" % gpu["ear_status"])
        expect(claims["ear_nvidia_evidence"]["signature_verified"] is True, "signature_verified")
        for cert in ocsp_certs:
            expect(cert["ocsp_crl_status"] == "good", "ocsp_crl_status %r" % cert["ocsp_crl_status"])
            expect(cert["ocsp_response_status"] is True, "ocsp_response_status")
            expect(cert["ocsp_nonce_matches"] is False, "ocsp_nonce_matches")
        expect(all(c["ocsp_crl_response_expired"] is (scenario == "ocsp-expired-not-enforced")
                   for c in ocsp_certs), "ocsp_crl_response_expired")
    elif scenario == "ocsp-missing":
        expect(gpu["ear_status"] == "contraindicated", "submod ear_status %r" % gpu["ear_status"])
        expect(ear["ear_status"] == "contraindicated", "top-level ear_status")
        for cert in ocsp_certs:
            expect(cert["ocsp_crl_status"] == "error", "ocsp_crl_status %r" % cert["ocsp_crl_status"])
        expect(claims["ear_nvidia_evidence"]["signature_verified"] is False, "signature_verified")
    elif scenario == "ocsp-revoked":
        expect(gpu["ear_status"] == "contraindicated", "submod ear_status %r" % gpu["ear_status"])
        for cert in ocsp_certs:
            expect(cert["ocsp_crl_status"] == "revoked", "ocsp_crl_status %r" % cert["ocsp_crl_status"])
            expect(cert["ocsp_response_status"] is False, "ocsp_response_status (test responder)")
            expect(cert["cert_check_status"] == "revoked", "cert_check_status")
            expect(cert.get("revocation_reason") == "keyCompromise", "revocation_reason")
        expect(claims["ear_nvidia_evidence"]["signature_verified"] is False, "signature_verified")
    elif scenario == "corim-missing":
        expect(gpu["ear_status"] == "contraindicated", "submod ear_status %r" % gpu["ear_status"])
        expect([rim["fetched"] for rim in rims] == [True, False], "fetched flags %r" %
               [rim["fetched"] for rim in rims])
        expect(rims[1].get("error", {}).get("code") == 104, "RIM error code (NVAT_RC_RIM_NOT_FOUND)")
    elif scenario == "ocsp-expired-enforced":
        expect(gpu["ear_status"] == "contraindicated", "submod ear_status %r" % gpu["ear_status"])
        for cert in ocsp_certs:
            expect(cert["ocsp_crl_status"] == "good", "ocsp_crl_status")
            expect(cert["ocsp_crl_response_expired"] is True, "ocsp_crl_response_expired")
        expect(claims["ear_nvidia_evidence"]["signature_verified"] is False, "signature_verified")
    else:
        print("unknown scenario %s" % scenario, file=sys.stderr)
        return 2

    if failures:
        print("FAIL %-26s %s" % (scenario, "; ".join(failures)))
        return 1
    print("PASS %-26s ear_status=%s" % (scenario, ear["ear_status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
