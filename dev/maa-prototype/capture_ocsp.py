#!/usr/bin/env python3
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Capture live OCSP responses for the AIA-bearing certificates of device certificate chains.

For every certificate of the given chains that has an AIA OCSP responder (and an issuer later in
the chain) this POSTs an OCSP request -- SHA-256 CertID, *no nonce* -- to the responder and stores
the raw DER OCSPResponse as <issuerKeyHash hex>_<serial hex>.der. That file name is exactly
the lookup key libnvat requests through nvat_collateral_cb_t
(NVAT_COLLATERAL_KIND_OCSP_RESPONSE), so a host can seed these files into its collateral
store and have them served back verbatim.

Chains come from --chain (a PEM bundle, leaf first) and/or --cmw (the certificate records of a CMW
collection); both may be repeated. Note that the golden rubin_evidence.cmw.json embeds a
different GR100 BROM/leaf than sample_attestation_data/gpu/rubinCertChain.txt (same ICA and
Identity certificates), so the bundle captures both.

Offline tolerance: if the responder cannot be reached but <out-dir>/<key>.der already exists
from an earlier capture, that file is kept (with a warning); otherwise the run fails.

Optionally (--revoked-dir) also writes a REVOKED(keyCompromise) variant for the same keys. NVIDIA's
real certificates are not revoked and their signing keys are not available, so the variants
are signed by a throw-away TEST responder; against NVIDIA's real roots they are not
cryptographically trusted, which libnvat reports as ocsp_crl_status "revoked" with
ocsp_response_status false (see dev/maa-prototype/README.md).

Requires the python `cryptography` package; network access only for the live capture.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
TESTDATA = REPO / "nv-attestation-sdk-cpp" / "unit-tests" / "testdata"
sys.path.insert(0, str(TESTDATA / "ocsp_fixtures"))

import ocsp_fixture_lib as lib  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.x509 import ocsp  # noqa: E402

DEFAULT_CHAIN = TESTDATA / "sample_attestation_data" / "gpu" / "rubinCertChain.txt"
DEFAULT_CMW = TESTDATA / "sample_attestation_data" / "rubin_evidence.cmw.json"


def fetch(url: str, request_der: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(
        url, data=request_der, method="POST",
        headers={"Content-Type": "application/ocsp-request",
                 "Accept": "application/ocsp-response"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError("HTTP %d from %s" % (response.status, url))
        return response.read()


def describe(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--chain", type=pathlib.Path, action="append", default=[],
                        help="PEM device certificate chain, leaf first (repeatable)")
    parser.add_argument("--cmw", type=pathlib.Path, action="append", default=[],
                        help="CMW collection whose embedded certificate chains are used (repeatable)")
    parser.add_argument("--out-dir", type=pathlib.Path, required=True,
                        help="where the GOOD <key>.der responses go (also the offline cache)")
    parser.add_argument("--revoked-dir", type=pathlib.Path,
                        help="also write REVOKED test-responder variants here")
    parser.add_argument("--index", type=pathlib.Path, help="write a JSON index of the captures")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    if not args.chain and not args.cmw:
        args.chain, args.cmw = [DEFAULT_CHAIN], [DEFAULT_CMW]

    chains = [lib.parse_chain(path.read_text()) for path in args.chain]
    for path in args.cmw:
        chains.extend(lib.chains_from_cmw(path.read_text()))
    args.out_dir.mkdir(parents=True, exist_ok=True)

    entries = []
    targets = []
    failures = 0
    for key, cert, issuer, url in lib.ocsp_targets(chains):
        targets.append((key, cert, issuer))
        target = args.out_dir / (key + ".der")
        source = "live"
        try:
            der = fetch(url, lib.ocsp_request_der(cert, issuer), args.timeout)
            lib.response_times(der)  # must parse as a SUCCESSFUL response
            target.write_bytes(der)
        except (urllib.error.URLError, OSError, RuntimeError, ValueError) as error:
            if target.exists():
                der = target.read_bytes()
                source = "cached"
                print("warn   %s unreachable (%s); keeping earlier capture" % (url, error))
            else:
                print("error: no live response for %s and nothing cached: %s" %
                      (describe(cert), error), file=sys.stderr)
                failures += 1
                continue
        response = ocsp.load_der_ocsp_response(der)
        this_update, next_update, produced_at = lib.response_times(der)
        print("%-6s %-58s %s status=%s thisUpdate=%s nextUpdate=%s" %
              (source, describe(cert)[:58], key, response.certificate_status.name,
               this_update.isoformat(), next_update.isoformat()))
        entries.append({
            "lookup_key": key,
            "file": key + ".der",
            "subject": describe(cert),
            "issuer": describe(issuer),
            "serial_hex": "%x" % cert.serial_number,
            "responder_url": url,
            "status": response.certificate_status.name.lower(),
            "this_update": this_update.isoformat(),
            "next_update": next_update.isoformat(),
            "produced_at": produced_at.isoformat(),
            "this_update_epoch": lib.epoch(this_update),
            "next_update_epoch": lib.epoch(next_update),
            "sha256": hashlib.sha256(der).hexdigest(),
            "source": source,
        })
    if failures or not entries:
        return 1

    if args.revoked_dir is not None:
        args.revoked_dir.mkdir(parents=True, exist_ok=True)
        responder_key = lib.new_key()
        responder = lib.issue_cert("NVAT MAA Test OCSP Responder (NOT NVIDIA)", responder_key,
                                   None, None, ocsp_signing=True)
        by_key = {entry["lookup_key"]: entry for entry in entries}
        for key, cert, issuer in targets:
            if key not in by_key:
                continue
            this_update = datetime.datetime.fromisoformat(by_key[key]["this_update"])
            der = lib.build_ocsp_response(
                cert, issuer, ocsp.OCSPCertStatus.REVOKED, responder, responder_key, [responder],
                this_update=this_update, next_update=this_update + datetime.timedelta(days=3650),
                revocation_time=this_update - datetime.timedelta(hours=1),
                reason=x509.ReasonFlags.key_compromise)
            (args.revoked_dir / (key + ".der")).write_bytes(der)
        (args.revoked_dir / "test-responder.pem").write_bytes(lib.pem(responder))
        print("wrote %d REVOKED test-responder variants to %s" % (len(by_key), args.revoked_dir))

    if args.index is not None:
        args.index.parent.mkdir(parents=True, exist_ok=True)
        args.index.write_text(json.dumps({
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "sources": [p.name for p in args.chain] + [p.name for p in args.cmw],
            "responses": entries,
        }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
