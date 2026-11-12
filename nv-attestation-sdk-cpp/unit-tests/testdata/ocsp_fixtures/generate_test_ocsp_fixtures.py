#!/usr/bin/env python3
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generate the OCSP unit-test fixtures (idempotent). Needs python `cryptography`.

Usage: generate_test_ocsp_fixtures.py <testdata-root>

Writes <testdata-root>/ocsp_fixtures/generated/:

  rubin_ocsp_revoked/<key>.der
      REVOKED(keyCompromise) responses for the AIA-bearing certificates of the real Rubin chains
      (the golden rubin_evidence.cmw.json's embedded chain and gpu/rubinCertChain.txt, which differ
      in their BROM/leaf), signed by a throw-away TEST responder.
      NVIDIA's real certificates cannot be revoked, and against NVIDIA's real roots such a
      response is not cryptographically trusted -- the point of this fixture. Same lookup keys
      (and thisUpdate) as the committed real GOOD captures in sample_attestation_data/gpu/rubin_ocsp.

  test_ca/
      A complete test device-identity PKI -- Root -> ICA -> leaf, the ICA and leaf carrying an AIA
      OCSP responder -- plus delegated OCSP responders issued by the respective CA:
        root.pem, chain.pem (leaf, ICA, root)
        good/<key>.der            both certificates GOOD
        revoked/<key>.der         leaf REVOKED(keyCompromise), ICA GOOD
        manifest.json             lookup keys + validity window of the responses
      Injected with nvat_local_corim_verifier_set_device_identity_roots, real OpenSSL
      OCSP_basic_verify accepts / rejects these responses.
"""

import datetime
import hashlib
import json
import pathlib
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ocsp_fixture_lib as lib  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.x509 import ocsp  # noqa: E402

TEST_OCSP_URL = "http://ocsp.test.invalid"


def write_real_chain_revoked(testdata: pathlib.Path, out_dir: pathlib.Path) -> None:
    # The golden CMW embeds a different BROM/leaf than rubinCertChain.txt (same ICA and
    # Identity certificates), so cover both chains.
    gpu_dir = testdata / "sample_attestation_data"
    chains = [lib.parse_chain((gpu_dir / "gpu" / "rubinCertChain.txt").read_text())]
    chains.extend(lib.chains_from_cmw((gpu_dir / "rubin_evidence.cmw.json").read_text()))
    good_dir = gpu_dir / "gpu" / "rubin_ocsp"
    responder_key = lib.new_key()
    responder = lib.issue_cert("NVAT MAA Test OCSP Responder (NOT NVIDIA)", responder_key,
                               None, None, ocsp_signing=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for key, cert, issuer, _ in lib.ocsp_targets(chains):
        good = good_dir / (key + ".der")
        if not good.exists():
            raise SystemExit("missing real OCSP capture %s" % good)
        this_update, _, _ = lib.response_times(good.read_bytes())
        der = lib.build_ocsp_response(
            cert, issuer, ocsp.OCSPCertStatus.REVOKED, responder, responder_key, [responder],
            this_update=this_update, next_update=this_update + datetime.timedelta(days=3650),
            revocation_time=this_update - datetime.timedelta(hours=1),
            reason=x509.ReasonFlags.key_compromise)
        (out_dir / (key + ".der")).write_bytes(der)
        written += 1
    if written == 0:
        raise SystemExit("no AIA-bearing certificates found in the Rubin chains")


def write_test_ca(out_dir: pathlib.Path) -> None:
    root_key, ica_key, leaf_key = lib.new_key(), lib.new_key(), lib.new_key()
    root = lib.issue_cert("NVAT MAA Test Device Identity Root", root_key, None, None, ca=True)
    ica = lib.issue_cert("NVAT MAA Test Device ICA", ica_key, root, root_key, ca=True,
                         aia_ocsp_url=TEST_OCSP_URL)
    leaf = lib.issue_cert("NVAT MAA Test Device Leaf", leaf_key, ica, ica_key,
                          aia_ocsp_url=TEST_OCSP_URL)
    # Delegated responders: OCSP_basic_verify wants the signer issued by the CA whose
    # certificate the response is about.
    root_responder_key, ica_responder_key = lib.new_key(), lib.new_key()
    root_responder = lib.issue_cert("NVAT MAA Test OCSP Responder (Root)", root_responder_key,
                                    root, root_key, ocsp_signing=True)
    ica_responder = lib.issue_cert("NVAT MAA Test OCSP Responder (ICA)", ica_responder_key,
                                   ica, ica_key, ocsp_signing=True)

    this_update = datetime.datetime(2026, 1, 1, tzinfo=lib.UTC)
    next_update = datetime.datetime(2126, 1, 1, tzinfo=lib.UTC)
    reason = x509.ReasonFlags.key_compromise
    revoked_at = this_update - datetime.timedelta(hours=1)

    def ica_status(status: ocsp.OCSPCertStatus) -> bytes:
        return lib.build_ocsp_response(ica, root, status, root_responder, root_responder_key,
                                       [root_responder], this_update, next_update,
                                       revoked_at if status == ocsp.OCSPCertStatus.REVOKED else None,
                                       reason if status == ocsp.OCSPCertStatus.REVOKED else None)

    def leaf_status(status: ocsp.OCSPCertStatus) -> bytes:
        return lib.build_ocsp_response(leaf, ica, status, ica_responder, ica_responder_key,
                                       [ica_responder, ica], this_update, next_update,
                                       revoked_at if status == ocsp.OCSPCertStatus.REVOKED else None,
                                       reason if status == ocsp.OCSPCertStatus.REVOKED else None)

    leaf_key_name = lib.lookup_key(leaf, ica)
    ica_key_name = lib.lookup_key(ica, root)
    for sub in ("good", "revoked"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)
    (out_dir / "good" / (leaf_key_name + ".der")).write_bytes(leaf_status(ocsp.OCSPCertStatus.GOOD))
    (out_dir / "good" / (ica_key_name + ".der")).write_bytes(ica_status(ocsp.OCSPCertStatus.GOOD))
    (out_dir / "revoked" / (leaf_key_name + ".der")).write_bytes(
        leaf_status(ocsp.OCSPCertStatus.REVOKED))
    (out_dir / "revoked" / (ica_key_name + ".der")).write_bytes(ica_status(ocsp.OCSPCertStatus.GOOD))
    (out_dir / "root.pem").write_bytes(lib.pem(root))
    (out_dir / "chain.pem").write_bytes(lib.pem(leaf) + lib.pem(ica) + lib.pem(root))
    (out_dir / "manifest.json").write_text(json.dumps({
        "leaf_key": leaf_key_name,
        "ica_key": ica_key_name,
        "this_update_epoch": lib.epoch(this_update),
        "next_update_epoch": lib.epoch(next_update),
    }, indent=2) + "\n")


def input_stamp(testdata: pathlib.Path) -> str:
    """Digest of everything the generated fixtures depend on (regenerate when it changes)."""
    digest = hashlib.sha256()
    sources = [pathlib.Path(__file__), HERE / "ocsp_fixture_lib.py"]
    gpu_dir = testdata / "sample_attestation_data"
    sources += [gpu_dir / "rubin_evidence.cmw.json", gpu_dir / "gpu" / "rubinCertChain.txt"]
    sources += sorted((gpu_dir / "gpu" / "rubin_ocsp").glob("*.der"))
    for source in sources:
        digest.update(source.name.encode())
        digest.update(source.read_bytes())
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    testdata = pathlib.Path(sys.argv[1]).resolve()
    out_root = testdata / "ocsp_fixtures" / "generated"
    stamp_file = out_root / ".inputs.sha256"
    stamp = input_stamp(testdata)
    if stamp_file.exists() and stamp_file.read_text().strip() == stamp:
        return 0  # up to date
    if out_root.exists():
        shutil.rmtree(out_root)
    write_real_chain_revoked(testdata, out_root / "rubin_ocsp_revoked")
    write_test_ca(out_root / "test_ca")
    stamp_file.write_text(stamp + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
