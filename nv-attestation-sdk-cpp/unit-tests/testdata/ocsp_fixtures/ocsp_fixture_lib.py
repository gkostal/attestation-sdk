# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for building and naming OCSP fixtures (python `cryptography`).

Used by
  * generate_test_ocsp_fixtures.py  -- unit-test fixtures (test CA chain, revoked variants)
  * dev/maa-prototype/capture_ocsp.py -- live capture of NVIDIA responses for the MAA bundle

`lookup_key()` is the single Python definition of the collateral lookup key that libnvat
asks for (NVAT_COLLATERAL_KIND_OCSP_RESPONSE, see nvat.h):

    "<issuerKeyHash lower hex>_<serial lower hex, no leading zeros>"

with issuerKeyHash being the SHA-256 CertID.issuerKeyHash of the (subject, issuer) pair.
"""

import base64
import datetime
import json
import re
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import (AuthorityInformationAccessOID, ExtendedKeyUsageOID,
                                   NameOID)

UTC = datetime.timezone.utc
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def parse_chain(pem_text: str) -> List[x509.Certificate]:
    """Certificates of a PEM bundle, in file order (leaf first, root last)."""
    return [x509.load_pem_x509_certificate(m.encode()) for m in PEM_RE.findall(pem_text)]


def ocsp_aia_url(cert: x509.Certificate) -> Optional[str]:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.OCSP:
            return desc.access_location.value
    return None


def chains_from_cmw(cmw_text: str) -> List[List[x509.Certificate]]:
    """Device certificate chains embedded in a CMW collection (one per evidence item)."""
    root = json.loads(cmw_text)
    chains = []
    for label, item in root.items():
        if not isinstance(item, dict) or "certificate" not in item:
            continue
        data = item["certificate"][1]
        pem_text = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode()
        chains.append(parse_chain(pem_text))
    return chains


def ocsp_targets(chains: List[List[x509.Certificate]]):
    """Unique (key, cert, issuer, url) for every AIA-bearing, non-root certificate."""
    seen = set()
    for chain in chains:
        for index in range(len(chain) - 1):
            cert, issuer = chain[index], chain[index + 1]
            url = ocsp_aia_url(cert)
            if url is None:
                continue
            key = lookup_key(cert, issuer)
            if key in seen:
                continue
            seen.add(key)
            yield key, cert, issuer, url


def lookup_key(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256()).build()
    return "%s_%x" % (request.issuer_key_hash.hex(), request.serial_number)


def ocsp_request_der(cert: x509.Certificate, issuer: x509.Certificate) -> bytes:
    """SHA-256 CertID request without a nonce extension (what a cached response answers)."""
    request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256()).build()
    return request.public_bytes(serialization.Encoding.DER)


def response_times(der: bytes) -> Tuple[datetime.datetime, datetime.datetime, datetime.datetime]:
    """(this_update, next_update, produced_at), timezone-aware UTC."""
    response = ocsp.load_der_ocsp_response(der)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError("OCSP response status %s" % response.response_status)

    def utc(name: str) -> datetime.datetime:
        # cryptography >= 43 offers timezone-aware *_utc properties; older versions
        # return naive UTC datetimes.
        value = getattr(response, name + "_utc", None)
        if value is None:
            value = getattr(response, name)
            value = value if value.tzinfo else value.replace(tzinfo=UTC)
        return value

    return utc("this_update"), utc("next_update"), utc("produced_at")


def epoch(value: datetime.datetime) -> int:
    return int(value.timestamp())


# --------------------------------------------------------------------------- test PKI

def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NVAT MAA Test PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def issue_cert(subject_cn: str, subject_key, issuer_cert: Optional[x509.Certificate], issuer_key,
               *, ca: bool = False, ocsp_signing: bool = False,
               aia_ocsp_url: Optional[str] = None) -> x509.Certificate:
    """Issue a test certificate (self-signed when issuer_cert is None)."""
    subject = _name(subject_cn)
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer_cert.subject if issuer_cert is not None else subject)
               .public_key(subject_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=UTC))
               .not_valid_after(datetime.datetime(2099, 12, 31, tzinfo=UTC))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
                              critical=False))
    issuer_public = (issuer_cert.public_key() if issuer_cert is not None
                     else subject_key.public_key())
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public),
                                    critical=False)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                      crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
    if ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
        builder = builder.add_extension(x509.OCSPNoCheck(), critical=False)
    if aia_ocsp_url is not None:
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   x509.UniformResourceIdentifier(aia_ocsp_url))]), critical=False)
    return builder.sign(issuer_key if issuer_cert is not None else subject_key, hashes.SHA384())


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def build_ocsp_response(cert: x509.Certificate, issuer: x509.Certificate,
                        status: ocsp.OCSPCertStatus,
                        responder_cert: x509.Certificate, responder_key,
                        embedded_certs: List[x509.Certificate],
                        this_update: datetime.datetime, next_update: datetime.datetime,
                        revocation_time: Optional[datetime.datetime] = None,
                        reason: Optional[x509.ReasonFlags] = None) -> bytes:
    """A DER OCSPResponse for (cert, issuer) with a SHA-256 CertID, signed by the responder."""
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=cert, issuer=issuer, algorithm=hashes.SHA256(), cert_status=status,
        this_update=this_update, next_update=next_update,
        revocation_time=revocation_time, revocation_reason=reason)
    builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    builder = builder.certificates(embedded_certs)
    return builder.sign(responder_key, hashes.SHA384()).public_bytes(serialization.Encoding.DER)
