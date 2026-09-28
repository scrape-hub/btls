#!/usr/bin/env python3
"""Renews the test certificates of btls, tokio-btls and compio-btls.

Each certificate keeps everything but its notAfter: version, serial number, names, key and
extensions stay byte for byte, only the validity and the signature change. It is signed again
with its issuer's key from the same directory. RSA PKCS #1 v1.5 signatures are deterministic, so
every run gives the same bytes, and the fingerprints the tests check change only with NOT_AFTER.
certs.pem and identity.p12 are rebuilt from the renewed certificates; identity.p12 gets new
random salts on every run, the certificates in it do not change.

Left alone on purpose: root-ca-2.pem, which x509/tests/trusted_first.rs needs expired, and
certificates the tests only parse (nid_test_cert.pem, nid_uid_test_cert.pem).

Needs Python 3 and the cryptography package (pip install cryptography). Run from the repository
root:

    python scripts/renew-test-certs.py

After changing NOT_AFTER, update the tests that check the dates and the SHA-1 fingerprints of
cert.pem and root-ca.pem, which the script prints.
"""

import base64
import datetime
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

NOT_AFTER = datetime.datetime(2126, 1, 1, tzinfo=datetime.timezone.utc)

BTLS = Path("btls/test")
TOKIO = Path("tokio-btls/tests")
COMPIO = Path("compio-btls/tests")

# (certificate, key of its issuer), issuers before the certificates they sign.
CERTIFICATES = [
    (BTLS / "root-ca.pem", BTLS / "root-ca.key"),
    (BTLS / "root-ca-cross.pem", BTLS / "root-ca-2.key"),
    (BTLS / "intermediate-ca.pem", BTLS / "root-ca.key"),
    (BTLS / "cert.pem", BTLS / "root-ca.key"),
    (BTLS / "cert-wildcard.pem", BTLS / "root-ca.key"),
    (BTLS / "cert-with-intermediate.pem", BTLS / "intermediate-ca.key"),
    (BTLS / "alt_name_cert.pem", BTLS / "root-ca.key"),
    (TOKIO / "cert.pem", TOKIO / "key.pem"),
    (COMPIO / "cert.pem", COMPIO / "key.pem"),
]

SHA256_WITH_RSA = bytes.fromhex("06092a864886f70d01010b")  # OID 1.2.840.113549.1.1.11


def read_tlv(der, pos):
    """The tag, and the start and end of the whole element and of its contents, at `pos`."""
    tag = der[pos]
    length = der[pos + 1]
    header = 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(der[pos + 2 : pos + 2 + count], "big")
        header += count
    return tag, pos, pos + header, pos + header + length


def children(der):
    """The elements in the contents of the constructed element `der`."""
    _, _, start, end = read_tlv(der, 0)
    elements = []
    pos = start
    while pos < end:
        _, element_start, _, element_end = read_tlv(der, pos)
        elements.append(der[element_start:element_end])
        pos = element_end
    return elements


def encode(tag, contents):
    length = len(contents)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        count = (length.bit_length() + 7) // 8
        header = bytes([tag, 0x80 | count]) + length.to_bytes(count, "big")
    return header + contents


def encode_time(time):
    # RFC 5280, section 4.1.2.5: UTCTime until 2049, GeneralizedTime from 2050.
    if time.year < 2050:
        return encode(0x17, time.strftime("%y%m%d%H%M%SZ").encode())
    return encode(0x18, time.strftime("%Y%m%d%H%M%SZ").encode())


def renew(cert_path, key_path):
    pem = cert_path.read_text()
    der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    tbs, signature_algorithm, _ = children(der)
    assert signature_algorithm[2:].startswith(SHA256_WITH_RSA), cert_path

    fields = children(tbs)
    # version [0] is optional; then serialNumber, signature, issuer, validity.
    validity = 4 if fields[0][0] == 0xA0 else 3
    not_before = children(fields[validity])[0]
    fields[validity] = encode(0x30, not_before + encode_time(NOT_AFTER))
    tbs = encode(0x30, b"".join(fields))

    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    signature = key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    der = encode(0x30, tbs + signature_algorithm + encode(0x03, b"\x00" + signature))

    cert = x509.load_der_x509_certificate(der)
    issuer_key = key.public_key()
    issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
    cert_path.write_text(to_pem(der), newline="\n")
    return cert


def to_pem(der):
    body = base64.b64encode(der).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def main():
    renewed = {path: renew(path, key) for path, key in CERTIFICATES}

    # The server's chain: the leaf and the root.
    (BTLS / "certs.pem").write_text(
        (BTLS / "cert.pem").read_text() + (BTLS / "root-ca.pem").read_text(), newline="\n"
    )

    # cert.pem with key.pem and root-ca.pem as its chain, password "mypass". Triple DES and an
    # HMAC-SHA1 instead of the original's 40-bit RC2, which OpenSSL 3 only reads with its legacy
    # provider.
    key = serialization.load_pem_private_key((BTLS / "key.pem").read_bytes(), password=None)
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(2048)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(b"mypass")
    )
    (BTLS / "identity.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"foobar.com",
            key,
            renewed[BTLS / "cert.pem"],
            [renewed[BTLS / "root-ca.pem"]],
            encryption,
        )
    )

    for path in (BTLS / "cert.pem", BTLS / "root-ca.pem", TOKIO / "cert.pem", COMPIO / "cert.pem"):
        der = renewed[path].public_bytes(serialization.Encoding.DER)
        print(f"{path}: SHA-1 {hashlib.sha1(der).hexdigest()}")


if __name__ == "__main__":
    main()
