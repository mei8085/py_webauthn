"""Helpers for loading X.509 certificates out of attestation statements.

Attestation certificates encountered in the wild occasionally violate ASN.1 DER rules (for
example by explicitly encoding the DEFAULT value of an extension's ``critical`` field). The
``cryptography`` library intentionally rejects such certificates. When that happens we fall back
to a lenient BER decode with ``pyasn1`` and re-encode the parsed structure back to valid DER
before handing it to ``cryptography`` again.

Nothing in this module treats a parseable-but-unknown field as a verified security attribute:
callers must always locate a specific, documented extension OID and validate its value
themselves.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from OpenSSL.crypto import FILETYPE_ASN1, X509, load_certificate
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules.rfc5280 import Certificate as Pyasn1Certificate

from .exceptions import InvalidCertificateChain


@dataclass
class ParsedCertificate:
    """A parsed attestation certificate paired with its original x5c bytes.

    Attributes:
        `cert`: A ``cryptography`` certificate for field and extension checks. For certificates
            that violate DER this is produced via a lenient BER decode followed by a re-encode, so
            its serialized bytes may differ from the wire bytes.
        `original_bytes`: The exact DER bytes received in the attestation statement. These are
            preserved for OpenSSL chain and signature verification, which must check the
            certificate exactly as the issuer signed it.
    """

    cert: x509.Certificate
    original_bytes: bytes


def load_x509_certificate(cert_bytes: bytes) -> ParsedCertificate:
    """Load a DER-encoded certificate, tolerating common BER encoding violations.

    Raises:
        `InvalidCertificateChain` if the bytes cannot be parsed as an X.509 certificate by any
        available decoder.
    """
    try:
        cert = x509.load_der_x509_certificate(cert_bytes)
    except ValueError:
        # Some certificates encode extension fields (notably Extension.critical = FALSE) in a
        # way that violates DER. Decode leniently with BER and re-encode to valid DER so that
        # cryptography's stricter parser can still inspect the certificate fields. Signature
        # verification still uses the untouched original bytes.
        try:
            parsed_cert, trailing_bytes = ber_decode(
                cert_bytes, asn1Spec=Pyasn1Certificate()
            )
        except Exception as exc:
            raise InvalidCertificateChain(
                "Could not parse certificate as DER or BER. See __cause__ for more info"
            ) from exc

        if trailing_bytes:
            raise InvalidCertificateChain(
                "Certificate contained trailing bytes after BER decoding"
            )

        try:
            cert = x509.load_der_x509_certificate(der_encode(parsed_cert))
        except Exception as exc:
            raise InvalidCertificateChain(
                "Could not load re-encoded certificate. See __cause__ for more info"
            ) from exc

    return ParsedCertificate(cert=cert, original_bytes=cert_bytes)


def load_x509_certificates(x5c: List[bytes]) -> List[ParsedCertificate]:
    """Load every certificate in an x5c list, preserving order and original bytes."""
    return [load_x509_certificate(cert_bytes) for cert_bytes in x5c]


def to_openssl_x509(parsed: ParsedCertificate) -> X509:
    """Load the original certificate bytes into a pyOpenSSL X509 for chain verification.

    The original bytes are used rather than any BER re-encoding so that signature verification
    operates on exactly what the issuer signed.
    """
    try:
        return load_certificate(FILETYPE_ASN1, parsed.original_bytes)
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not prepare certificate for chain validation. See __cause__ for more info"
        ) from exc


def certificate_name_der(parsed: ParsedCertificate) -> bytes:
    """Return the DER-encoded Name of a certificate for subject/issuer equality checks."""
    return parsed.cert.subject.public_bytes()


def certificate_issuer_der(parsed: ParsedCertificate) -> bytes:
    """Return the DER-encoded issuer Name of a certificate."""
    return parsed.cert.issuer.public_bytes()


def get_unrecognized_extension_value(
    parsed: ParsedCertificate,
    oid: ObjectIdentifier,
) -> Optional[Tuple[bool, bytes]]:
    """Fetch an extension that ``cryptography`` does not model as a typed extension.

    Returns a ``(critical, raw_extension_value)`` tuple, or ``None`` when the extension is
    absent. The returned bytes are the raw extension value (i.e. the DER-encoded OCTET STRING
    payload); callers are responsible for fully validating their contents.
    """
    try:
        extension = parsed.cert.extensions.get_extension_for_oid(oid)
    except Exception:
        return None

    return extension.critical, extension.value.value  # type: ignore[attr-defined]
