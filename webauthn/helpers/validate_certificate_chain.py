from datetime import datetime, timezone
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurvePublicKey,
)
from OpenSSL.crypto import X509Store, X509StoreContext, X509StoreContextError

from .attestation_cert_constraints import (
    AttestationCertificateType,
    validate_attestation_certificate_constraints,
)
from .certificate_parsing import (
    ParsedCertificate,
    certificate_issuer_der,
    certificate_name_der,
    load_x509_certificates,
    to_openssl_x509,
)
from .exceptions import (
    CertificateChainExpired,
    InvalidCertificateChain,
    InvalidCertificateCurve,
    InvalidCertificateOrder,
)
from .pem_cert_bytes_to_open_ssl_x509 import pem_cert_bytes_to_open_ssl_x509

# Only these curves are registered for WebAuthn EC2 credential public keys (COSE crv P-256,
# P-384, P-521). An attestation leaf certificate using any other EC curve cannot attest to a
# credential this library can verify.
_WEBAUTHN_PERMITTED_EC_CURVES = (SECP256R1, SECP384R1, SECP521R1)

# OpenSSL verification error codes (from x509_vfy.h)
_X509_V_ERR_CERT_NOT_YET_VALID = 9
_X509_V_ERR_CERT_HAS_EXPIRED = 10

# Test hook: when not None, overrides the moment at which certificate validity windows are
# evaluated. Production code leaves this as None. Tests set it via the x509store helper.
_validation_time_override: Optional[datetime] = None


def _get_validation_time() -> datetime:
    if _validation_time_override is not None:
        return _validation_time_override
    return datetime.now(timezone.utc)


def validate_certificate_chain(
    *,
    x5c: List[bytes],
    pem_root_certs_bytes: Optional[List[bytes]] = None,
    attestation_type: Optional[AttestationCertificateType] = None,
    aaguid: Optional[bytes] = None,
    validation_time: Optional[datetime] = None,
) -> bool:
    """Validate the certificates in an attestation statement's x5c.

    Validation covers, in order:

    1. Every certificate in x5c can be parsed (with lenient BER fallback for DER violations).
    2. The certificates are ordered leaf-first, each issuer immediately following its subject.
    3. Every certificate is within its validity window.
    4. Any EC public key in the chain uses a curve permitted for WebAuthn (P-256, P-384, P-521).
    5. The leaf satisfies attestation-type-specific constraints (basic constraints, key usage,
       mandatory extensions, AAGUID binding) when ``attestation_type`` is provided.
    6. When root certificates are supplied, the chain cryptographically verifies back to one of
       them, including signature and trust-anchor checks performed by OpenSSL.

    Args:
        `x5c`: X5C certificates from a registration response's attestation statement
        (optional) `pem_root_certs_bytes`: Any additional (PEM-formatted) root certificates
            that may complete the certificate chain
        (optional) `attestation_type`: Attestation format whose leaf certificate constraints
            should be enforced
        (optional) `aaguid`: The 16-byte AAGUID from the attested credential data, used to
            bind the id-fido-gen-ce-aaguid extension
        (optional) `validation_time`: The moment at which validity windows must be satisfied.
            Defaults to the current time. Intended for testing against captured, long-expired
            certificate chains.

    Raises:
        A stable subclass of `helpers.exceptions.InvalidCertificateChain` when any part of the
        chain cannot be validated:
            `InvalidCertificateOrder`, `CertificateChainExpired`,
            `InvalidCertificateCurve`, `InvalidCertificateExtension`,
            `CertificateAAGUIDMismatch`, `InvalidCertificateKeyUsage`, or
            `InvalidCertificateChain` for other failures.
    """
    # Make sure we have at least one certificate to validate
    if len(x5c) < 1:
        raise InvalidCertificateChain("x5c was empty")

    if validation_time is None:
        validation_time = _get_validation_time()
    if validation_time.tzinfo is None:
        # Treat naive datetimes (e.g. the ones used in tests) as UTC so comparisons stay
        # timezone-safe.
        validation_time = validation_time.replace(tzinfo=timezone.utc)

    # 1. Parse every certificate. Parsing never grants trust by itself; each security attribute
    # is checked explicitly below.
    try:
        parsed_certs = load_x509_certificates(x5c)
    except InvalidCertificateChain:
        raise
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not prepare x5c certificates. See __cause__ for more info"
        ) from exc

    leaf_parsed = parsed_certs[0]

    # 2. Enforce the leaf-first ordering requirement. OpenSSL will silently reorder a shuffled
    # chain, so verify the adjacency explicitly rather than relying on it to fail verification.
    _validate_certificate_order(parsed_certs)

    # 3. Reject an expired or not-yet-valid chain with a dedicated, stable error.
    _validate_validity_windows(parsed_certs, validation_time)

    # 4. Reject EC certificates on curves that WebAuthn cannot represent.
    _validate_certificates_curves(parsed_certs)

    # 5. Attestation-type-specific leaf certificate constraints.
    if attestation_type is not None:
        validate_attestation_certificate_constraints(
            leaf_cert=leaf_parsed,
            attestation_type=attestation_type,
            aaguid=aaguid,
        )

    # 6. Cryptographic chain verification against the known roots. Without root certificates we
    # cannot establish a trust anchor, so the structural checks above are all that can be done.
    if not pem_root_certs_bytes:
        return True

    try:
        leaf_cert_openssl = to_openssl_x509(parsed_certs[0])
        intermediate_certs = [to_openssl_x509(parsed) for parsed in parsed_certs[1:]]
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not prepare certificates for chain verification. See __cause__ for more info"
        ) from exc

    cert_store = _generate_new_cert_store()
    # Keep the OpenSSL store's notion of time consistent with the explicit validity checks
    if validation_time is not None:
        cert_store.set_time(validation_time)

    try:
        for root_cert_bytes in pem_root_certs_bytes:
            cert_store.add_cert(pem_cert_bytes_to_open_ssl_x509(root_cert_bytes))
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not prepare root certs. See __cause__ for more info"
        ) from exc

    context = X509StoreContext(
        store=cert_store,
        certificate=leaf_cert_openssl,
        chain=intermediate_certs,
    )

    try:
        context.verify_certificate()
    except X509StoreContextError as exc:
        raise _classify_store_context_error(exc) from exc

    return True


def _validate_certificate_order(parsed_certs: List[ParsedCertificate]) -> None:
    """Each certificate's issuer Name must equal the next certificate's subject Name.

    The final certificate in x5c is either a root/trust anchor (self-issued) or an intermediate
    whose issuer must be supplied among the root certificates; in both cases the adjacency
    checks below cover every link present in x5c.
    """
    for index in range(len(parsed_certs) - 1):
        subject_cert = parsed_certs[index]
        issuer_cert = parsed_certs[index + 1]

        if certificate_issuer_der(subject_cert) != certificate_name_der(issuer_cert):
            raise InvalidCertificateOrder(
                f"x5c certificate at position {index} was not issued by the certificate at "
                f"position {index + 1}; x5c must be ordered leaf-first with each issuer "
                "following its subject"
            )


def _validate_validity_windows(
    parsed_certs: List[ParsedCertificate], validation_time: datetime
) -> None:
    """Reject any certificate that is expired or not yet valid at the validation time."""
    for index, parsed in enumerate(parsed_certs):
        cert = parsed.cert
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        if validation_time < not_before:
            raise CertificateChainExpired(
                f"x5c certificate at position {index} is not valid until "
                f"{not_before.isoformat()}"
            )

        if validation_time > not_after:
            raise CertificateChainExpired(
                f"x5c certificate at position {index} expired at {not_after.isoformat()}"
            )


def _validate_certificates_curves(parsed_certs: List[ParsedCertificate]) -> None:
    """Reject EC certificates on anything other than the WebAuthn-permitted curves."""
    for index, parsed in enumerate(parsed_certs):
        public_key = parsed.cert.public_key()

        if not isinstance(public_key, EllipticCurvePublicKey):
            # RSA, Ed25519 and other non-EC key types have no WebAuthn curve restriction here
            continue

        if not isinstance(public_key.curve, _WEBAUTHN_PERMITTED_EC_CURVES):
            raise InvalidCertificateCurve(
                f"x5c certificate at position {index} uses unsupported EC curve "
                f'"{public_key.curve.name}"; expected one of P-256, P-384, or P-521'
            )


def _classify_store_context_error(
    exc: X509StoreContextError,
) -> InvalidCertificateChain:
    """Turn an OpenSSL store context error into the library's stable exception types."""
    errors = getattr(exc, "errors", None)

    error_code = None
    if errors:
        # Each entry is a (verification_error_code, certificate_depth, message) tuple
        first_error = errors[0]
        if isinstance(first_error, (list, tuple)):
            error_code = first_error[0]
        else:
            error_code = first_error

    if error_code in (_X509_V_ERR_CERT_NOT_YET_VALID, _X509_V_ERR_CERT_HAS_EXPIRED):
        return CertificateChainExpired(
            "Certificate chain is outside of its validity window. "
            "See __cause__ for more info"
        )

    return InvalidCertificateChain(
        "Certificate chain could not be validated. See __cause__ for more info"
    )


def _generate_new_cert_store() -> X509Store:
    """
    Something that can be patched during testing to return an X509Store instance with its time
    adjusted to some datetime in the past. This allows full certificate validity checks even after
    cert expiration in the real world. See here:

    https://www.pyopenssl.org/en/stable/api/crypto.html#OpenSSL.crypto.X509Store.set_time
    """
    return X509Store()
