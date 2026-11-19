"""Attestation-type-specific X.509 certificate constraints.

Chain building, signature verification and trust-anchor checks live in
``validate_certificate_chain``. This module holds the policy checks that differ between
attestation statement formats:

- which extensions are mandatory and how their contents must be interpreted,
- which Extended Key Usage OIDs authorize a certificate to act as an attestation certificate,
- how the optional ``id-fido-gen-ce-aaguid`` extension is bound to the AAGUID in
  authenticator data.

Only extensions identified by an explicit OID and fully validated here are treated as
verified security attributes. An extension that is merely present, or that uses an unknown OID,
never causes a check to pass.
"""

from enum import Enum
from typing import List, Optional

from cryptography import x509
from cryptography.x509 import (
    BasicConstraints,
    ExtendedKeyUsage,
    KeyUsage,
    SubjectAlternativeName,
    GeneralName,
    Name,
)
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

from .certificate_parsing import ParsedCertificate, get_unrecognized_extension_value
from .exceptions import (
    CertificateAAGUIDMismatch,
    InvalidCertificateExtension,
    InvalidCertificateKeyUsage,
)

# id-fido-gen-ce-aaguid: the FIDO AAGUID extension carried by some attestation certificates.
# https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements
FIDO_GEN_CE_AAGUID_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

# TCG TPM key-purpose OID identifying an AIK certificate
# tcg-kp-AIKCertificate (joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) 3)
TCG_KP_AIK_CERTIFICATE_OID = "2.23.133.8.3"

# TPM manufacturer/model/firmware version OIDs carried in the Subject Alternative Name
TCG_AT_TPM_MANUFACTURER_OID = "2.23.133.2.1"
TCG_AT_TPM_MODEL_OID = "2.23.133.2.2"
TCG_AT_TPM_VERSION_OID = "2.23.133.2.3"

# DER tag prefix of an OCTET STRING wrapping a 16-byte AAGUID: 0x04 (OCTET STRING), 0x10 (16)
_AAGUID_OCTET_STRING_PREFIX = b"\x04\x10"
_AAGUID_LENGTH = 16


class AttestationCertificateType(str, Enum):
    """The attestation format whose certificate constraints should be enforced."""

    PACKED = "packed"
    TPM = "tpm"
    FIDO_U2F = "fido-u2f"
    GENERIC = "generic"


def validate_attestation_certificate_constraints(
    *,
    leaf_cert: ParsedCertificate,
    attestation_type: AttestationCertificateType,
    aaguid: Optional[bytes] = None,
) -> None:
    """Validate the attestation-type-specific constraints on a leaf attestation certificate.

    Args:
        `leaf_cert`: The first (leaf) certificate from the attestation statement's x5c
        `attestation_type`: Which attestation format's requirements to enforce
        (optional) `aaguid`: The 16-byte AAGUID from attested credential data, required when
            binding the id-fido-gen-ce-aaguid extension for packed/TPM attestation

    Raises subclasses of `InvalidCertificateChain` with stable, distinct messages.
    """
    # Basic Constraints: an attestation leaf is an end-entity certificate, never a CA.
    _validate_basic_constraints(leaf_cert.cert, attestation_type)

    # Key Usage / Extended Key Usage must actually authorize attestation use.
    _validate_key_usage(leaf_cert.cert, attestation_type)

    # Type-specific mandatory extensions.
    if attestation_type == AttestationCertificateType.TPM:
        _validate_tpm_extensions(leaf_cert.cert)

    # The AAGUID extension is optional, but when present it must be well-formed, must not be
    # marked critical, and must match the authenticator's AAGUID. This binding applies to
    # packed and TPM attestation; legacy fido-u2f attestation uses an all-zero AAGUID by
    # requirement while its certificate may carry a vendor AAGUID, so fido-u2f only gets the
    # structural (criticality/encoding) checks below via _validate_aaguid_extension_shape.
    if attestation_type in (
        AttestationCertificateType.PACKED,
        AttestationCertificateType.TPM,
    ):
        _validate_aaguid_extension(leaf_cert, aaguid, attestation_type)
    elif attestation_type == AttestationCertificateType.FIDO_U2F:
        _validate_aaguid_extension_shape(leaf_cert, attestation_type)


def _validate_basic_constraints(
    leaf_cert: x509.Certificate,
    attestation_type: AttestationCertificateType,
) -> None:
    """The Basic Constraints extension must mark the leaf certificate as not a CA.

    The extension is mandatory for packed and TPM attestation per their certificate
    requirements. Other formats may legitimately omit it (some legacy attestation certificates
    do), so absence is only rejected for those two types.
    """
    try:
        basic_constraints: (
            BasicConstraints
        ) = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value  # type: ignore[assignment]
    except ExtensionNotFound:
        if attestation_type in (
            AttestationCertificateType.PACKED,
            AttestationCertificateType.TPM,
        ):
            raise InvalidCertificateExtension(
                "Certificate missing Basic Constraints extension "
                f"({attestation_type.value})"
            )
        return

    if basic_constraints.ca is not False:
        raise InvalidCertificateExtension(
            "Certificate Basic Constraints CA component was not false "
            f"({attestation_type.value})"
        )


def _validate_key_usage(
    leaf_cert: x509.Certificate,
    attestation_type: AttestationCertificateType,
) -> None:
    """Validate Key Usage and, where required, Extended Key Usage for attestation purposes."""
    # When a Key Usage extension is present it must permit digital signatures. An absent Key
    # Usage extension imposes no constraint here (some attestation certificates omit it).
    key_usage: Optional[KeyUsage] = None
    try:
        key_usage = leaf_cert.extensions.get_extension_for_oid(  # type: ignore[assignment]
            ExtensionOID.KEY_USAGE
        ).value
    except ExtensionNotFound:
        pass

    if key_usage is not None and not key_usage.digital_signature:
        raise InvalidCertificateKeyUsage(
            "Certificate Key Usage did not permit digitalSignature "
            f"({attestation_type.value})"
        )

    # TPM attestation certificates MUST carry the TCG AIK certificate EKU.
    if attestation_type == AttestationCertificateType.TPM:
        try:
            extended_key_usage: ExtendedKeyUsage = (
                leaf_cert.extensions.get_extension_for_oid(  # type: ignore[assignment]
                    ExtensionOID.EXTENDED_KEY_USAGE
                ).value
            )
        except ExtensionNotFound:
            raise InvalidCertificateExtension(
                "Certificate missing Extended Key Usage extension (tpm)"
            )

        eku_oids: List[str] = [oid.dotted_string for oid in extended_key_usage]
        if TCG_KP_AIK_CERTIFICATE_OID not in eku_oids:
            raise InvalidCertificateKeyUsage(
                f"Certificate Extended Key Usage {eku_oids} did not contain "
                f'"{TCG_KP_AIK_CERTIFICATE_OID}" (tpm)'
            )


def _validate_tpm_extensions(leaf_cert: x509.Certificate) -> None:
    """Validate the mandatory TPM AIK certificate extensions beyond key usage.

    The Subject Alternative Name extension must carry the TPM manufacturer, model and firmware
    version directory name entries. Only entries with the explicitly documented OIDs are read;
    unknown general names are ignored rather than treated as verified attributes.
    """
    try:
        subject_alt_name: SubjectAlternativeName = (
            leaf_cert.extensions.get_extension_for_oid(  # type: ignore[assignment]
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
        )
    except ExtensionNotFound:
        raise InvalidCertificateExtension(
            "Certificate missing Subject Alternative Name extension (tpm)"
        )

    try:
        tpm_directory_names = subject_alt_name.get_values_for_type(GeneralName)  # type: ignore[arg-type]
        if not tpm_directory_names:
            raise IndexError
        tcg_at_tpm_values: Name = tpm_directory_names[0]  # type: ignore[assignment]
    except IndexError:
        raise InvalidCertificateExtension(
            "Certificate Subject Alternative Name did not contain a TPM directory name (tpm)"
        )

    manufacturer = None
    model = None
    version = None
    for attribute in tcg_at_tpm_values:
        oid = attribute.oid.dotted_string
        if oid == TCG_AT_TPM_MANUFACTURER_OID:
            manufacturer = str(attribute.value)
        elif oid == TCG_AT_TPM_MODEL_OID:
            model = attribute.value
        elif oid == TCG_AT_TPM_VERSION_OID:
            version = attribute.value
        # Any other OID is deliberately ignored: unknown fields are never treated as verified
        # security attributes.

    if not manufacturer or not model or not version:
        raise InvalidCertificateExtension(
            "Certificate Subject Alt Name was missing a TPM manufacturer, model, or version "
            f"entry (tpm): {tcg_at_tpm_values}"
        )


def _validate_aaguid_extension_shape(
    leaf_cert: ParsedCertificate,
    attestation_type: AttestationCertificateType,
) -> None:
    """Structural-only checks for the optional id-fido-gen-ce-aaguid extension.

    Used for attestation types (fido-u2f) whose authenticator data AAGUID is not comparable to
    the certificate extension value. Presence remains optional.
    """
    extension_data = get_unrecognized_extension_value(
        leaf_cert,
        FIDO_GEN_CE_AAGUID_OID,
    )

    if extension_data is None:
        return

    critical, raw_value = extension_data

    if critical:
        raise InvalidCertificateExtension(
            f"Extension {FIDO_GEN_CE_AAGUID_OID.dotted_string} must not be marked critical "
            f"({attestation_type.value})"
        )

    if not raw_value.startswith(_AAGUID_OCTET_STRING_PREFIX):
        raise CertificateAAGUIDMismatch(
            f"Extension {FIDO_GEN_CE_AAGUID_OID.dotted_string} was not an OCTET STRING "
            f"({attestation_type.value})"
        )

    if len(raw_value) != len(_AAGUID_OCTET_STRING_PREFIX) + _AAGUID_LENGTH:
        raise CertificateAAGUIDMismatch(
            f"Extension {FIDO_GEN_CE_AAGUID_OID.dotted_string} did not contain a 16-byte AAGUID "
            f"({attestation_type.value})"
        )


def _validate_aaguid_extension(
    leaf_cert: ParsedCertificate,
    aaguid: Optional[bytes],
    attestation_type: AttestationCertificateType,
) -> None:
    """Validate the optional id-fido-gen-ce-aaguid extension against authenticator data.

    The extension is optional: a certificate without it passes. When present it must:

    - not be marked critical (per WebAuthn, a critical id-fido-gen-ce-aaguid is invalid),
    - contain an OCTET STRING wrapping exactly 16 bytes,
    - equal the AAGUID in the attested credential data.
    """
    extension_data = get_unrecognized_extension_value(
        leaf_cert,
        FIDO_GEN_CE_AAGUID_OID,
    )

    # Missing optional extension is explicitly allowed.
    if extension_data is None:
        return

    critical, raw_value = extension_data

    if critical:
        raise InvalidCertificateExtension(
            f"Extension {FIDO_GEN_CE_AAGUID_OID.dotted_string} must not be marked critical "
            f"({attestation_type.value})"
        )

    if not raw_value.startswith(_AAGUID_OCTET_STRING_PREFIX):
        raise CertificateAAGUIDMismatch(
            f"Extension {FIDO_GEN_CE_AAGUID_OID.dotted_string} was not an OCTET STRING "
            f"({attestation_type.value})"
        )

    extension_aaguid = raw_value[len(_AAGUID_OCTET_STRING_PREFIX) :]

    if (
        len(extension_aaguid) != _AAGUID_LENGTH
        or len(raw_value) != len(_AAGUID_OCTET_STRING_PREFIX) + _AAGUID_LENGTH
    ):
        raise CertificateAAGUIDMismatch(
            f"Extension {FIDO_GEN_CE_AAGUID_OID.dotted_string} did not contain a 16-byte AAGUID "
            f"({attestation_type.value})"
        )

    if aaguid is None:
        raise CertificateAAGUIDMismatch(
            f"Extension {FIDO_GEN_CE_AAGUID_OID.dotted_string} was present but no authenticator "
            f"AAGUID was available for comparison ({attestation_type.value})"
        )

    if extension_aaguid != aaguid:
        raise CertificateAAGUIDMismatch(
            "Certificate AAGUID extension did not match authenticator data AAGUID "
            f"({attestation_type.value})"
        )
