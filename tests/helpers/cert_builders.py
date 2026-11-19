"""Builders for synthetic X.509 certificates used by the certificate-chain security tests.

The certificates generated here exist solely to exercise validation logic under controlled
conditions: ordering, validity windows, curves, key usage and extension handling. They are not
real attestation roots and must never be shipped as trust anchors.
"""

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    BasicConstraints,
    ExtendedKeyUsage,
    KeyUsage,
    Name,
    NameAttribute,
    SubjectAlternativeName,
    UnrecognizedExtension,
)
from cryptography.x509.oid import NameOID, ObjectIdentifier

from webauthn.helpers.attestation_cert_constraints import (
    FIDO_GEN_CE_AAGUID_OID,
    TCG_KP_AIK_CERTIFICATE_OID,
)

_EPOCH = datetime(2026, 6, 1, tzinfo=timezone.utc)
_DEFAULT_NOT_BEFORE = _EPOCH - timedelta(days=365)
_DEFAULT_NOT_AFTER = _EPOCH + timedelta(days=365 * 5)

# OID for the TPM directory-name SAN entries
_TCG_AT_TPM_MANUFACTURER_OID = ObjectIdentifier("2.23.133.2.1")
_TCG_AT_TPM_MODEL_OID = ObjectIdentifier("2.23.133.2.2")
_TCG_AT_TPM_VERSION_OID = ObjectIdentifier("2.23.133.2.3")


@dataclass
class CertificateSpec:
    """Knobs controlling a single generated certificate in a chain."""

    common_name: str = "Test Attestation"
    curve: ec.EllipticCurve = field(default_factory=ec.SECP256R1)
    not_before: datetime = _DEFAULT_NOT_BEFORE
    not_after: datetime = _DEFAULT_NOT_AFTER
    basic_constraints_ca: bool = False
    include_basic_constraints: bool = True
    include_key_usage: bool = True
    digital_signature: bool = True
    eku_oids: Optional[List[str]] = None
    include_san_tpm: bool = False
    tpm_manufacturer: str = "id:494E5443"
    tpm_model: str = "Test Model"
    tpm_version: str = "1.2.3.4"
    aaguid: Optional[bytes] = None
    aaguid_critical: bool = False
    aaguid_encoded_value: Optional[bytes] = None
    extra_extensions: List[x509.Extension] = field(default_factory=list)
    is_root: bool = False


def _name(common_name: str) -> Name:
    # TPM AIK certificates have an empty subject, so an empty common name maps to an empty Name
    if not common_name:
        return Name([])
    return Name([NameAttribute(NameOID.COMMON_NAME, common_name)])


def _build_certificate(
    spec: CertificateSpec,
    subject_key,
    issuer_key,
    issuer_name: Name,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(spec.common_name))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(spec.not_before)
        .not_valid_after(spec.not_after)
    )

    if spec.include_basic_constraints:
        builder = builder.add_extension(
            BasicConstraints(ca=spec.basic_constraints_ca, path_length=None),
            critical=True,
        )

    if spec.include_key_usage:
        builder = builder.add_extension(
            KeyUsage(
                digital_signature=spec.digital_signature,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=spec.basic_constraints_ca,
                crl_sign=spec.basic_constraints_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    if spec.eku_oids is not None:
        builder = builder.add_extension(
            ExtendedKeyUsage([ObjectIdentifier(oid) for oid in spec.eku_oids]),
            critical=False,
        )

    if spec.include_san_tpm:
        tpm_dir_name = Name(
            [
                NameAttribute(_TCG_AT_TPM_MANUFACTURER_OID, spec.tpm_manufacturer),
                NameAttribute(_TCG_AT_TPM_MODEL_OID, spec.tpm_model),
                NameAttribute(_TCG_AT_TPM_VERSION_OID, spec.tpm_version),
            ]
        )
        builder = builder.add_extension(
            SubjectAlternativeName([x509.DirectoryName(tpm_dir_name)]),
            critical=False,
        )

    if spec.aaguid is not None or spec.aaguid_encoded_value is not None:
        raw_value = spec.aaguid_encoded_value
        if raw_value is None:
            assert spec.aaguid is not None
            raw_value = b"\x04\x10" + spec.aaguid
        builder = builder.add_extension(
            UnrecognizedExtension(FIDO_GEN_CE_AAGUID_OID, raw_value),
            critical=spec.aaguid_critical,
        )

    for extension in spec.extra_extensions:
        builder = builder.add_extension(extension.value, critical=extension.critical)
    return builder.sign(issuer_key, hashes.SHA256())


def build_chain(
    leaf_spec: Optional[CertificateSpec] = None,
    intermediate_spec: Optional[CertificateSpec] = None,
    include_root: bool = True,
) -> Tuple[List[bytes], bytes]:
    """Build a leaf -> intermediate -> root chain and return (x5c_der_list, root_pem).

    The returned x5c list follows WebAuthn ordering (leaf first). When ``include_root`` is
    False the root is omitted from x5c but still returned for use as a trust anchor.
    """
    leaf_spec = leaf_spec or CertificateSpec()
    intermediate_spec = intermediate_spec or CertificateSpec(
        common_name="Test Intermediate CA",
        basic_constraints_ca=True,
        is_root=False,
        include_san_tpm=False,
        eku_oids=None,
        aaguid=None,
    )

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = _name("Test Root CA")
    root_cert = _build_certificate(
        CertificateSpec(
            common_name="Test Root CA",
            basic_constraints_ca=True,
            is_root=True,
            include_san_tpm=False,
            eku_oids=None,
            aaguid=None,
        ),
        root_key,
        root_key,
        root_name,
    )

    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_cert = _build_certificate(
        intermediate_spec,
        intermediate_key,
        root_key,
        root_name,
    )

    leaf_key = ec.generate_private_key(leaf_spec.curve)
    leaf_cert = _build_certificate(
        leaf_spec,
        leaf_key,
        intermediate_key,
        _name(intermediate_spec.common_name),
    )

    x5c = [
        leaf_cert.public_bytes(serialization.Encoding.DER),
        intermediate_cert.public_bytes(serialization.Encoding.DER),
    ]
    if include_root:
        x5c.append(root_cert.public_bytes(serialization.Encoding.DER))

    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    return x5c, root_pem


def tpm_leaf_spec(aaguid: Optional[bytes] = None) -> CertificateSpec:
    """A leaf spec satisfying every TPM AIK certificate requirement."""
    return CertificateSpec(
        common_name="",
        eku_oids=[TCG_KP_AIK_CERTIFICATE_OID],
        include_san_tpm=True,
        aaguid=aaguid,
    )


def packed_leaf_spec(aaguid: Optional[bytes] = None) -> CertificateSpec:
    """A leaf spec satisfying every packed attestation certificate requirement."""
    return CertificateSpec(
        common_name="Test Packed Attestation",
        aaguid=aaguid,
    )


def build_packed_attestation_credential(
    *,
    rp_id: str = "localhost",
    origin: str = "http://localhost:5000",
    challenge: bytes = b"0" * 32,
    aaguid: bytes = b"\x01" * 16,
    authenticator_aaguid: Optional[bytes] = None,
    leaf_spec: Optional[CertificateSpec] = None,
    alg: int = -7,
) -> Tuple[Dict[str, Any], bytes]:
    """Assemble a complete, internally consistent "packed" registration credential.

    Returns a ``(credential_dict, root_pem)`` pair ready for
    ``verify_registration_response(...)``. The signature is produced with the generated leaf
    private key, so a response built here verifies end-to-end when its chain passes.

    Args:
        `authenticator_aaguid`: When set, overrides the AAGUID placed in authenticator data
            while the certificate keeps `aaguid`, simulating a device-identifier disagreement.
        `alg`: COSE algorithm identifier; -7 (ES256) is the only fully wired value here.
    """
    if alg != -7:
        raise ValueError("Only ES256 (-7) synthetic packed attestations are supported")

    leaf_spec = leaf_spec or packed_leaf_spec(aaguid)

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = _name("Test Root CA")
    root_cert = _build_certificate(
        CertificateSpec(common_name="Test Root CA", basic_constraints_ca=True),
        root_key,
        root_key,
        root_name,
    )

    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_name = _name("Test Intermediate CA")
    intermediate_cert = _build_certificate(
        CertificateSpec(common_name="Test Intermediate CA", basic_constraints_ca=True),
        intermediate_key,
        root_key,
        root_name,
    )

    leaf_key = ec.generate_private_key(leaf_spec.curve)
    leaf_cert = _build_certificate(
        leaf_spec, leaf_key, intermediate_key, intermediate_name
    )

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    # flags: UP (bit 0) + AT (bit 6)
    flags = bytes([0x45])
    sign_count = (0).to_bytes(4, "big")
    credential_id = b"\x02" * 16

    public_numbers = leaf_key.public_key().public_numbers()
    cose_public_key = {
        1: 2,  # kty: EC2
        3: alg,  # alg: ES256
        -1: 1,  # crv: P-256
        -2: public_numbers.x.to_bytes(32, "big"),
        -3: public_numbers.y.to_bytes(32, "big"),
    }

    # Authenticator data always carries a 16-byte AAGUID; only the certificate extension is
    # optional, so fall back to a fixed device AAGUID when no explicit value is supplied.
    auth_data_aaguid = (
        authenticator_aaguid
        if authenticator_aaguid is not None
        else (aaguid if aaguid is not None else b"\x01" * 16)
    )
    authenticator_data = b"".join(
        [
            rp_id_hash,
            flags,
            sign_count,
            auth_data_aaguid,
            len(credential_id).to_bytes(2, "big"),
            credential_id,
            cbor2.dumps(cose_public_key),
        ]
    )

    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": base64.urlsafe_b64encode(challenge)
            .decode("utf-8")
            .rstrip("="),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    client_data_hash = hashlib.sha256(client_data_json).digest()
    signature = leaf_key.sign(
        authenticator_data + client_data_hash,
        ec.ECDSA(hashes.SHA256()),
    )

    attestation_object = cbor2.dumps(
        {
            "fmt": "packed",
            "attStmt": {
                "alg": alg,
                "sig": signature,
                "x5c": [
                    leaf_cert.public_bytes(serialization.Encoding.DER),
                    intermediate_cert.public_bytes(serialization.Encoding.DER),
                ],
            },
            "authData": authenticator_data,
        }
    )

    credential = {
        "id": base64.urlsafe_b64encode(credential_id).decode("utf-8").rstrip("="),
        "rawId": base64.urlsafe_b64encode(credential_id).decode("utf-8").rstrip("="),
        "response": {
            "attestationObject": base64.urlsafe_b64encode(attestation_object)
            .decode("utf-8")
            .rstrip("="),
            "clientDataJSON": base64.urlsafe_b64encode(client_data_json)
            .decode("utf-8")
            .rstrip("="),
        },
        "type": "public-key",
    }

    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    return credential, root_pem
