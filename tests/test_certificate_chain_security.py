"""Tests for the strict certificate chain validation used by packed and TPM attestation.

Each failure mode the security requirements call out gets its own stable exception type and a
dedicated test here:

- missing required extension / malformed optional extension -> InvalidCertificateExtension
- certificate order abnormalities -> InvalidCertificateOrder
- illegal EC curves -> InvalidCertificateCurve
- expired / not-yet-valid chains -> CertificateChainExpired
- AAGUID disagreements between certificate and authenticator -> CertificateAAGUIDMismatch
- key usage / EKU not authorizing attestation -> InvalidCertificateKeyUsage
"""

from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import patch

import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

from webauthn.helpers.attestation_cert_constraints import (
    TCG_KP_AIK_CERTIFICATE_OID,
    AttestationCertificateType,
)
from webauthn.helpers.exceptions import (
    CertificateAAGUIDMismatch,
    CertificateChainExpired,
    InvalidCertificateChain,
    InvalidCertificateCurve,
    InvalidCertificateExtension,
    InvalidCertificateKeyUsage,
    InvalidCertificateOrder,
)
from webauthn.helpers.validate_certificate_chain import validate_certificate_chain

from .helpers.cert_builders import (
    CertificateSpec,
    build_chain,
    packed_leaf_spec,
    tpm_leaf_spec,
)

AAGUID = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
DIFFERENT_AAGUID = bytes.fromhex("ffeeddccbbaa99887766554433221100")


class TestCertificateOrdering(TestCase):
    def test_rejects_shuffled_leaf_and_intermediate(self) -> None:
        """OpenSSL silently reorders a shuffled chain; the library must reject it explicitly."""
        x5c, root = build_chain(packed_leaf_spec(AAGUID))
        shuffled = [x5c[1], x5c[0]] + x5c[2:]

        with self.assertRaises(InvalidCertificateOrder) as ctx:
            validate_certificate_chain(
                x5c=shuffled,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )

        # The error must be stable and point at the offending positions
        self.assertIn("position 0", str(ctx.exception))
        self.assertIn("position 1", str(ctx.exception))

    def test_rejects_chain_with_unrelated_certificate_inserted(self) -> None:
        x5c, root = build_chain(packed_leaf_spec(AAGUID))
        other_x5c, _other_root = build_chain(packed_leaf_spec(AAGUID))

        with self.assertRaises(InvalidCertificateOrder):
            validate_certificate_chain(
                x5c=[x5c[0], other_x5c[1]] + x5c[1:],
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )

    def test_accepts_properly_ordered_chain(self) -> None:
        x5c, root = build_chain(packed_leaf_spec(AAGUID))

        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )
        )


class TestCertificateValidityWindow(TestCase):
    def test_rejects_expired_leaf(self) -> None:
        now = datetime.now(timezone.utc)
        expired_spec = CertificateSpec(
            not_before=now - timedelta(days=730),
            not_after=now - timedelta(days=1),
            aaguid=AAGUID,
        )
        x5c, root = build_chain(expired_spec)

        with self.assertRaises(CertificateChainExpired) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )

        self.assertIn("expired", str(ctx.exception))

    def test_rejects_not_yet_valid_leaf(self) -> None:
        now = datetime.now(timezone.utc)
        future_spec = CertificateSpec(
            not_before=now + timedelta(days=1),
            not_after=now + timedelta(days=730),
            aaguid=AAGUID,
        )
        x5c, root = build_chain(future_spec)

        with self.assertRaises(CertificateChainExpired) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )

        self.assertIn("not valid until", str(ctx.exception))

    def test_rejects_expired_intermediate(self) -> None:
        now = datetime.now(timezone.utc)
        expired_intermediate = CertificateSpec(
            common_name="Expired Intermediate CA",
            basic_constraints_ca=True,
            not_before=now - timedelta(days=730),
            not_after=now - timedelta(days=1),
        )
        x5c, root = build_chain(intermediate_spec=expired_intermediate)

        with self.assertRaises(CertificateChainExpired) as ctx:
            validate_certificate_chain(x5c=x5c, pem_root_certs_bytes=[root])

        self.assertIn("position 1", str(ctx.exception))

    def test_validation_time_argument_overrides_wall_clock(self) -> None:
        now = datetime.now(timezone.utc)
        expired_spec = CertificateSpec(
            not_before=now - timedelta(days=730),
            not_after=now - timedelta(days=1),
            aaguid=AAGUID,
        )
        x5c, root = build_chain(expired_spec)

        # At a moment inside the validity window validation succeeds even though "now" is later
        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
                validation_time=now - timedelta(days=365),
            )
        )

    def test_openssl_expiry_error_maps_to_stable_exception(self) -> None:
        """An expiry reported by OpenSSL itself must also map to CertificateChainExpired."""
        from OpenSSL.crypto import X509StoreContextError

        x5c, root = build_chain(packed_leaf_spec(AAGUID))
        expiry_error = X509StoreContextError(
            message="certificate has expired",
            certificate=OpenSSL.crypto.X509(),
            errors=[[10, 0, "certificate has expired"]],
        )

        with patch(
            "OpenSSL.crypto.X509StoreContext.verify_certificate",
            side_effect=expiry_error,
        ):
            with self.assertRaises(CertificateChainExpired):
                validate_certificate_chain(
                    x5c=x5c,
                    pem_root_certs_bytes=[root],
                )


class TestCertificateCurves(TestCase):
    def test_rejects_illegal_ec_curve_on_leaf(self) -> None:
        # SECP224R1 is a valid EC curve but is not among WebAuthn's P-256/P-384/P-521
        illegal_curve_spec = CertificateSpec(curve=ec.SECP224R1())
        x5c, root = build_chain(illegal_curve_spec)

        with self.assertRaises(InvalidCertificateCurve) as ctx:
            validate_certificate_chain(x5c=x5c, pem_root_certs_bytes=[root])

        self.assertIn("secp224r1", str(ctx.exception))

    def test_accepts_webauthn_curves(self) -> None:
        for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()):
            with self.subTest(curve=curve.name):
                x5c, root = build_chain(CertificateSpec(curve=curve))
                self.assertTrue(
                    validate_certificate_chain(x5c=x5c, pem_root_certs_bytes=[root])
                )


class TestPackedCertificateConstraints(TestCase):
    def test_accepts_cert_with_matching_aaguid_extension(self) -> None:
        x5c, root = build_chain(packed_leaf_spec(AAGUID))

        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )
        )

    def test_accepts_cert_without_optional_aaguid_extension(self) -> None:
        """Missing optional extensions produce no error and grant no trust on their own."""
        x5c, root = build_chain(packed_leaf_spec(aaguid=None))

        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )
        )

    def test_rejects_aaguid_mismatch_between_cert_and_authenticator(self) -> None:
        x5c, root = build_chain(packed_leaf_spec(AAGUID))

        with self.assertRaises(CertificateAAGUIDMismatch) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=DIFFERENT_AAGUID,
            )

        self.assertIn("AAGUID", str(ctx.exception))

    def test_rejects_critical_aaguid_extension(self) -> None:
        spec = CertificateSpec(aaguid=AAGUID, aaguid_critical=True)
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateExtension) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )

        self.assertIn("critical", str(ctx.exception))

    def test_rejects_malformed_aaguid_extension_payload(self) -> None:
        # OCTET STRING tag present but wrong inner length
        spec = CertificateSpec(aaguid_encoded_value=b"\x04\x0c" + b"\x00" * 12)
        x5c, root = build_chain(spec)

        with self.assertRaises(CertificateAAGUIDMismatch):
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )

    def test_rejects_aaguid_extension_without_octet_string_wrapper(self) -> None:
        spec = CertificateSpec(aaguid_encoded_value=b"\x31\x10" + b"\x00" * 16)
        x5c, root = build_chain(spec)

        with self.assertRaises(CertificateAAGUIDMismatch):
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )

    def test_rejects_leaf_with_ca_basic_constraint(self) -> None:
        spec = CertificateSpec(basic_constraints_ca=True)
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateExtension) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
            )

        self.assertIn("CA", str(ctx.exception))

    def test_rejects_leaf_missing_basic_constraints(self) -> None:
        spec = CertificateSpec(include_basic_constraints=False)
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateExtension) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
            )

        self.assertIn("Basic Constraints", str(ctx.exception))

    def test_rejects_key_usage_without_digital_signature(self) -> None:
        spec = CertificateSpec(digital_signature=False)
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateKeyUsage) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
            )

        self.assertIn("digitalSignature", str(ctx.exception))

    def test_accepts_leaf_without_key_usage_extension(self) -> None:
        # Key Usage is only enforced when present
        spec = CertificateSpec(include_key_usage=False, aaguid=AAGUID)
        x5c, root = build_chain(spec)

        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )
        )

    def test_unknown_extension_is_not_treated_as_verified_attribute(self) -> None:
        """An arbitrary unknown extension OID must not satisfy any required-extension check."""
        unknown_oid = ObjectIdentifier("1.2.3.4.5.6.7.8.9")
        unknown_ext = x509.Extension(
            unknown_oid,
            critical=False,
            value=x509.UnrecognizedExtension(unknown_oid, b"whatever"),
        )
        # A packed leaf without Basic Constraints, carrying only an unrelated extension, must
        # still be rejected: unknown fields never substitute for required security attributes.
        spec = CertificateSpec(
            include_basic_constraints=False,
            extra_extensions=[unknown_ext],
        )
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateExtension):
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.PACKED,
            )


class TestTPMCertificateConstraints(TestCase):
    def test_accepts_well_formed_tpm_leaf(self) -> None:
        x5c, root = build_chain(tpm_leaf_spec())

        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
                aaguid=AAGUID,
            )
        )

    def test_rejects_tpm_leaf_missing_aik_eku(self) -> None:
        spec = CertificateSpec(include_san_tpm=True, eku_oids=None)
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateExtension) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
            )

        self.assertIn("Extended Key Usage", str(ctx.exception))

    def test_rejects_tpm_leaf_with_wrong_eku_oid(self) -> None:
        spec = CertificateSpec(
            include_san_tpm=True,
            eku_oids=["1.3.6.1.5.5.7.3.2"],  # clientAuth, not tcg-kp-AIKCertificate
        )
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateKeyUsage) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
            )

        self.assertIn(TCG_KP_AIK_CERTIFICATE_OID, str(ctx.exception))

    def test_accepts_aik_eku_alongside_other_ekus(self) -> None:
        spec = CertificateSpec(
            include_san_tpm=True,
            eku_oids=["1.3.6.1.5.5.7.3.2", TCG_KP_AIK_CERTIFICATE_OID],
        )
        x5c, root = build_chain(spec)

        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
            )
        )

    def test_rejects_tpm_leaf_missing_san(self) -> None:
        spec = CertificateSpec(
            include_san_tpm=False, eku_oids=[TCG_KP_AIK_CERTIFICATE_OID]
        )
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateExtension) as ctx:
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
            )

        self.assertIn("Subject Alternative Name", str(ctx.exception))

    def test_rejects_tpm_leaf_with_incomplete_san_entries(self) -> None:
        spec = CertificateSpec(
            include_san_tpm=True,
            eku_oids=[TCG_KP_AIK_CERTIFICATE_OID],
            tpm_version="",
        )
        x5c, root = build_chain(spec)

        with self.assertRaises(InvalidCertificateExtension):
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
            )

    def test_rejects_tpm_aaguid_mismatch(self) -> None:
        spec = tpm_leaf_spec(aaguid=AAGUID)
        x5c, root = build_chain(spec)

        with self.assertRaises(CertificateAAGUIDMismatch):
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
                aaguid=DIFFERENT_AAGUID,
            )

    def test_accepts_tpm_leaf_without_optional_aaguid_extension(self) -> None:
        x5c, root = build_chain(tpm_leaf_spec(aaguid=None))

        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
                aaguid=AAGUID,
            )
        )

    def test_tpm_aaguid_extension_uses_same_binding_as_packed(self) -> None:
        """A TPM cert carrying id-fido-gen-ce-aaguid is bound to the authenticator AAGUID."""
        x5c, root = build_chain(tpm_leaf_spec(aaguid=AAGUID))

        # Same AAGUID: passes
        self.assertTrue(
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
                aaguid=AAGUID,
            )
        )

        # Different AAGUID: rejected with the dedicated mismatch error
        with self.assertRaises(CertificateAAGUIDMismatch):
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[root],
                attestation_type=AttestationCertificateType.TPM,
                aaguid=DIFFERENT_AAGUID,
            )


class TestTPMPubAreaCurveHandling(TestCase):
    def test_unknown_tpm_curve_id_raises_stable_exception(self) -> None:
        from webauthn.helpers.exceptions import InvalidTPMPubAreaStructure
        from webauthn.helpers.tpm.parse_pub_area import parse_pub_area

        # ECC pub area prefix (type ECC, nameAlg SHA256) with an unallocated curve ID 0x00FF
        malformed = (
            b"\x00\x23"  # type: TPM_ALG_ECC
            b"\x00\x0b"  # nameAlg: SHA256
            b"\x00\x00\x00\x00"  # objectAttributes
            b"\x00\x00"  # authPolicy length 0
            b"\x00\x10\x00\x10"  # ECC parameters: symmetric/scheme
            b"\x00\xff"  # curve ID: unallocated
            b"\x00\x20"  # kdf
            b"\x00\x00"  # unique length prefixes (parsing stops at parameters here)
        )

        with self.assertRaises(InvalidTPMPubAreaStructure):
            parse_pub_area(malformed)


class TestChainTrustAnchors(TestCase):
    def test_rejects_when_root_cert_does_not_match(self) -> None:
        x5c, _root = build_chain(packed_leaf_spec(AAGUID))
        _other_x5c, other_root = build_chain(packed_leaf_spec(AAGUID))

        with self.assertRaises(InvalidCertificateChain):
            validate_certificate_chain(
                x5c=x5c,
                pem_root_certs_bytes=[other_root],
                attestation_type=AttestationCertificateType.PACKED,
                aaguid=AAGUID,
            )

    def test_empty_x5c_raises(self) -> None:
        with self.assertRaises(InvalidCertificateChain):
            validate_certificate_chain(x5c=[])

    def test_malformed_cert_bytes_raise_stable_error(self) -> None:
        with self.assertRaises(InvalidCertificateChain):
            validate_certificate_chain(x5c=[b"definitely not a certificate"])

    def test_structural_checks_still_run_without_root_certs(self) -> None:
        """Without roots we cannot verify trust, but order/curve/constraints still apply."""
        spec = CertificateSpec(curve=ec.SECP224R1())
        x5c, _root = build_chain(spec)

        with self.assertRaises(InvalidCertificateCurve):
            validate_certificate_chain(x5c=x5c)
