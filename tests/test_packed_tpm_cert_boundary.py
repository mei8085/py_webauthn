"""End-to-end tests for the strict packed/TPM certificate boundary.

These build complete synthetic attestation responses and drive them through
``verify_registration_response`` so the certificate chain, extension, AAGUID and signature
checks are exercised together.
"""

from unittest import TestCase

from webauthn import verify_registration_response
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import AttestationFormat

from .helpers.cert_builders import (
    CertificateSpec,
    build_packed_attestation_credential,
)

RP_ID = "localhost"
ORIGIN = "http://localhost:5000"
CHALLENGE = b"0" * 32
AAGUID = b"\x01" * 16
OTHER_AAGUID = b"\xff" * 16


class TestPackedEndToEnd(TestCase):
    def test_well_formed_packed_attestation_verifies(self) -> None:
        credential, root_pem = build_packed_attestation_credential(aaguid=AAGUID)

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            pem_root_certs_bytes_by_fmt={AttestationFormat.PACKED: [root_pem]},
        )

        self.assertEqual(verification.fmt, AttestationFormat.PACKED)
        self.assertEqual(verification.aaguid, "01010101-0101-0101-0101-010101010101")

    def test_aaguid_disagreement_between_cert_and_authenticator_rejected(self) -> None:
        # The certificate extension carries AAGUID, authenticator data carries a different one
        credential, root_pem = build_packed_attestation_credential(
            aaguid=AAGUID,
            authenticator_aaguid=OTHER_AAGUID,
        )

        with self.assertRaises(InvalidRegistrationResponse) as ctx:
            verify_registration_response(
                credential=credential,
                expected_challenge=CHALLENGE,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                pem_root_certs_bytes_by_fmt={AttestationFormat.PACKED: [root_pem]},
            )

        # The mismatch must surface through the dedicated AAGUID error
        self.assertIn("AAGUID", str(ctx.exception))

    def test_critical_aaguid_extension_rejected_end_to_end(self) -> None:
        spec = CertificateSpec(aaguid=AAGUID, aaguid_critical=True)
        credential, root_pem = build_packed_attestation_credential(
            aaguid=AAGUID,
            leaf_spec=spec,
        )

        with self.assertRaises(InvalidRegistrationResponse) as ctx:
            verify_registration_response(
                credential=credential,
                expected_challenge=CHALLENGE,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                pem_root_certs_bytes_by_fmt={AttestationFormat.PACKED: [root_pem]},
            )

        self.assertIn("critical", str(ctx.exception))

    def test_illegal_curve_rejected_end_to_end(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        spec = CertificateSpec(curve=ec.SECP224R1())
        credential, root_pem = build_packed_attestation_credential(
            aaguid=AAGUID,
            leaf_spec=spec,
        )

        with self.assertRaises(InvalidRegistrationResponse) as ctx:
            verify_registration_response(
                credential=credential,
                expected_challenge=CHALLENGE,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                pem_root_certs_bytes_by_fmt={AttestationFormat.PACKED: [root_pem]},
            )

        self.assertIn("curve", str(ctx.exception).lower())

    def test_missing_basic_constraints_rejected_end_to_end(self) -> None:
        spec = CertificateSpec(include_basic_constraints=False)
        credential, root_pem = build_packed_attestation_credential(
            aaguid=AAGUID,
            leaf_spec=spec,
        )

        with self.assertRaises(InvalidRegistrationResponse) as ctx:
            verify_registration_response(
                credential=credential,
                expected_challenge=CHALLENGE,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                pem_root_certs_bytes_by_fmt={AttestationFormat.PACKED: [root_pem]},
            )

        self.assertIn("Basic Constraints", str(ctx.exception))

    def test_optional_aaguid_extension_absence_still_verifies(self) -> None:
        # No AAGUID extension in the certificate is valid; only mismatches are rejected
        credential, root_pem = build_packed_attestation_credential(aaguid=None)

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            pem_root_certs_bytes_by_fmt={AttestationFormat.PACKED: [root_pem]},
        )

        self.assertEqual(verification.fmt, AttestationFormat.PACKED)

    def test_algorithm_selection_is_preserved(self) -> None:
        """A legitimate ES256 packed attestation still passes via the original alg selection."""
        credential, root_pem = build_packed_attestation_credential(
            aaguid=AAGUID, alg=-7
        )

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            pem_root_certs_bytes_by_fmt={AttestationFormat.PACKED: [root_pem]},
        )

        self.assertTrue(verification.fmt == AttestationFormat.PACKED)

    def test_self_attestation_without_x5c_still_verifies(self) -> None:
        """Self attestation (no x5c) must bypass certificate checks but keep alg matching."""
        import base64
        import cbor2
        import hashlib
        import json

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
        credential_id = b"\x03" * 16
        public_numbers = leaf_key.public_key().public_numbers()
        cose_public_key = {
            1: 2,
            3: -7,
            -1: 1,
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
        authenticator_data = b"".join(
            [
                rp_id_hash,
                bytes([0x45]),
                (0).to_bytes(4, "big"),
                AAGUID,
                len(credential_id).to_bytes(2, "big"),
                credential_id,
                cbor2.dumps(cose_public_key),
            ]
        )
        client_data_json = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": base64.urlsafe_b64encode(CHALLENGE)
                .decode("utf-8")
                .rstrip("="),
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        signature = leaf_key.sign(
            authenticator_data + hashlib.sha256(client_data_json).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        attestation_object = cbor2.dumps(
            {
                "fmt": "packed",
                # No x5c: this is self attestation
                "attStmt": {"alg": -7, "sig": signature},
                "authData": authenticator_data,
            }
        )
        credential = {
            "id": base64.urlsafe_b64encode(credential_id).decode("utf-8").rstrip("="),
            "rawId": base64.urlsafe_b64encode(credential_id)
            .decode("utf-8")
            .rstrip("="),
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

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )

        self.assertEqual(verification.fmt, AttestationFormat.PACKED)
