import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from unittest import TestCase

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from webauthn import verify_authentication_response
from webauthn.authentication.verify_authentication_response import (
    VerifiedAuthentication,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    encode_cbor,
    parse_authentication_credential_json,
    parse_authenticator_data,
)
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidBackupFlags,
)
from webauthn.helpers.structs import CredentialDeviceType

RP_ID = "assertion.example"
ORIGIN = "https://assertion.example"
CHALLENGE = b"local-challenge"
CREDENTIAL_ID = b"\x01\x02\x03\x04"
USER_HANDLE = b"local-user"
MAX_SIGN_COUNT = 0xFFFFFFFF


def _counter_message(
    context: str, stored_before: int, asserted: int, stored_after: int
) -> str:
    """Assertion message that always carries counter state before and after."""
    return (
        f"{context}: stored sign count before={stored_before}, "
        f"assertion sign count={asserted}, stored sign count after={stored_after}"
    )


def _cose_ec2_public_key(public_key: EllipticCurvePublicKey) -> bytes:
    """Build a minimal CBOR-encoded COSE EC2/ES256 public key."""
    numbers = public_key.public_numbers()
    return encode_cbor(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )


@dataclass
class _CredentialRecord:
    """The subset of credential state an RP would persist between assertions."""

    credential_id: bytes
    public_key: bytes
    sign_count: int
    credential_device_type: CredentialDeviceType = CredentialDeviceType.SINGLE_DEVICE
    backed_up: bool = False


class TestVerifyAuthenticationResponseState(TestCase):
    private_key: EllipticCurvePrivateKey
    public_key: bytes

    @classmethod
    def setUpClass(cls) -> None:
        # Generate keys locally; no checked-in key material or oversized fixtures
        cls.private_key = ec.generate_private_key(ec.SECP256R1())
        cls.public_key = _cose_ec2_public_key(cls.private_key.public_key())

    def _build_assertion(
        self,
        *,
        sign_count: int,
        up: bool = True,
        uv: bool = False,
        be: bool = False,
        bs: bool = False,
        user_handle: Optional[bytes] = USER_HANDLE,
        rp_id: str = RP_ID,
        origin: str = ORIGIN,
        challenge: bytes = CHALLENGE,
    ) -> Dict[str, Any]:
        """Build a minimal assertion signed by the locally generated key.

        Authenticator data is the 37-byte minimum (rpIdHash, flags, sign count) and
        clientDataJSON contains only the required fields.
        """
        flags = 0
        if up:
            flags |= 1 << 0
        if uv:
            flags |= 1 << 2
        if be:
            flags |= 1 << 3
        if bs:
            flags |= 1 << 4

        authenticator_data = b"".join(
            [
                hashlib.sha256(rp_id.encode("utf-8")).digest(),
                bytes([flags]),
                sign_count.to_bytes(4, "big"),
            ]
        )
        client_data_json = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": bytes_to_base64url(challenge),
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        signature = self.private_key.sign(
            authenticator_data + hashlib.sha256(client_data_json).digest(),
            ec.ECDSA(hashes.SHA256()),
        )

        response: Dict[str, Any] = {
            "authenticatorData": bytes_to_base64url(authenticator_data),
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "signature": bytes_to_base64url(signature),
        }
        if user_handle is not None:
            response["userHandle"] = bytes_to_base64url(user_handle)

        encoded_id = bytes_to_base64url(CREDENTIAL_ID)
        return {
            "id": encoded_id,
            "rawId": encoded_id,
            "response": response,
            "type": "public-key",
        }

    def _authenticate(
        self,
        record: _CredentialRecord,
        credential: Dict[str, Any],
        *,
        expected_rp_id: str = RP_ID,
    ) -> VerifiedAuthentication:
        return verify_authentication_response(
            credential=credential,
            expected_challenge=CHALLENGE,
            expected_rp_id=expected_rp_id,
            expected_origin=ORIGIN,
            credential_public_key=record.public_key,
            credential_current_sign_count=record.sign_count,
        )

    def _snapshot(self, record: _CredentialRecord) -> Dict[str, Any]:
        return {
            "credential_id": bytes(record.credential_id),
            "public_key": bytes(record.public_key),
            "sign_count": record.sign_count,
            "credential_device_type": record.credential_device_type,
            "backed_up": record.backed_up,
        }

    def _commit(
        self, record: _CredentialRecord, verification: VerifiedAuthentication
    ) -> None:
        record.sign_count = verification.new_sign_count
        record.credential_device_type = verification.credential_device_type
        record.backed_up = verification.credential_backed_up

    def test_verifies_assertion_with_rp_id_hash_and_user_handle(self) -> None:
        record = _CredentialRecord(CREDENTIAL_ID, self.public_key, 4)
        before = self._snapshot(record)
        assertion = self._build_assertion(sign_count=5)
        assertion_before = copy.deepcopy(assertion)

        verification = self._authenticate(record, assertion)

        msg = _counter_message(
            "valid increment", before["sign_count"], 5, verification.new_sign_count
        )
        self.assertEqual(verification.new_sign_count, 5, msg)
        self.assertEqual(verification.credential_id, CREDENTIAL_ID, msg)
        self.assertEqual(
            verification.credential_device_type,
            CredentialDeviceType.SINGLE_DEVICE,
            msg,
        )
        self.assertFalse(verification.credential_backed_up, msg)
        self.assertFalse(verification.user_verified, msg)
        self.assertEqual(
            assertion, assertion_before, f"{msg}; credential input was mutated"
        )
        self.assertEqual(
            self._snapshot(record),
            before,
            f"{msg}; verification must not commit the new count itself",
        )

        parsed = parse_authentication_credential_json(assertion)
        auth_data = parse_authenticator_data(parsed.response.authenticator_data)
        self.assertEqual(
            auth_data.rp_id_hash,
            hashlib.sha256(RP_ID.encode("utf-8")).digest(),
            f"{msg}; rpIdHash did not bind the assertion to the expected RP ID",
        )
        self.assertEqual(
            parsed.response.user_handle,
            USER_HANDLE,
            f"{msg}; user handle was not preserved",
        )
        self.assertEqual(
            parsed.raw_id, CREDENTIAL_ID, f"{msg}; user handle leaked into id"
        )

    def test_checks_rp_id_hash_without_updating_state(self) -> None:
        record = _CredentialRecord(CREDENTIAL_ID, self.public_key, 4)
        cases = [
            ("assertion for another RP ID", "other.example", RP_ID),
            ("wrong expected RP ID", RP_ID, "other.example"),
        ]

        for label, assertion_rp_id, expected_rp_id in cases:
            with self.subTest(label):
                assertion = self._build_assertion(sign_count=5, rp_id=assertion_rp_id)
                before = self._snapshot(record)
                verification = None

                with self.assertRaisesRegex(
                    InvalidAuthenticationResponse, "Unexpected RP ID hash"
                ):
                    verification = self._authenticate(
                        record, assertion, expected_rp_id=expected_rp_id
                    )

                after = self._snapshot(record)
                msg = _counter_message(
                    f"rpIdHash mismatch ({label})",
                    before["sign_count"],
                    5,
                    after["sign_count"],
                )
                self.assertIsNone(verification, msg)
                self.assertEqual(after, before, msg)

    def test_handles_absent_and_present_user_handle(self) -> None:
        record = _CredentialRecord(CREDENTIAL_ID, self.public_key, 4)

        with self.subTest("user handle present"):
            assertion = self._build_assertion(sign_count=5, user_handle=USER_HANDLE)
            verification = self._authenticate(record, assertion)
            msg = _counter_message(
                "user handle present", record.sign_count, 5, verification.new_sign_count
            )
            self.assertEqual(verification.new_sign_count, 5, msg)
            parsed = parse_authentication_credential_json(assertion)
            self.assertEqual(parsed.response.user_handle, USER_HANDLE, msg)
            self.assertEqual(parsed.raw_id, CREDENTIAL_ID, msg)

        with self.subTest("user handle absent"):
            assertion = self._build_assertion(sign_count=5, user_handle=None)
            verification = self._authenticate(record, assertion)
            msg = _counter_message(
                "user handle absent", record.sign_count, 5, verification.new_sign_count
            )
            self.assertEqual(verification.new_sign_count, 5, msg)
            parsed = parse_authentication_credential_json(assertion)
            self.assertIsNone(parsed.response.user_handle, msg)
            self.assertEqual(parsed.raw_id, CREDENTIAL_ID, msg)

    def test_accepts_legitimate_counter_growth(self) -> None:
        cases = [(0, 0), (1, 2), (77, 78), (MAX_SIGN_COUNT - 1, MAX_SIGN_COUNT)]

        for stored, asserted in cases:
            with self.subTest(stored=stored, asserted=asserted):
                record = _CredentialRecord(CREDENTIAL_ID, self.public_key, stored)
                before = self._snapshot(record)
                assertion = self._build_assertion(sign_count=asserted)

                verification = self._authenticate(record, assertion)

                msg = _counter_message(
                    "legitimate growth", stored, asserted, verification.new_sign_count
                )
                self.assertEqual(verification.new_sign_count, asserted, msg)
                self.assertEqual(
                    self._snapshot(record),
                    before,
                    f"{msg}; caller commits the new count explicitly",
                )

                self._commit(record, verification)
                self.assertEqual(record.sign_count, asserted, msg)

    def test_rejects_counter_rollback_without_partial_update(self) -> None:
        cases = [(10, 9), (5, 0), (MAX_SIGN_COUNT, MAX_SIGN_COUNT - 1)]

        for stored, asserted in cases:
            with self.subTest(stored=stored, asserted=asserted):
                record = _CredentialRecord(CREDENTIAL_ID, self.public_key, stored)
                before = self._snapshot(record)
                assertion = self._build_assertion(sign_count=asserted)
                assertion_before = copy.deepcopy(assertion)
                verification = None

                with self.assertRaises(InvalidAuthenticationResponse) as raised:
                    verification = self._authenticate(record, assertion)

                after = self._snapshot(record)
                msg = _counter_message(
                    "counter rollback", stored, asserted, after["sign_count"]
                )
                self.assertIsNone(
                    verification, f"{msg}; no verification result may escape on error"
                )
                self.assertIn(str(asserted), str(raised.exception), msg)
                self.assertIn(str(stored), str(raised.exception), msg)
                self.assertEqual(
                    after, before, f"{msg}; credential state was partially updated"
                )
                self.assertEqual(
                    assertion, assertion_before, f"{msg}; credential input was mutated"
                )

    def test_counter_wraparound_behavior(self) -> None:
        with self.subTest("last increment before wrap is accepted"):
            record = _CredentialRecord(
                CREDENTIAL_ID, self.public_key, MAX_SIGN_COUNT - 1
            )
            before = self._snapshot(record)
            assertion = self._build_assertion(sign_count=MAX_SIGN_COUNT)

            pre_wrap_verification = self._authenticate(record, assertion)

            msg = _counter_message(
                "pre-wrap increment",
                MAX_SIGN_COUNT - 1,
                MAX_SIGN_COUNT,
                pre_wrap_verification.new_sign_count,
            )
            self.assertEqual(pre_wrap_verification.new_sign_count, MAX_SIGN_COUNT, msg)
            self.assertEqual(self._snapshot(record), before, msg)

        for asserted in (0, 1):
            with self.subTest(
                "post-wrap value is treated as replay", asserted=asserted
            ):
                record = _CredentialRecord(
                    CREDENTIAL_ID, self.public_key, MAX_SIGN_COUNT
                )
                before = self._snapshot(record)
                assertion = self._build_assertion(sign_count=asserted)
                verification: Optional[VerifiedAuthentication] = None

                with self.assertRaises(InvalidAuthenticationResponse) as raised:
                    verification = self._authenticate(record, assertion)

                after = self._snapshot(record)
                msg = _counter_message(
                    "counter wraparound",
                    MAX_SIGN_COUNT,
                    asserted,
                    after["sign_count"],
                )
                self.assertIsNone(verification, msg)
                self.assertIn(str(asserted), str(raised.exception), msg)
                self.assertIn(str(MAX_SIGN_COUNT), str(raised.exception), msg)
                self.assertEqual(
                    after, before, f"{msg}; credential state was partially updated"
                )

    def test_backup_flags_and_duplicate_credential_combinations(self) -> None:
        # (be, bs, stored, asserted) where stored == asserted is a duplicate assertion
        cases: List[Tuple[bool, bool, int, int, Optional[type]]] = [
            (False, False, 0, 0, None),
            (True, False, 0, 0, None),
            (True, True, 0, 0, None),
            (True, True, 0, 1, None),
            (False, False, 7, 7, InvalidAuthenticationResponse),
            (True, False, 7, 7, InvalidAuthenticationResponse),
            (True, True, 7, 7, InvalidAuthenticationResponse),
            (False, True, 0, 0, InvalidBackupFlags),
            (False, True, 5, 6, InvalidBackupFlags),
        ]

        for be, bs, stored, asserted, expected_error in cases:
            with self.subTest(be=be, bs=bs, stored=stored, asserted=asserted):
                record = _CredentialRecord(CREDENTIAL_ID, self.public_key, stored)
                before = self._snapshot(record)
                assertion = self._build_assertion(sign_count=asserted, be=be, bs=bs)
                verification = None

                if expected_error is None:
                    verification = self._authenticate(record, assertion)
                    msg = _counter_message(
                        f"backup flags be={be} bs={bs}",
                        stored,
                        asserted,
                        verification.new_sign_count,
                    )
                    self.assertEqual(verification.new_sign_count, asserted, msg)
                    expected_device_type = (
                        CredentialDeviceType.MULTI_DEVICE
                        if be
                        else CredentialDeviceType.SINGLE_DEVICE
                    )
                    self.assertEqual(
                        verification.credential_device_type, expected_device_type, msg
                    )
                    self.assertEqual(verification.credential_backed_up, bs, msg)
                    self.assertEqual(self._snapshot(record), before, msg)
                    self._commit(record, verification)
                    self.assertEqual(record.sign_count, asserted, msg)
                else:
                    with self.assertRaises(expected_error):
                        verification = self._authenticate(record, assertion)

                    after = self._snapshot(record)
                    msg = _counter_message(
                        f"backup flags be={be} bs={bs}",
                        stored,
                        asserted,
                        after["sign_count"],
                    )
                    self.assertIsNone(verification, msg)
                    self.assertEqual(
                        after, before, f"{msg}; credential state was partially updated"
                    )

    def test_duplicate_assertion_is_rejected_after_commit(self) -> None:
        record = _CredentialRecord(CREDENTIAL_ID, self.public_key, 0)
        assertion = self._build_assertion(sign_count=1, be=True, bs=True)

        first = self._authenticate(record, assertion)
        msg = _counter_message(
            "duplicate assertion first use", 0, 1, first.new_sign_count
        )
        self.assertEqual(first.new_sign_count, 1, msg)
        self.assertEqual(
            first.credential_device_type, CredentialDeviceType.MULTI_DEVICE, msg
        )
        self.assertTrue(first.credential_backed_up, msg)

        self._commit(record, first)
        committed = self._snapshot(record)

        second = None
        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            second = self._authenticate(record, assertion)

        after = self._snapshot(record)
        msg = _counter_message(
            "duplicate assertion replay",
            committed["sign_count"],
            1,
            after["sign_count"],
        )
        self.assertIsNone(second, f"{msg}; duplicate assertion must not verify twice")
        self.assertIn("was not greater than current count", str(raised.exception), msg)
        self.assertEqual(
            after, committed, f"{msg}; rejected replay must not change credential state"
        )

    def test_invalid_signature_leaves_counter_state_untouched(self) -> None:
        record = _CredentialRecord(CREDENTIAL_ID, self.public_key, 4)
        before = self._snapshot(record)
        assertion = self._build_assertion(sign_count=5)
        # Corrupt the last signature byte; the DER structure stays parseable, so
        # signature verification must fail after the counter check has passed
        raw_signature = bytearray(
            base64url_to_bytes(assertion["response"]["signature"])
        )
        raw_signature[-1] ^= 0x01
        assertion["response"]["signature"] = bytes_to_base64url(bytes(raw_signature))
        assertion_before = copy.deepcopy(assertion)
        verification = None

        with self.assertRaisesRegex(
            InvalidAuthenticationResponse,
            "Could not verify authentication signature",
        ):
            verification = self._authenticate(record, assertion)

        after = self._snapshot(record)
        msg = _counter_message(
            "invalid signature after counter check", 4, 5, after["sign_count"]
        )
        self.assertIsNone(verification, msg)
        self.assertEqual(
            after, before, f"{msg}; credential state was partially updated"
        )
        self.assertEqual(
            assertion, assertion_before, f"{msg}; credential input was mutated"
        )

    def test_concurrent_reads_keep_original_behavior(self) -> None:
        record = _CredentialRecord(CREDENTIAL_ID, self.public_key, 4)
        before = self._snapshot(record)
        assertion = self._build_assertion(sign_count=5)
        assertion_before = copy.deepcopy(assertion)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(
                executor.map(lambda _: self._authenticate(record, assertion), range(32))
            )

        msg = _counter_message("concurrent reads", 4, 5, 5)
        self.assertEqual(len(results), 32, msg)
        for verification in results:
            self.assertEqual(verification.new_sign_count, 5, msg)
            self.assertEqual(verification.credential_id, CREDENTIAL_ID, msg)
        self.assertEqual(
            self._snapshot(record),
            before,
            f"{msg}; concurrent reads must not commit or mutate credential state",
        )
        self.assertEqual(
            assertion, assertion_before, f"{msg}; credential input was mutated"
        )

        # Concurrent accepts and rejects against the same stored state: successful
        # reads see the original count and rejected reads leave the state untouched
        stale_assertion = self._build_assertion(sign_count=4)

        def _attempt(credential: Dict[str, Any]) -> Any:
            try:
                return self._authenticate(record, credential)
            except InvalidAuthenticationResponse as exc:
                return exc

        with ThreadPoolExecutor(max_workers=8) as executor:
            mixed = list(executor.map(_attempt, [assertion, stale_assertion] * 16))

        successes = [item for item in mixed if isinstance(item, VerifiedAuthentication)]
        failures = [
            item for item in mixed if isinstance(item, InvalidAuthenticationResponse)
        ]
        mixed_msg = _counter_message("concurrent mixed reads", 4, 5, record.sign_count)
        self.assertEqual(len(successes), 16, mixed_msg)
        self.assertEqual(len(failures), 16, mixed_msg)
        for verification in successes:
            self.assertEqual(verification.new_sign_count, 5, mixed_msg)
        for failure in failures:
            self.assertIn("was not greater than current count", str(failure), mixed_msg)
        self.assertEqual(
            self._snapshot(record),
            before,
            f"{mixed_msg}; concurrent reads must not commit or mutate credential state",
        )
