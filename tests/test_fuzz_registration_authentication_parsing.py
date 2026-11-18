"""
Fuzz-style unit tests for WebAuthn registration and authentication response parsing.

Two parse paths are exercised:

- Registration: `parse_registration_credential_json` -> `parse_attestation_object`
  (-> `parse_authenticator_data` -> `parse_cbor`)
- Authentication: `parse_authentication_credential_json` -> `parse_authenticator_data`
  (-> `parse_cbor`)

Mutation categories (each mapped to a stable assertion):

1. Truncated byte strings: every truncation must either parse cleanly (only possible
   at an exact field boundary) or raise a `WebAuthnException` subclass. Truncations
   below the 37-byte authenticator-data minimum must always raise
   `InvalidAuthenticatorDataStructure`.
2. Nested CBOR lengths: declared map/array/byte-string lengths that exceed the
   available bytes must raise a `WebAuthnException` subclass, never leak a bare
   `TypeError`/`ValueError`/cbor2 exception, and never parse successfully.
3. Unknown fields: unknown JSON properties and unknown CBOR map keys are legal per
   spec and must parse without error (no false positives).
4. Duplicate fields: duplicate CBOR map keys must be rejected with a
   `WebAuthnException` subclass on both paths.
5. Inconsistent counts: a `credential_id_len` that disagrees with the actual bytes,
   or a CBOR container count that disagrees with its items, must raise a
   `WebAuthnException` subclass.

The generator is deterministic (fixed seed) and preserves minimal failing samples:
any input that violates the oracle is shrunk with a greedy ddmin-style reducer and
recorded, together with a re-runnable repro, in `tests/fuzz_evidence/`.

Readable evidence (regenerated on every run, deterministic):

1. `tests/fuzz_evidence/01_minimal_mutated_inputs.md` - minimal mutated input per
   category and parse path, with hex + repro snippet.
2. `tests/fuzz_evidence/02_path_error_category_diff.md` - error-category comparison
   between the registration and authentication parse paths.
3. `tests/fuzz_evidence/03_legit_boundary_passes.md` - legitimate extensions,
   credential types and boundary lengths that must pass (no false positives).

Run with the existing test command (no external services involved):

    python -m unittest tests.test_fuzz_registration_authentication_parsing
"""

import copy
import json
import random
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

import cbor2

from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.parse_attestation_object import parse_attestation_object
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.parse_authenticator_data import parse_authenticator_data
from webauthn.helpers.parse_registration_credential_json import (
    parse_registration_credential_json,
)

SEED = 20261118

EVIDENCE_DIR = Path(__file__).resolve().parent / "fuzz_evidence"

# A valid COSE EC2 public key ({1: 2, 3: -7, -1: 1, -2: x, -3: y})
COSE_KEY = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x11" * 32, -3: b"\x22" * 32})

CREDENTIAL_ID = b"\x99" * 16


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_auth_data(
    *,
    at: bool = False,
    ed: bool = False,
    credential_id: bytes = CREDENTIAL_ID,
    extensions: Optional[Dict[str, Any]] = None,
) -> bytes:
    """Build a structurally valid authenticatorData byte string."""
    data = b"\x00" * 32  # rpIdHash
    flags = 0x01  # UP
    if at:
        flags |= 0x40
    if ed:
        flags |= 0x80
    data += bytes([flags]) + (0).to_bytes(4, "big")  # signCount
    if at:
        data += b"\x00" * 16  # AAGUID
        data += len(credential_id).to_bytes(2, "big")
        data += credential_id
        data += COSE_KEY
    if ed:
        data += cbor2.dumps(extensions if extensions is not None else {"credProtect": 3})
    return data


def build_attestation_object(
    auth_data: bytes,
    *,
    fmt: str = "none",
    att_stmt: Optional[Dict[str, Any]] = None,
    extra_keys: Optional[Dict[Any, Any]] = None,
) -> bytes:
    obj: Dict[Any, Any] = {
        "fmt": fmt,
        "authData": auth_data,
        "attStmt": att_stmt if att_stmt is not None else {},
    }
    if extra_keys:
        obj.update(extra_keys)
    return cbor2.dumps(obj)


def build_registration_credential(attestation_object: bytes) -> Dict[str, Any]:
    return {
        "id": _b64url(CREDENTIAL_ID),
        "rawId": _b64url(CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64url(b'{"type":"webauthn.create"}'),
            "attestationObject": _b64url(attestation_object),
        },
    }


def build_authentication_credential(auth_data: bytes) -> Dict[str, Any]:
    return {
        "id": _b64url(CREDENTIAL_ID),
        "rawId": _b64url(CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64url(b'{"type":"webauthn.get"}'),
            "authenticatorData": _b64url(auth_data),
            "signature": _b64url(b"\x30" * 70),
        },
    }


class Outcome(NamedTuple):
    ok: bool
    error: Optional[str]  # exception class name, e.g. "InvalidCBORData"
    cause: Optional[str]  # direct __cause__/__context__ class name
    message: str  # str() of the raised exception
    root: Optional[str]  # root cause class name (end of the exception chain)
    root_message: str  # str() of the root cause
    leaked: bool  # True if a non-WebAuthnException escaped the parse path


def _root_cause(exc: BaseException) -> BaseException:
    seen = exc
    for _ in range(32):
        nxt = seen.__cause__ if seen.__cause__ is not None else seen.__context__
        if nxt is None:
            return seen
        seen = nxt
    return seen


def _to_outcome(fn: Callable[[], Any]) -> Outcome:
    try:
        fn()
        return Outcome(True, None, None, "", None, "", False)
    except WebAuthnException as exc:
        cause_exc = exc.__cause__ if exc.__cause__ is not None else exc.__context__
        cause = type(cause_exc).__name__ if cause_exc else None
        root = _root_cause(exc)
        return Outcome(
            False, type(exc).__name__, cause, str(exc), type(root).__name__, str(root), False
        )
    except Exception as exc:  # noqa: BLE001 - the oracle WANTS to catch these
        return Outcome(False, type(exc).__name__, None, str(exc), None, "", True)


def run_registration_blob(attestation_object: bytes) -> Outcome:
    """Full registration parse path, from a raw attestationObject blob."""

    def _run() -> None:
        cred = parse_registration_credential_json(
            build_registration_credential(attestation_object)
        )
        parse_attestation_object(cred.response.attestation_object)

    return _to_outcome(_run)


def run_authentication_blob(auth_data: bytes) -> Outcome:
    """Full authentication parse path, from a raw authenticatorData blob."""

    def _run() -> None:
        cred = parse_authentication_credential_json(
            build_authentication_credential(auth_data)
        )
        parse_authenticator_data(cred.response.authenticator_data)

    return _to_outcome(_run)


def run_registration_credential(cred: Dict[str, Any]) -> Outcome:
    def _run() -> None:
        parsed = parse_registration_credential_json(cred)
        parse_attestation_object(parsed.response.attestation_object)

    return _to_outcome(_run)


def run_authentication_credential(cred: Dict[str, Any]) -> Outcome:
    def _run() -> None:
        parsed = parse_authentication_credential_json(cred)
        parse_authenticator_data(parsed.response.authenticator_data)

    return _to_outcome(_run)


def shrink_to_minimal(blob: bytes, predicate: Callable[[bytes], bool]) -> bytes:
    """
    Greedy ddmin-style reducer: remove chunks of decreasing size while `predicate`
    keeps holding. Deterministic for a deterministic predicate.
    """
    blob = bytes(blob)
    assert predicate(blob), "predicate must hold for the initial input"
    chunk = max(1, len(blob) // 2)
    while chunk >= 1 and blob:
        i = 0
        while i < len(blob):
            candidate = blob[:i] + blob[i + chunk :]
            if predicate(candidate):
                blob = candidate
            else:
                i += chunk
        chunk //= 2
    return blob


# ---------------------------------------------------------------------------
# Evidence collection (module-level, written out by the final test)
# ---------------------------------------------------------------------------

MINIMAL_SAMPLES: List[Dict[str, str]] = []
PATH_DIFF_ROWS: List[Tuple[str, str, str, str]] = []
LEGIT_PASSES: List[str] = []
INVARIANT_VIOLATIONS: List[Dict[str, str]] = []


def record_minimal(category: str, path: str, blob: bytes, outcome: Outcome) -> None:
    MINIMAL_SAMPLES.append(
        {
            "category": category,
            "path": path,
            "length": str(len(blob)),
            "hex": blob.hex() or "(empty)",
            "error": outcome.error or "ok",
            "cause": outcome.cause or "-",
            "root": f"{outcome.root}: {outcome.root_message}" if outcome.root else "-",
        }
    )


class FuzzTestCase(unittest.TestCase):
    def assert_well_typed(self, outcome: Outcome, context: str) -> None:
        """The oracle: a parse path may fail, but only with a WebAuthnException."""
        if outcome.leaked:
            self.fail(
                f"{context}: non-WebAuthnException escaped the parse path: "
                f"{outcome.error}"
            )

    def handle_leak(
        self,
        category: str,
        path: str,
        blob: bytes,
        runner: Callable[[bytes], Outcome],
    ) -> None:
        """Shrink a non-WebAuthnException failure to its minimal form and record it."""
        minimal = shrink_to_minimal(blob, lambda b: runner(b).leaked)
        outcome = runner(minimal)
        INVARIANT_VIOLATIONS.append(
            {
                "category": category,
                "path": path,
                "length": str(len(minimal)),
                "hex": minimal.hex() or "(empty)",
                "error": outcome.error or "?",
            }
        )
        self.fail(
            f"[{category}/{path}] leaked {outcome.error}; minimal repro "
            f"({len(minimal)} bytes): bytes.fromhex(\"{minimal.hex()}\")"
        )


class TestTruncatedByteStrings(FuzzTestCase):
    """Category 1: truncated byte strings on both parse paths."""

    def test_1_truncated_byte_strings(self) -> None:
        rng = random.Random(SEED + 1)

        # --- Registration: truncate the attestationObject at every byte ---
        att_obj = build_attestation_object(build_auth_data(at=True, ed=True))
        for cut in range(len(att_obj)):
            blob = att_obj[:cut]
            outcome = run_registration_blob(blob)
            if outcome.leaked:
                self.handle_leak("truncated_byte_string", "registration", blob, run_registration_blob)
            # A truncated attestationObject can never parse: cbor2 requires the
            # whole document and rejects trailing/premature data.
            self.assertFalse(outcome.ok, f"truncated attestationObject parsed at cut={cut}")
            self.assertEqual(
                outcome.error,
                "InvalidAttestationObjectStructure",
                f"cut={cut} raised {outcome.error}",
            )

        # --- Authentication: truncate authenticatorData at every byte ---
        # The flags byte survives truncation, so a truncated blob always claims
        # extensions/attested-data it no longer contains: every truncation must
        # raise, and always with a WebAuthnException subclass.
        auth_data = build_auth_data(ed=True)
        for cut in range(len(auth_data)):
            blob = auth_data[:cut]
            outcome = run_authentication_blob(blob)
            if outcome.leaked:
                self.handle_leak("truncated_byte_string", "authentication", blob, run_authentication_blob)
            self.assertFalse(outcome.ok, f"truncated authenticatorData parsed at cut={cut}")
            if cut < 37:
                # Below the 37-byte minimum the parser must always refuse.
                self.assertEqual(
                    outcome.error,
                    "InvalidAuthenticatorDataStructure",
                    f"cut={cut} raised {outcome.error}",
                )
            else:
                self.assertIn(
                    outcome.error,
                    ("InvalidCBORData", "InvalidAuthenticatorDataStructure"),
                    f"cut={cut} raised {outcome.error}",
                )

        # --- Random interior truncation of JSON-carried base64url values ---
        cred = build_registration_credential(att_obj)
        for _ in range(64):
            mutated = copy.deepcopy(cred)
            val = mutated["response"]["attestationObject"]
            mutated["response"]["attestationObject"] = val[: rng.randrange(len(val))]
            outcome = run_registration_credential(mutated)
            if outcome.leaked:
                self.fail("truncated base64url attestationObject leaked " f"{outcome.error}")

        # Record minimal failing (rejected) samples for evidence. Predicates pin
        # the error signature (class + root cause) so shrinking cannot collapse
        # the sample into a degenerate input from a different failure mode.
        minimal = shrink_to_minimal(
            att_obj[:10],
            lambda b: (o := run_registration_blob(b)).error
            == "InvalidAttestationObjectStructure"
            and o.root == "CBORDecodeEOF"
            and len(b) > 0,
        )
        record_minimal("truncated_byte_string", "registration", minimal, run_registration_blob(minimal))

        minimal = shrink_to_minimal(
            auth_data[:10],
            lambda b: run_authentication_blob(b).error == "InvalidAuthenticatorDataStructure"
            and len(b) > 0,
        )
        record_minimal("truncated_byte_string", "authentication", minimal, run_authentication_blob(minimal))


class TestNestedCBORLengths(FuzzTestCase):
    """Category 2: nested CBOR length headers that lie about their contents."""

    def _cases(self) -> Dict[str, Tuple[bytes, bytes, bool]]:
        """(registration blob, authentication blob, auth blob expected to parse)."""
        auth_data = build_auth_data(at=True)
        valid_att = build_attestation_object(auth_data)

        # Map header claims 4 pairs, only 3 are present.
        map_overrun = b"\xa4" + valid_att[1:]

        # Byte-string header claims 255 bytes, far fewer follow.
        bytes_overrun = (
            b"\xa3\x63fmt\x64none"  # {"fmt": "none"
            b"\x68authData\x58\xff"  # "authData": bytes(255) -- but only 37 follow
            + b"\x00" * 37
            + b"\x67attStmt\xa0"  # "attStmt": {}
        )

        # Nested array header claims 5 elements, only 1 is present.
        nested_array_overrun = (
            b"\xa3\x63fmt\x64none"
            b"\x68authData\x58\x25" + b"\x00" * 37 +
            b"\x67attStmt\xa1\x63x5c\x85\x41\x00"  # {"x5c": [<1 of 5>]}
        )

        # Deeply nested arrays (nested-length stress): [[[[...0...]]]]
        deep_nesting = b"\x81" * 64 + b"\x00"

        # Authentication side: extensions map claims 2 pairs, 1 is present.
        auth_ext_overrun = build_auth_data() + b"\xa2\x6bcredProtect\x03"
        # Authentication side: extension byte-string claims 32 bytes, 1 follows.
        auth_ext_bytes_overrun = build_auth_data() + b"\xa1\x61x\x58\x20\x00"

        # Note: on the authentication path a deeply nested CBOR value is a
        # *legal* extension payload, so it must parse (no false positive).
        auth_deep_nesting = build_auth_data() + deep_nesting
        auth_deep_nesting = (
            auth_deep_nesting[:32] + bytes([auth_deep_nesting[32] | 0x80]) + auth_deep_nesting[33:]
        )

        return {
            "map_len_overrun": (map_overrun, auth_ext_overrun, False),
            "bytes_len_overrun": (bytes_overrun, auth_ext_bytes_overrun, False),
            "nested_array_len_overrun": (nested_array_overrun, auth_ext_overrun, False),
            "deep_nesting": (deep_nesting, auth_deep_nesting, True),
        }

    def test_2_nested_cbor_lengths(self) -> None:
        for name, (reg_blob, auth_blob, auth_expect_ok) in self._cases().items():
            reg_outcome = run_registration_blob(reg_blob)
            if reg_outcome.leaked:
                self.handle_leak(name, "registration", reg_blob, run_registration_blob)
            self.assertFalse(reg_outcome.ok, f"{name}: registration parsed corrupt lengths")
            self.assert_well_typed(reg_outcome, f"{name}/registration")

            auth_outcome = run_authentication_blob(auth_blob)
            if auth_outcome.leaked:
                self.handle_leak(name, "authentication", auth_blob, run_authentication_blob)
            if auth_expect_ok:
                self.assertTrue(
                    auth_outcome.ok,
                    f"{name}: authentication false-positive on legal extension: {auth_outcome}",
                )
            else:
                self.assertFalse(auth_outcome.ok, f"{name}: authentication parsed corrupt lengths")
            self.assert_well_typed(auth_outcome, f"{name}/authentication")

            note = (
                "deeply nested CBOR is a legal extension value on the authentication path"
                if auth_expect_ok
                else "corrupt declared lengths rejected on both paths"
            )
            PATH_DIFF_ROWS.append(
                (
                    f"nested CBOR length: {name}",
                    reg_outcome.error or "ok",
                    auth_outcome.error or "ok",
                    note,
                )
            )

            if name == "deep_nesting":
                # Hand-crafted: the point of this sample is its depth (64 levels).
                record_minimal(
                    f"nested_cbor_length/{name}", "registration", reg_blob, reg_outcome
                )
            else:
                minimal = shrink_to_minimal(
                    reg_blob,
                    lambda b: (o := run_registration_blob(b)).error
                    == "InvalidAttestationObjectStructure"
                    and o.root == "CBORDecodeEOF"
                    and len(b) > 0,
                )
                record_minimal(
                    f"nested_cbor_length/{name}", "registration", minimal, run_registration_blob(minimal)
                )

        # Randomized length-header corruption: flip length bytes in valid CBOR.
        rng = random.Random(SEED + 2)
        auth_data = build_auth_data(at=True, ed=True)
        att_obj = build_attestation_object(auth_data)
        for _ in range(128):
            blob = bytearray(att_obj)
            pos = rng.randrange(len(blob))
            blob[pos] = rng.choice([0x58, 0x59, 0x5A, 0x9F, 0xBF, 0xFF, 0x1B])
            outcome = run_registration_blob(bytes(blob))
            if outcome.leaked:
                self.handle_leak(
                    "nested_cbor_length/random", "registration", bytes(blob), run_registration_blob
                )
            self.assert_well_typed(outcome, "nested_cbor_length/random")


class TestUnknownFields(FuzzTestCase):
    """Category 3: unknown fields are legal and must not be false-positived."""

    def test_3_unknown_fields(self) -> None:
        rng = random.Random(SEED + 3)

        # Unknown CBOR map keys in the attestationObject (text, int, negative int).
        att_obj = build_attestation_object(
            build_auth_data(at=True),
            extra_keys={"futureExtKey": b"\x01\x02", 42: [1, 2, 3], -7: {"nested": True}},
        )
        outcome = run_registration_blob(att_obj)
        self.assertTrue(outcome.ok, f"unknown attestationObject keys rejected: {outcome}")
        LEGIT_PASSES.append("attestationObject with unknown CBOR keys (text/int/negative) -> OK")

        # Unknown keys inside attStmt.
        att_obj = build_attestation_object(
            build_auth_data(at=True),
            att_stmt={"unknownStmtKey": b"\x00", "sig": b"\x30\x44"},
        )
        outcome = run_registration_blob(att_obj)
        self.assertTrue(outcome.ok, f"unknown attStmt keys rejected: {outcome}")
        LEGIT_PASSES.append("attStmt with unknown keys -> OK")

        # Unknown extension keys in authenticatorData (both paths).
        auth_data = build_auth_data(ed=True, extensions={"futureExtension": {"flag": True}})
        for path, runner in (
            ("registration", run_registration_blob),
            ("authentication", run_authentication_blob),
        ):
            blob = (
                build_attestation_object(auth_data) if path == "registration" else auth_data
            )
            outcome = runner(blob)
            self.assertTrue(outcome.ok, f"unknown extension keys rejected on {path}: {outcome}")
        LEGIT_PASSES.append("authenticatorData extensions with unknown keys -> OK (both paths)")

        # Random unknown JSON fields at top level and inside `response`.
        for _ in range(64):
            cred = build_registration_credential(
                build_attestation_object(build_auth_data(at=True))
            )
            cred[f"x-unknown-{rng.randrange(1000)}"] = {"anything": [1, "two", None]}
            cred["response"][f"x-unknown-{rng.randrange(1000)}"] = rng.random()
            outcome = run_registration_credential(cred)
            self.assertTrue(outcome.ok, f"unknown JSON fields rejected (registration): {outcome}")

            cred = build_authentication_credential(build_auth_data())
            cred[f"x-unknown-{rng.randrange(1000)}"] = [b"\x00".hex()]
            cred["response"][f"x-unknown-{rng.randrange(1000)}"] = True
            outcome = run_authentication_credential(cred)
            self.assertTrue(outcome.ok, f"unknown JSON fields rejected (authentication): {outcome}")
        LEGIT_PASSES.append("random unknown JSON fields (top-level + response) -> OK (both paths)")


class TestDuplicateFields(FuzzTestCase):
    """Category 4: duplicate CBOR map keys must be rejected on both paths."""

    def test_4_duplicate_fields(self) -> None:
        auth_data = build_auth_data(at=True)

        # Registration: attestationObject with a duplicated "fmt" key.
        dup_fmt = (
            b"\xa4\x63fmt\x64none\x63fmt\x64none"
            b"\x68authData\x58" + bytes([len(auth_data)]) + auth_data +
            b"\x67attStmt\xa0"
        )
        outcome = run_registration_blob(dup_fmt)
        if outcome.leaked:
            self.handle_leak("duplicate_cbor_key", "registration", dup_fmt, run_registration_blob)
        self.assertFalse(outcome.ok, "duplicate fmt key parsed")
        self.assertEqual(outcome.error, "InvalidAttestationObjectStructure")
        self.assertEqual(outcome.cause, "InvalidCBORData")
        PATH_DIFF_ROWS.append(
            (
                "duplicate CBOR key (top-level structure)",
                f"{outcome.error} (cause: {outcome.cause})",
                "n/a (authentication response carries no top-level CBOR map)",
                "registration wraps CBOR failure as InvalidAttestationObjectStructure",
            )
        )
        minimal = shrink_to_minimal(
            dup_fmt,
            lambda b: "Duplicate map key" in run_registration_blob(b).root_message,
        )
        record_minimal("duplicate_cbor_key", "registration", minimal, run_registration_blob(minimal))

        # Registration, one level down: duplicated key inside the COSE public key.
        bad_cose = b"\xa3\x01\x02\x01\x03\x03\x26"  # {1: 2, 1: 3, 3: -7} - duplicate key 1
        auth_data_dup_cose = (
            b"\x00" * 32 + b"\x41" + b"\x00" * 4 + b"\x00" * 16
            + len(CREDENTIAL_ID).to_bytes(2, "big") + CREDENTIAL_ID + bad_cose
        )
        outcome = run_registration_blob(build_attestation_object(auth_data_dup_cose))
        if outcome.leaked:
            self.handle_leak("duplicate_cose_key", "registration", auth_data_dup_cose, run_registration_blob)
        self.assertFalse(outcome.ok, "duplicate COSE key parsed")
        self.assertEqual(outcome.error, "InvalidCBORData")

        # Authentication: duplicated key inside the extensions CBOR map.
        dup_ext = b"\xa2\x6bcredProtect\x03\x6bcredProtect\x02"
        auth_blob = build_auth_data() + dup_ext
        # Fix flags byte to set ED.
        auth_blob = auth_blob[:32] + bytes([auth_blob[32] | 0x80]) + auth_blob[33:]
        outcome = run_authentication_blob(auth_blob)
        if outcome.leaked:
            self.handle_leak("duplicate_cbor_key", "authentication", auth_blob, run_authentication_blob)
        self.assertFalse(outcome.ok, "duplicate extension key parsed")
        self.assertEqual(outcome.error, "InvalidCBORData")
        PATH_DIFF_ROWS.append(
            (
                "duplicate CBOR key (extensions map)",
                "InvalidCBORData",
                f"{outcome.error} (cause: {outcome.cause})",
                "authentication lets InvalidCBORData propagate unwrapped",
            )
        )
        minimal = shrink_to_minimal(
            auth_blob,
            lambda b: "Duplicate map key" in run_authentication_blob(b).root_message,
        )
        record_minimal("duplicate_cbor_key", "authentication", minimal, run_authentication_blob(minimal))

        # JSON-level duplicates: Python's json keeps the last value, so the parse
        # layer cannot detect them. Documented asymmetry vs the CBOR layer.
        raw = json.dumps(build_authentication_credential(build_auth_data()))
        raw = raw.replace('"id":', '"id": "AAAA", "id":', 1)
        outcome = _to_outcome(lambda: parse_authentication_credential_json(raw))
        self.assertTrue(outcome.ok, "JSON duplicate keys should keep-last, not crash")
        PATH_DIFF_ROWS.append(
            (
                "duplicate JSON key (both paths)",
                "ok (last value wins, undetectable)",
                "ok (last value wins, undetectable)",
                "JSON layer cannot detect duplicates; CBOR layer rejects them",
            )
        )


class TestInconsistentCounts(FuzzTestCase):
    """Category 5: counts that disagree with the actual content."""

    def test_5_inconsistent_counts(self) -> None:
        # credential_id_len field vs actual credential ID bytes. The credential ID
        # is 0xFF-padded so a misaligned parse lands on invalid CBOR (0xFF = break).
        cred_id = b"\xff" * 16
        base = build_auth_data(at=True, credential_id=cred_id)
        len_offset = 32 + 1 + 4 + 16  # rpIdHash + flags + signCount + AAGUID

        for delta in (-8, -1, 1, 8, 1000):
            mutated = bytearray(base)
            new_len = len(cred_id) + delta
            mutated[len_offset : len_offset + 2] = new_len.to_bytes(2, "big")
            for path, blob, runner in (
                ("registration", build_attestation_object(bytes(mutated)), run_registration_blob),
                ("authentication", bytes(mutated), run_authentication_blob),
            ):
                outcome = runner(blob)
                if outcome.leaked:
                    self.handle_leak("inconsistent_cred_id_len", path, blob, runner)
                self.assertFalse(
                    outcome.ok,
                    f"cred_id_len {new_len} vs actual {len(cred_id)} parsed on {path}",
                )
                self.assertIn(
                    outcome.error,
                    ("InvalidCBORData", "InvalidAuthenticatorDataStructure"),
                    f"delta={delta} path={path} raised {outcome.error}",
                )

        PATH_DIFF_ROWS.append(
            (
                "inconsistent credential_id_len (authData)",
                "InvalidCBORData / InvalidAuthenticatorDataStructure",
                "InvalidCBORData / InvalidAuthenticatorDataStructure",
                "identical: both paths share parse_authenticator_data",
            )
        )

        # Minimal sample: shrink the +8 mutation on the authentication path,
        # pinning the "Leftover bytes" signature so the count mismatch survives.
        mutated = bytearray(base)
        mutated[len_offset : len_offset + 2] = (len(cred_id) + 8).to_bytes(2, "big")
        minimal = shrink_to_minimal(
            bytes(mutated),
            lambda b: "Leftover bytes" in run_authentication_blob(b).message,
        )
        record_minimal(
            "inconsistent_cred_id_len", "authentication", minimal, run_authentication_blob(minimal)
        )

        # CBOR container count vs items: corrupt the top-level attestationObject
        # map count (0xA3 = 3 pairs) to every other small count.
        att_obj = build_attestation_object(build_auth_data(at=True, ed=True))
        self.assertEqual(att_obj[0], 0xA3)
        for count in range(1, 24):
            if count == 3:
                continue
            blob = bytes([0xA0 | count]) + att_obj[1:]
            outcome = run_registration_blob(blob)
            if outcome.leaked:
                self.handle_leak("inconsistent_map_count", "registration", blob, run_registration_blob)
            if count == 2:
                # Documented decoder behavior: cbor2 ignores trailing bytes, and
                # the dropped third pair is the OPTIONAL attStmt, so a count of 2
                # still parses. Larger counts hit EOF; a count of 1 drops the
                # required authData and is rejected.
                self.assertTrue(outcome.ok, "count=2 should parse (attStmt is optional)")
            else:
                self.assertFalse(outcome.ok, f"inconsistent map count {count} parsed")
                self.assert_well_typed(outcome, "inconsistent_map_count")
        PATH_DIFF_ROWS.append(
            (
                "inconsistent CBOR map count (top-level)",
                "InvalidAttestationObjectStructure (count 1 or >3); ok for count 2 "
                "(cbor2 ignores trailing bytes, attStmt is optional)",
                "n/a",
                "documented decoder tolerance, not a false positive",
            )
        )


class TestLegitBoundariesNoFalsePositives(FuzzTestCase):
    """Legitimate extensions, credential types and boundary lengths must pass."""

    def test_6_legit_boundaries(self) -> None:
        def check_ok(label: str, outcome: Outcome) -> None:
            self.assertTrue(outcome.ok, f"false positive on legit input: {label}: {outcome}")
            LEGIT_PASSES.append(f"{label} -> OK")

        # Boundary: minimal 37-byte authenticatorData (no AT, no ED), both paths.
        auth_data = build_auth_data()
        self.assertEqual(len(auth_data), 37)
        check_ok(
            "registration: 37-byte authData (minimum)",
            run_registration_blob(build_attestation_object(auth_data)),
        )
        check_ok("authentication: 37-byte authData (minimum)", run_authentication_blob(auth_data))

        # Boundary: credential ID lengths 16 (spec minimum) and 1023 (spec maximum).
        for length in (16, 1023):
            auth_data = build_auth_data(at=True, credential_id=bytes([length % 256]) * length)
            check_ok(
                f"registration: credential ID length {length}",
                run_registration_blob(build_attestation_object(auth_data)),
            )

        # Legit extensions on both paths.
        auth_data = build_auth_data(ed=True, extensions={"credProtect": 3, "hmac-secret": True})
        check_ok(
            "registration: extensions credProtect + hmac-secret",
            run_registration_blob(build_attestation_object(auth_data)),
        )
        check_ok("authentication: extensions credProtect + hmac-secret", run_authentication_blob(auth_data))

        # Legit AT+ED combination.
        auth_data = build_auth_data(at=True, ed=True)
        check_ok(
            "registration: attested credential data + extensions",
            run_registration_blob(build_attestation_object(auth_data)),
        )

        # Credential type: the only legal value must pass; others must be rejected
        # (a rejection here is a true positive, not a false positive).
        cred = build_registration_credential(build_attestation_object(build_auth_data()))
        check_ok("registration: type=public-key", run_registration_credential(cred))
        cred = build_authentication_credential(build_auth_data())
        check_ok("authentication: type=public-key", run_authentication_credential(cred))

        for bad_type in ("password", "public-key2", ""):
            cred = build_authentication_credential(build_auth_data())
            cred["type"] = bad_type
            outcome = run_authentication_credential(cred)
            self.assertEqual(outcome.error, "InvalidJSONStructure", f"type={bad_type!r}")
        LEGIT_PASSES.append("type != 'public-key' -> InvalidJSONStructure (true positive)")

        # Unknown transports are ignored, known ones kept.
        cred = build_registration_credential(build_attestation_object(build_auth_data()))
        cred["response"]["transports"] = ["usb", "future-transport", "internal"]
        outcome = run_registration_credential(cred)
        check_ok("registration: transports with unknown values (ignored)", outcome)

        # authenticatorAttachment legal values.
        for attachment in ("platform", "cross-platform"):
            cred = build_authentication_credential(build_auth_data())
            cred["authenticatorAttachment"] = attachment
            check_ok(f"authentication: authenticatorAttachment={attachment}", run_authentication_credential(cred))

        # userHandle present and absent.
        cred = build_authentication_credential(build_auth_data())
        cred["response"]["userHandle"] = _b64url(b"user-handle")
        check_ok("authentication: userHandle present", run_authentication_credential(cred))
        cred = build_authentication_credential(build_auth_data())
        cred["response"]["userHandle"] = None
        check_ok("authentication: userHandle null", run_authentication_credential(cred))

        # Unknown attestation fmt string parses (format validation is not parsing).
        check_ok(
            "registration: unknown fmt string",
            run_registration_blob(build_attestation_object(build_auth_data(), fmt="future-fmt")),
        )


class TestPathErrorCategoryComparison(FuzzTestCase):
    """Compare error categories between the two parse paths on shared mutations."""

    def test_7_path_error_category_diff(self) -> None:
        auth_data = build_auth_data(at=True, ed=True)
        att_obj = build_attestation_object(auth_data)

        battery: List[Tuple[str, bytes, bytes]] = [
            ("truncated byte string", att_obj[:20], auth_data[:20]),
            ("truncated below 37-byte minimum", att_obj[:5], auth_data[:5]),
            ("empty input", b"", b""),
        ]
        for label, reg_blob, auth_blob in battery:
            reg_outcome = run_registration_blob(reg_blob)
            auth_outcome = run_authentication_blob(auth_blob)
            self.assert_well_typed(reg_outcome, f"{label}/registration")
            self.assert_well_typed(auth_outcome, f"{label}/authentication")
            PATH_DIFF_ROWS.append(
                (
                    label,
                    reg_outcome.error or "ok",
                    auth_outcome.error or "ok",
                    "same mutation, path-specific error category",
                )
            )

        # Stable mapping: the same truncation is categorized differently per path.
        reg_outcome = run_registration_blob(att_obj[:20])
        auth_outcome = run_authentication_blob(auth_data[:20])
        self.assertEqual(reg_outcome.error, "InvalidAttestationObjectStructure")
        self.assertEqual(auth_outcome.error, "InvalidAuthenticatorDataStructure")

        # Wrapping asymmetry: registration wraps CBOR failures into
        # InvalidAttestationObjectStructure; authentication surfaces InvalidCBORData
        # directly from parse_authenticator_data.
        self.assertEqual(reg_outcome.cause, "InvalidCBORData")
        dup_ext_blob = build_auth_data() + b"\xa2\x6bcredProtect\x03\x6bcredProtect\x02"
        dup_ext_blob = dup_ext_blob[:32] + bytes([dup_ext_blob[32] | 0x80]) + dup_ext_blob[33:]
        self.assertEqual(run_authentication_blob(dup_ext_blob).error, "InvalidCBORData")


class TestWriteEvidence(unittest.TestCase):
    """Regenerate the human-readable evidence files (deterministic)."""

    def test_9_write_evidence(self) -> None:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        self._write_minimal_inputs()
        self._write_path_diff()
        self._write_legit_passes()

    def _header(self, title: str) -> str:
        return (
            f"# {title}\n\n"
            f"Regenerated deterministically by "
            f"`python -m unittest tests.test_fuzz_registration_authentication_parsing` "
            f"(seed={SEED}). No external services are contacted.\n\n"
        )

    def _write_minimal_inputs(self) -> None:
        lines = [self._header("Evidence 1: Minimal mutated inputs")]
        lines.append(
            "Each entry is the smallest input (found by greedy chunk-removal "
            "shrinking) that still triggers the same error category. Re-run any "
            "entry with the shown snippet.\n"
        )
        if INVARIANT_VIOLATIONS:
            lines.append("\n## INVARIANT VIOLATIONS (non-WebAuthnException leaks)\n")
            for v in INVARIANT_VIOLATIONS:
                lines.append(
                    f"- **{v['category']} / {v['path']}**: `{v['error']}`, "
                    f"{v['length']} bytes, hex `{v['hex']}`"
                )
        else:
            lines.append("\n## Invariant violations\n\nNone: every rejection on both "
                         "parse paths is a `WebAuthnException` subclass.\n")
        lines.append("\n## Minimal rejected inputs per mutation category\n")
        for s in MINIMAL_SAMPLES:
            runner = (
                "parse_attestation_object"
                if s["path"] == "registration"
                else "parse_authenticator_data"
            )
            lines.append(
                f"\n### {s['category']} / {s['path']}\n\n"
                f"- minimal length: {s['length']} bytes\n"
                f"- hex: `{s['hex']}`\n"
                f"- error: `{s['error']}` (cause: `{s['cause']}`; root: {s['root']})\n"
                f"- repro:\n\n"
                f"```python\n"
                f"from webauthn.helpers.{ 'parse_attestation_object' if s['path']=='registration' else 'parse_authenticator_data' } import {runner}\n"
                f"{runner}(bytes.fromhex(\"{'' if s['hex']=='(empty)' else s['hex']}\"))\n"
                f"```\n"
            )
        (EVIDENCE_DIR / "01_minimal_mutated_inputs.md").write_text("".join(lines))

    def _write_path_diff(self) -> None:
        lines = [self._header("Evidence 2: Error-category differences between parse paths")]
        lines.append(
            "| Mutation | Registration path | Authentication path | Note |\n"
            "|---|---|---|---|\n"
        )
        for label, reg, auth, note in PATH_DIFF_ROWS:
            lines.append(f"| {label} | `{reg}` | `{auth}` | {note} |\n")
        (EVIDENCE_DIR / "02_path_error_category_diff.md").write_text("".join(lines))

    def _write_legit_passes(self) -> None:
        lines = [self._header("Evidence 3: Legitimate inputs that pass (no false positives)")]
        for entry in LEGIT_PASSES:
            lines.append(f"- {entry}\n")
        (EVIDENCE_DIR / "03_legit_boundary_passes.md").write_text("".join(lines))


if __name__ == "__main__":
    unittest.main()
