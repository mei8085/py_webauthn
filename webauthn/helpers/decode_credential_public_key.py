from dataclasses import dataclass
from typing import Any, Dict, Tuple, Union

from .cose import COSECRV, COSEKTY, COSEAlgorithmIdentifier, COSEKey
from .exceptions import InvalidPublicKeyStructure, UnsupportedPublicKeyType
from .parse_cbor import parse_cbor


@dataclass
class DecodedOKPPublicKey:
    kty: COSEKTY
    alg: COSEAlgorithmIdentifier
    crv: COSECRV
    x: bytes


@dataclass
class DecodedEC2PublicKey:
    kty: COSEKTY
    alg: COSEAlgorithmIdentifier
    crv: COSECRV
    x: bytes
    y: bytes


@dataclass
class DecodedRSAPublicKey:
    kty: COSEKTY
    alg: COSEAlgorithmIdentifier
    n: bytes
    e: bytes


@dataclass
class DecodedMLDSAPublicKey:
    kty: COSEKTY
    alg: COSEAlgorithmIdentifier
    pub: bytes


# The exact (curve, per-coordinate byte length) combinations that each EC2 COSE
# algorithm identifier is allowed to use. Coordinate lengths come from the
# field sizes defined for each NIST curve in RFC 9053 §7.1:
#   - P-256: 32-byte x and y
#   - P-521: 66-byte x and y (ceil(521 / 8))
# P-384 is intentionally absent: none of the COSE algorithm identifiers that
# this library supports is defined to be used with it (ES384 is not registered
# for WebAuthn use here), so an ES256/ES512 key claiming P-384 must be rejected.
_EC2_ALG_SPECS: Dict[COSEAlgorithmIdentifier, Tuple[COSECRV, int]] = {
    COSEAlgorithmIdentifier.ECDSA_SHA_256: (COSECRV.P256, 32),
    COSEAlgorithmIdentifier.ECDSA_SHA_512: (COSECRV.P521, 66),
}

# EdDSA (alg -8) is only defined for the Ed25519 OKP curve, whose single public
# key coordinate x is exactly 32 bytes long (RFC 8037).
_OKP_ALG_SPECS: Dict[COSEAlgorithmIdentifier, Tuple[COSECRV, int]] = {
    COSEAlgorithmIdentifier.EDDSA: (COSECRV.ED25519, 32),
}

# Every RSA COSE algorithm identifier supported by this library may only appear
# on an RSA (kty 3) key. There is no curve and no fixed coordinate length for
# RSA keys; n and e are only required to be present as byte strings.
_RSA_ALGS: Tuple[COSEAlgorithmIdentifier, ...] = (
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_384,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_1,
)

# Exact raw public key byte lengths per FIPS 204 ML-DSA parameter set. A
# "pub" parameter of any other length cannot belong to the claimed algorithm.
_ML_DSA_PUB_LENGTHS: Dict[COSEAlgorithmIdentifier, int] = {
    COSEAlgorithmIdentifier.ML_DSA_44: 1312,
    COSEAlgorithmIdentifier.ML_DSA_65: 1952,
    COSEAlgorithmIdentifier.ML_DSA_87: 2592,
}

# The only COSE map keys that each key type is allowed to contain. Anything
# else is an unhandled field and must cause the key to be rejected instead of
# being silently ignored.
_EXPECTED_KEYS: Dict[COSEKTY, Tuple[COSEKey, ...]] = {
    COSEKTY.OKP: (COSEKey.KTY, COSEKey.ALG, COSEKey.CRV, COSEKey.X),
    COSEKTY.EC2: (
        COSEKey.KTY,
        COSEKey.ALG,
        COSEKey.CRV,
        COSEKey.X,
        COSEKey.Y,
    ),
    COSEKTY.RSA: (COSEKey.KTY, COSEKey.ALG, COSEKey.N, COSEKey.E),
    COSEKTY.ML_DSA: (COSEKey.KTY, COSEKey.ALG, COSEKey.PUB),
}


def _coerce_enum(value: Any, enum_type: Any, label: str) -> Any:
    """Turn a raw integer COSE parameter into its enum member.

    Booleans are rejected explicitly because ``True``/``False`` compare equal to
    the integers 1/0 in Python and must not be accepted as COSE identifiers.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidPublicKeyStructure(
            f'Credential public key parameter "{label}" must be an integer, got {type(value).__name__}'
        )

    try:
        return enum_type(value)
    except ValueError:
        raise InvalidPublicKeyStructure(
            f'Credential public key parameter "{label}" had unrecognized value {value}'
        )


def _require_int(decoded_key: Dict[Any, Any], cose_key: COSEKey, enum_type: Any, label: str) -> Any:
    """Fetch a required integer COSE parameter and bind it to its enum."""
    if cose_key not in decoded_key:
        raise InvalidPublicKeyStructure(
            f'Credential public key missing required parameter "{label}"'
        )

    return _coerce_enum(decoded_key[cose_key], enum_type, label)


def _require_bytes(decoded_key: Dict[Any, Any], cose_key: COSEKey, label: str) -> bytes:
    """Fetch a required byte-string COSE parameter, rejecting anything else."""
    if cose_key not in decoded_key:
        raise InvalidPublicKeyStructure(
            f'Credential public key missing required parameter "{label}"'
        )

    value = decoded_key[cose_key]

    if isinstance(value, bool) or not isinstance(value, bytes) or len(value) == 0:
        raise InvalidPublicKeyStructure(
            f'Credential public key parameter "{label}" must be a non-empty byte string'
        )

    return value


def _reject_unexpected_fields(
    decoded_key: Dict[Any, Any], expected: Tuple[COSEKey, ...], kty: COSEKTY
) -> None:
    """Refuse keys carrying map fields that the claimed key type does not define."""
    expected_values = {field.value for field in expected}
    unexpected = [field for field in decoded_key.keys() if field not in expected_values]

    if unexpected:
        raise InvalidPublicKeyStructure(
            f'Credential public key of kty {kty.name} contained unexpected field(s) {unexpected}'
        )


def decode_credential_public_key(
    key: bytes,
) -> Union[DecodedOKPPublicKey, DecodedEC2PublicKey, DecodedRSAPublicKey, DecodedMLDSAPublicKey]:
    """
    Decode a CBOR-encoded public key and turn it into a data structure.

    Supports OKP, EC2, RSA, and ML-DSA public keys. The algorithm identifier,
    key type, curve identifier (where applicable), and coordinate/public key
    byte lengths are validated against the combinations allowed by the COSE
    and WebAuthn specifications: a key whose parameters are inconsistent with
    each other, or that contains fields not defined for its key type, is
    rejected with ``InvalidPublicKeyStructure``. The returned dataclass carries
    the confirmed (enum-bound) algorithm and curve so that downstream signature
    verification never has to re-interpret the raw COSE fields.
    """
    # Occasionally we might be given a public key in an "uncompressed" format,
    # typically from older U2F security keys. As per the FIDO spec this is indicated by
    # a leading 0x04 "uncompressed point compression method" format byte. In that case
    # we need to fill in some blanks to turn it into a full EC2 key for signature
    # verification
    #
    # See https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats
    if len(key) == 0:
        raise InvalidPublicKeyStructure("Credential public key was empty")

    if key[0] == 0x04:
        # An uncompressed P-256 point is exactly 65 bytes: 0x04 plus two
        # 32-byte coordinates. Anything shorter cannot be a valid point.
        if len(key) != 65:
            raise InvalidPublicKeyStructure(
                f"Uncompressed EC2 public key must be 65 bytes, got {len(key)}"
            )

        return DecodedEC2PublicKey(
            kty=COSEKTY.EC2,
            alg=COSEAlgorithmIdentifier.ECDSA_SHA_256,
            crv=COSECRV.P256,
            x=key[1:33],
            y=key[33:65],
        )

    decoded_key: Dict[Any, Any] = parse_cbor(key)

    if not isinstance(decoded_key, dict):
        raise InvalidPublicKeyStructure("Credential public key CBOR must be a map")

    if COSEKey.KTY not in decoded_key:
        raise InvalidPublicKeyStructure("Credential public key missing kty")
    if COSEKey.ALG not in decoded_key:
        raise InvalidPublicKeyStructure("Credential public key missing alg")

    # An unrecognized kty keeps its historical classification so callers can
    # continue to distinguish "key type we don't know" from "malformed key of
    # a type we do know"
    kty_value = decoded_key[COSEKey.KTY]
    if isinstance(kty_value, bool) or not isinstance(kty_value, int):
        raise InvalidPublicKeyStructure(
            f'Credential public key parameter "kty" must be an integer, got {type(kty_value).__name__}'
        )
    try:
        kty = COSEKTY(kty_value)
    except ValueError:
        raise UnsupportedPublicKeyType(f'Unsupported credential public key type "{kty_value}"')

    alg = _require_int(decoded_key, COSEKey.ALG, COSEAlgorithmIdentifier, "alg")

    if kty == COSEKTY.OKP:
        _reject_unexpected_fields(decoded_key, _EXPECTED_KEYS[COSEKTY.OKP], kty)

        if alg not in _OKP_ALG_SPECS:
            raise InvalidPublicKeyStructure(
                f"OKP credential public key alg {alg.name} is not supported"
            )

        expected_crv, expected_x_len = _OKP_ALG_SPECS[alg]
        crv = _require_int(decoded_key, COSEKey.CRV, COSECRV, "crv")

        if crv != expected_crv:
            raise InvalidPublicKeyStructure(
                f"OKP credential public key alg {alg.name} cannot be used with crv {crv.name}, "
                f"expected {expected_crv.name}"
            )

        x = _require_bytes(decoded_key, COSEKey.X, "x")
        if len(x) != expected_x_len:
            raise InvalidPublicKeyStructure(
                f"OKP credential public key x must be {expected_x_len} bytes for "
                f"{expected_crv.name}, got {len(x)}"
            )

        return DecodedOKPPublicKey(kty=kty, alg=alg, crv=crv, x=x)
    elif kty == COSEKTY.EC2:
        _reject_unexpected_fields(decoded_key, _EXPECTED_KEYS[COSEKTY.EC2], kty)

        if alg not in _EC2_ALG_SPECS:
            raise InvalidPublicKeyStructure(
                f"EC2 credential public key alg {alg.name} is not supported"
            )

        expected_crv, expected_coord_len = _EC2_ALG_SPECS[alg]
        crv = _require_int(decoded_key, COSEKey.CRV, COSECRV, "crv")

        if crv != expected_crv:
            raise InvalidPublicKeyStructure(
                f"EC2 credential public key alg {alg.name} cannot be used with crv {crv.name}, "
                f"expected {expected_crv.name}"
            )

        x = _require_bytes(decoded_key, COSEKey.X, "x")
        y = _require_bytes(decoded_key, COSEKey.Y, "y")

        if len(x) != expected_coord_len:
            raise InvalidPublicKeyStructure(
                f"EC2 credential public key x must be {expected_coord_len} bytes for "
                f"{expected_crv.name} with alg {alg.name}, got {len(x)}"
            )
        if len(y) != expected_coord_len:
            raise InvalidPublicKeyStructure(
                f"EC2 credential public key y must be {expected_coord_len} bytes for "
                f"{expected_crv.name} with alg {alg.name}, got {len(y)}"
            )

        return DecodedEC2PublicKey(kty=kty, alg=alg, crv=crv, x=x, y=y)
    elif kty == COSEKTY.RSA:
        _reject_unexpected_fields(decoded_key, _EXPECTED_KEYS[COSEKTY.RSA], kty)

        if alg not in _RSA_ALGS:
            raise InvalidPublicKeyStructure(
                f"RSA credential public key alg {alg.name} is not supported"
            )

        n = _require_bytes(decoded_key, COSEKey.N, "n")
        e = _require_bytes(decoded_key, COSEKey.E, "e")

        return DecodedRSAPublicKey(kty=kty, alg=alg, n=n, e=e)
    elif kty == COSEKTY.ML_DSA:
        _reject_unexpected_fields(decoded_key, _EXPECTED_KEYS[COSEKTY.ML_DSA], kty)

        if alg not in _ML_DSA_PUB_LENGTHS:
            raise InvalidPublicKeyStructure(
                f"ML-DSA credential public key alg {alg.name} is not supported"
            )

        pub = _require_bytes(decoded_key, COSEKey.PUB, "pub")
        expected_pub_len = _ML_DSA_PUB_LENGTHS[alg]

        if len(pub) != expected_pub_len:
            raise InvalidPublicKeyStructure(
                f"ML-DSA credential public key pub must be {expected_pub_len} bytes for "
                f"alg {alg.name}, got {len(pub)}"
            )

        return DecodedMLDSAPublicKey(kty=kty, alg=alg, pub=pub)

    # Unreachable in practice: unknown kty values are mapped to
    # UnsupportedPublicKeyType before this point, but keep the guard explicit
    raise UnsupportedPublicKeyType(f'Unsupported credential public key type "{kty}"')
