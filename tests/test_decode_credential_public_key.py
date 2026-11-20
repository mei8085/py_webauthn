from typing import Any, Dict
from unittest import TestCase

import cbor2

from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.cose import COSECRV, COSEKTY, COSEAlgorithmIdentifier, COSEKey
from webauthn.helpers.decode_credential_public_key import (
    DecodedEC2PublicKey,
    DecodedMLDSAPublicKey,
    DecodedOKPPublicKey,
    DecodedRSAPublicKey,
    decode_credential_public_key,
)
from webauthn.helpers.exceptions import (
    InvalidPublicKeyStructure,
    UnsupportedPublicKeyType,
)

K = COSEKey


def _encode_key(key_map: Dict[Any, Any]) -> bytes:
    return cbor2.dumps(key_map)


class TestDecodeCredentialPublicKey(TestCase):
    def test_decodes_ec2_public_key(self) -> None:
        decoded = decode_credential_public_key(
            base64url_to_bytes(
                "pQECAyYgASFYIDDHBDxTqWP4yZZnAa524L6uPuwhireUwRD5sXY6U2gxIlggxuwbECbDdNfTTegnc174oYdusZiMmJgct0yI_ulrJGI"
            )
        )

        assert isinstance(decoded, DecodedEC2PublicKey)
        assert decoded.kty == COSEKTY.EC2
        assert decoded.alg == COSEAlgorithmIdentifier.ECDSA_SHA_256
        assert decoded.crv == 1
        assert (
            decoded.x
            and bytes_to_base64url(decoded.x) == "MMcEPFOpY_jJlmcBrnbgvq4-7CGKt5TBEPmxdjpTaDE"
        )
        assert (
            decoded.y
            and bytes_to_base64url(decoded.y) == "xuwbECbDdNfTTegnc174oYdusZiMmJgct0yI_ulrJGI"
        )

    def test_decode_rsa_public_key(self) -> None:
        decoded = decode_credential_public_key(
            base64url_to_bytes(
                "pAEDAzkBACBZAQDxfpXrj0ba_AH30JJ_-W7BHSOPugOD8aEDdNBKc1gjB9AmV3FPl2aL0fwiOMKtM_byI24qXb2FzcyjC7HUVkHRtzkAQnahXckI4wY_01koaY6iwXuIE3Ya0Zjs2iZyz6u4G_abGnWdObqa_kHxc3CHR7Xy5MDkAkKyX6TqU0tgHZcEhDd_Lb5ONJDwg4wvKlZBtZYElfMuZ6lonoRZ7qR_81rGkDZyFaxp6RlyvzEbo4ijeIaHQylqCz-oFm03ifZMOfRHYuF4uTjJDRH-g4BW1f3rdi7DTHk1hJnIw1IyL_VFIQ9NifkAguYjNCySCUNpYli2eMrPhAu5dYJFFjINIUMBAAE"
            )
        )

        assert isinstance(decoded, DecodedRSAPublicKey)
        assert decoded.kty == COSEKTY.RSA
        assert decoded.alg == COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256
        assert decoded.e and bytes_to_base64url(decoded.e) == "AQAB"
        assert (
            decoded.n
            and bytes_to_base64url(decoded.n)
            == "8X6V649G2vwB99CSf_luwR0jj7oDg_GhA3TQSnNYIwfQJldxT5dmi9H8IjjCrTP28iNuKl29hc3Mowux1FZB0bc5AEJ2oV3JCOMGP9NZKGmOosF7iBN2GtGY7Nomcs-ruBv2mxp1nTm6mv5B8XNwh0e18uTA5AJCsl-k6lNLYB2XBIQ3fy2-TjSQ8IOMLypWQbWWBJXzLmepaJ6EWe6kf_NaxpA2chWsaekZcr8xG6OIo3iGh0Mpags_qBZtN4n2TDn0R2LheLk4yQ0R_oOAVtX963Yuw0x5NYSZyMNSMi_1RSEPTYn5AILmIzQskglDaWJYtnjKz4QLuXWCRRYyDQ"
        )

    def test_decode_uncompressed_ec2_public_key(self) -> None:
        decoded = decode_credential_public_key(
            base64url_to_bytes(
                "BBaxKZueVyr5ICDfosygxwRflSdPUcNheZhThXCeTFTNo0EM9dj0V+xJ1JwpE2XZ/8NRIt5KVvr71Zl0rB8BWOs="
            )
        )

        assert isinstance(decoded, DecodedEC2PublicKey)
        assert decoded.kty == COSEKTY.EC2
        assert decoded.alg == COSEAlgorithmIdentifier.ECDSA_SHA_256
        assert decoded.crv == 1
        assert (
            decoded.x
            and bytes_to_base64url(decoded.x) == "FrEpm55XKvkgIN-izKDHBF-VJ09Rw2F5mFOFcJ5MVM0"
        )
        assert (
            decoded.y
            and bytes_to_base64url(decoded.y) == "o0EM9dj0V-xJ1JwpE2XZ_8NRIt5KVvr71Zl0rB8BWOs"
        )

    def test_decodes_well_formed_ec2_p256_with_enum_binding(self) -> None:
        key = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            K.CRV: COSECRV.P256,
            K.X: b"\x11" * 32,
            K.Y: b"\x22" * 32,
        }

        decoded = decode_credential_public_key(_encode_key(key))

        assert isinstance(decoded, DecodedEC2PublicKey)
        # The confirmed fields are enum members, not the raw integer inputs
        assert decoded.kty is COSEKTY.EC2
        assert decoded.alg is COSEAlgorithmIdentifier.ECDSA_SHA_256
        assert decoded.crv is COSECRV.P256

    def test_decodes_well_formed_ec2_p521(self) -> None:
        key = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_512,
            K.CRV: COSECRV.P521,
            K.X: b"\x11" * 66,
            K.Y: b"\x22" * 66,
        }

        decoded = decode_credential_public_key(_encode_key(key))

        assert isinstance(decoded, DecodedEC2PublicKey)
        assert decoded.alg is COSEAlgorithmIdentifier.ECDSA_SHA_512
        assert decoded.crv is COSECRV.P521

    def test_decodes_well_formed_okp_ed25519(self) -> None:
        key = {
            K.KTY: COSEKTY.OKP,
            K.ALG: COSEAlgorithmIdentifier.EDDSA,
            K.CRV: COSECRV.ED25519,
            K.X: b"\x33" * 32,
        }

        decoded = decode_credential_public_key(_encode_key(key))

        assert isinstance(decoded, DecodedOKPPublicKey)
        assert decoded.alg is COSEAlgorithmIdentifier.EDDSA
        assert decoded.crv is COSECRV.ED25519

    def test_decodes_well_formed_ml_dsa_keys(self) -> None:
        for alg, pub_len in (
            (COSEAlgorithmIdentifier.ML_DSA_44, 1312),
            (COSEAlgorithmIdentifier.ML_DSA_65, 1952),
            (COSEAlgorithmIdentifier.ML_DSA_87, 2592),
        ):
            key = {
                K.KTY: COSEKTY.ML_DSA,
                K.ALG: alg,
                K.PUB: b"\x44" * pub_len,
            }

            decoded = decode_credential_public_key(_encode_key(key))

            assert isinstance(decoded, DecodedMLDSAPublicKey)
            assert decoded.alg is alg
            assert len(decoded.pub) == pub_len

    def test_rejects_ec2_alg_curve_mismatches(self) -> None:
        base = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            K.CRV: COSECRV.P256,
            K.X: b"\x11" * 32,
            K.Y: b"\x22" * 32,
        }

        # ES256 may not be paired with P-521 or P-384
        for bad_crv in (COSECRV.P521, COSECRV.P384):
            bad_key = dict(base)
            bad_key[K.CRV] = bad_crv
            with self.assertRaises(InvalidPublicKeyStructure):
                decode_credential_public_key(_encode_key(bad_key))

        # ES512 may not be paired with P-256
        bad_key = dict(base)
        bad_key[K.ALG] = COSEAlgorithmIdentifier.ECDSA_SHA_512
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

    def test_rejects_ec2_coordinate_length_mismatches(self) -> None:
        p256 = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            K.CRV: COSECRV.P256,
            K.X: b"\x11" * 32,
            K.Y: b"\x22" * 32,
        }

        for field_name, field, bad_len in (
            ("x", K.X, 31),
            ("x", K.X, 33),
            ("y", K.Y, 31),
            ("y", K.Y, 33),
        ):
            bad_key = dict(p256)
            bad_key[field] = b"\x00" * bad_len
            with self.assertRaises(InvalidPublicKeyStructure):
                decode_credential_public_key(_encode_key(bad_key))

        # P-521 coordinates must be 66 bytes, not 32
        p521_bad = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_512,
            K.CRV: COSECRV.P521,
            K.X: b"\x11" * 32,
            K.Y: b"\x22" * 32,
        }
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(p521_bad))

    def test_rejects_okp_alg_curve_and_length_mismatches(self) -> None:
        base = {
            K.KTY: COSEKTY.OKP,
            K.ALG: COSEAlgorithmIdentifier.EDDSA,
            K.CRV: COSECRV.ED25519,
            K.X: b"\x33" * 32,
        }

        # EdDSA cannot be paired with an EC2 curve
        bad_key = dict(base)
        bad_key[K.CRV] = COSECRV.P256
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

        # OKP keys cannot carry an EC2 algorithm
        bad_key = dict(base)
        bad_key[K.ALG] = COSEAlgorithmIdentifier.ECDSA_SHA_256
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

        # Ed25519 x must be exactly 32 bytes
        for bad_len in (31, 33, 0):
            bad_key = dict(base)
            bad_key[K.X] = b"\x33" * bad_len
            with self.assertRaises(InvalidPublicKeyStructure):
                decode_credential_public_key(_encode_key(bad_key))

    def test_rejects_cross_key_type_algorithm_bindings(self) -> None:
        rsa_key = {
            K.KTY: COSEKTY.RSA,
            K.ALG: COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            K.N: b"\xaa" * 256,
            K.E: b"\x01\x00\x01",
        }
        bad_rsa = dict(rsa_key)
        bad_rsa[K.ALG] = COSEAlgorithmIdentifier.ECDSA_SHA_256
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_rsa))

        mldsa_key = {
            K.KTY: COSEKTY.ML_DSA,
            K.ALG: COSEAlgorithmIdentifier.ML_DSA_44,
            K.PUB: b"\x44" * 1312,
        }
        bad_mldsa = dict(mldsa_key)
        bad_mldsa[K.ALG] = COSEAlgorithmIdentifier.EDDSA
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_mldsa))

    def test_rejects_ml_dsa_pub_length_mismatches(self) -> None:
        base = {
            K.KTY: COSEKTY.ML_DSA,
            K.ALG: COSEAlgorithmIdentifier.ML_DSA_44,
            K.PUB: b"\x44" * 1312,
        }

        for bad_len in (1311, 1313, 1952, 2592):
            bad_key = dict(base)
            bad_key[K.PUB] = b"\x44" * bad_len
            with self.assertRaises(InvalidPublicKeyStructure):
                decode_credential_public_key(_encode_key(bad_key))

    def test_rejects_unexpected_or_unhandled_fields(self) -> None:
        ec2_key: Dict[Any, Any] = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            K.CRV: COSECRV.P256,
            K.X: b"\x11" * 32,
            K.Y: b"\x22" * 32,
        }
        # Unknown map key
        bad_key = dict(ec2_key)
        bad_key[999] = b"unexpected"
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

        # OKP keys must not carry the EC2-only "y" parameter
        okp_key = {
            K.KTY: COSEKTY.OKP,
            K.ALG: COSEAlgorithmIdentifier.EDDSA,
            K.CRV: COSECRV.ED25519,
            K.X: b"\x33" * 32,
        }
        bad_key = dict(okp_key)
        bad_key[K.Y] = b"\x55" * 32
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

        # RSA keys must not carry a "crv" parameter
        rsa_key = {
            K.KTY: COSEKTY.RSA,
            K.ALG: COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            K.N: b"\xaa" * 256,
            K.E: b"\x01\x00\x01",
        }
        bad_key = dict(rsa_key)
        bad_key[K.CRV] = COSECRV.P256
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

        # ML-DSA keys must not carry an "x" parameter
        mldsa_key = {
            K.KTY: COSEKTY.ML_DSA,
            K.ALG: COSEAlgorithmIdentifier.ML_DSA_44,
            K.PUB: b"\x44" * 1312,
        }
        bad_key = dict(mldsa_key)
        bad_key[K.X] = b"\x66" * 32
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

    def test_rejects_missing_empty_and_wrong_typed_fields(self) -> None:
        ec2_key = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            K.CRV: COSECRV.P256,
            K.X: b"\x11" * 32,
            K.Y: b"\x22" * 32,
        }

        # Missing required fields
        for field in (K.KTY, K.ALG, K.CRV, K.X, K.Y):
            bad_key = dict(ec2_key)
            del bad_key[field]
            with self.assertRaises(InvalidPublicKeyStructure):
                decode_credential_public_key(_encode_key(bad_key))

        # Boolean values must not be mistaken for integer identifiers
        bad_key = dict(ec2_key)
        bad_key[K.CRV] = True
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

        # Byte-string parameters reject non-bytes values
        bad_key = dict(ec2_key)
        bad_key[K.X] = "not-bytes"
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

        # Unrecognized algorithm identifier on an otherwise well-formed key
        bad_key = dict(ec2_key)
        bad_key[K.ALG] = -99999
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(_encode_key(bad_key))

    def test_rejects_non_map_cbor(self) -> None:
        # cbor2.dumps([1, 2, 3]) -> a CBOR array, not a COSE key map
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(cbor2.dumps([1, 2, 3]))

        # Scalar CBOR values and empty input must not leak low-level errors
        for scalar in (b"", cbor2.dumps(7), cbor2.dumps("hello"), cbor2.dumps(None)):
            with self.assertRaises(InvalidPublicKeyStructure):
                decode_credential_public_key(scalar)

    def test_unknown_key_type_keeps_historical_exception(self) -> None:
        bad_key = {
            K.KTY: 99,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            K.CRV: COSECRV.P256,
            K.X: b"\x11" * 32,
            K.Y: b"\x22" * 32,
        }
        with self.assertRaises(UnsupportedPublicKeyType):
            decode_credential_public_key(_encode_key(bad_key))

    def test_rejects_malformed_uncompressed_ec2_point(self) -> None:
        valid = b"\x04" + b"\x11" * 32 + b"\x22" * 32
        assert isinstance(decode_credential_public_key(valid), DecodedEC2PublicKey)

        for bad_point in (
            b"\x04" + b"\x11" * 32 + b"\x22" * 31,  # 64 bytes, truncated
            b"\x04" + b"\x11" * 32 + b"\x22" * 33,  # 66 bytes, trailing byte
            b"\x04",  # marker only
        ):
            with self.assertRaises(InvalidPublicKeyStructure):
                decode_credential_public_key(bad_point)
