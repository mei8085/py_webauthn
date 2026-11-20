from typing import Any, Dict, Union
from unittest import TestCase

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding, rsa

from webauthn.helpers.cose import COSECRV, COSEKTY, COSEAlgorithmIdentifier, COSEKey
from webauthn.helpers.decode_credential_public_key import decode_credential_public_key
from webauthn.helpers.decoded_public_key_to_cryptography import (
    decoded_public_key_to_cryptography,
)
from webauthn.helpers.exceptions import InvalidPublicKeyStructure
from webauthn.helpers.verify_signature import verify_signature

K = COSEKey
DATA = b"assertion-to-be-verified"

PrivateKey = Union[
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    rsa.RSAPrivateKey,
    mldsa.MLDSA44PrivateKey,
    mldsa.MLDSA65PrivateKey,
    mldsa.MLDSA87PrivateKey,
]


class TestDecodedKeyCarriesConfirmedBinding(TestCase):
    """The alg/crv confirmed during decoding must be what powers later
    assertion verification, with no re-interpretation of the raw COSE fields.
    """

    def _roundtrip(
        self, key_map: Dict[Any, Any], private_key: PrivateKey, sign_kwargs: Dict[str, Any]
    ) -> None:
        decoded = decode_credential_public_key(cbor2.dumps(key_map))
        crypto_public_key = decoded_public_key_to_cryptography(decoded)
        signature = private_key.sign(DATA, **sign_kwargs)

        # verify_signature consumes the alg carried by the confirmed decoded
        # key, not any value re-read from the raw COSE bytes
        verify_signature(
            public_key=crypto_public_key,
            signature_alg=decoded.alg,
            signature=signature,
            data=DATA,
        )

    def test_ec2_p256_roundtrip(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        key_map = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            K.CRV: COSECRV.P256,
            K.X: numbers.x.to_bytes(32, "big"),
            K.Y: numbers.y.to_bytes(32, "big"),
        }

        self._roundtrip(
            key_map, private_key, {"signature_algorithm": ec.ECDSA(hashes.SHA256())}
        )

    def test_ec2_p521_roundtrip(self) -> None:
        private_key = ec.generate_private_key(ec.SECP521R1())
        numbers = private_key.public_key().public_numbers()
        key_map = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_512,
            K.CRV: COSECRV.P521,
            K.X: numbers.x.to_bytes(66, "big"),
            K.Y: numbers.y.to_bytes(66, "big"),
        }

        self._roundtrip(
            key_map, private_key, {"signature_algorithm": ec.ECDSA(hashes.SHA512())}
        )

    def test_okp_ed25519_roundtrip(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        x = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        key_map = {
            K.KTY: COSEKTY.OKP,
            K.ALG: COSEAlgorithmIdentifier.EDDSA,
            K.CRV: COSECRV.ED25519,
            K.X: x,
        }

        self._roundtrip(key_map, private_key, {})

    def test_rsa_roundtrip(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.public_key().public_numbers()
        key_map = {
            K.KTY: COSEKTY.RSA,
            K.ALG: COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            K.N: numbers.n.to_bytes(256, "big"),
            K.E: numbers.e.to_bytes(3, "big"),
        }

        self._roundtrip(
            key_map,
            private_key,
            {"padding": padding.PKCS1v15(), "algorithm": hashes.SHA256()},
        )

    def test_ml_dsa_roundtrip(self) -> None:
        for alg, generator, pub_len in (
            (COSEAlgorithmIdentifier.ML_DSA_44, mldsa.MLDSA44PrivateKey, 1312),
            (COSEAlgorithmIdentifier.ML_DSA_65, mldsa.MLDSA65PrivateKey, 1952),
            (COSEAlgorithmIdentifier.ML_DSA_87, mldsa.MLDSA87PrivateKey, 2592),
        ):
            private_key = generator.generate()
            raw_pub = private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            assert len(raw_pub) == pub_len
            key_map = {K.KTY: COSEKTY.ML_DSA, K.ALG: alg, K.PUB: raw_pub}

            self._roundtrip(key_map, private_key, {})

    def test_tampered_alg_never_reaches_signature_verification(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        key_map = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_512,  # conflicts with P-256
            K.CRV: COSECRV.P256,
            K.X: numbers.x.to_bytes(32, "big"),
            K.Y: numbers.y.to_bytes(32, "big"),
        }

        # A caller cannot coerce ES512 verification over a P-256 key because the
        # inconsistent key is refused before any crypto object is built
        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(cbor2.dumps(key_map))

    def test_tampered_curve_never_reaches_signature_verification(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        key_map = {
            K.KTY: COSEKTY.EC2,
            K.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            K.CRV: COSECRV.P521,  # conflicts with ES256 and 32-byte coords
            K.X: numbers.x.to_bytes(32, "big"),
            K.Y: numbers.y.to_bytes(32, "big"),
        }

        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(cbor2.dumps(key_map))

    def test_extra_field_never_reaches_signature_verification(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        x = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        key_map = {
            K.KTY: COSEKTY.OKP,
            K.ALG: COSEAlgorithmIdentifier.EDDSA,
            K.CRV: COSECRV.ED25519,
            K.X: x,
            2: "unhandled-extra-field",
        }

        with self.assertRaises(InvalidPublicKeyStructure):
            decode_credential_public_key(cbor2.dumps(key_map))
