from typing import List

from cryptography.exceptions import InvalidSignature

from webauthn.helpers import (
    decode_credential_public_key,
    hash_by_alg,
    parse_cbor,
    validate_certificate_chain,
    verify_signature,
)
from webauthn.helpers.attestation_cert_constraints import (
    AttestationCertificateType,
    TCG_AT_TPM_MANUFACTURER_OID,
)
from webauthn.helpers.certificate_parsing import load_x509_certificate
from webauthn.helpers.decode_credential_public_key import (
    DecodedEC2PublicKey,
    DecodedRSAPublicKey,
)
from webauthn.helpers.exceptions import (
    InvalidCertificateChain,
    InvalidCertificateCurve,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import AttestationStatement
from webauthn.helpers.tpm import (
    map_tpm_manufacturer_id,
    parse_cert_info,
    parse_pub_area,
)
from webauthn.helpers.tpm.structs import (
    TPM_ALG_COSE_ALG_MAP,
    TPM_ECC_CURVE_COSE_CRV_MAP,
    TPMPubAreaParametersECC,
    TPMPubAreaParametersRSA,
)
from cryptography.x509 import Version
from cryptography.x509 import SubjectAlternativeName, GeneralName
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID


def verify_tpm(
    *,
    attestation_statement: AttestationStatement,
    attestation_object: bytes,
    client_data_json: bytes,
    credential_public_key: bytes,
    pem_root_certs_bytes: List[bytes],
    aaguid: bytes,
) -> bool:
    """Verify a "tpm" attestation statement

    See https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
    """
    if not attestation_statement.cert_info:
        raise InvalidRegistrationResponse(
            "Attestation statement was missing certInfo (TPM)"
        )

    if not attestation_statement.pub_area:
        raise InvalidRegistrationResponse(
            "Attestation statement was missing pubArea (TPM)"
        )

    if not attestation_statement.alg:
        raise InvalidRegistrationResponse("Attestation statement was missing alg (TPM)")

    if not attestation_statement.x5c:
        raise InvalidRegistrationResponse("Attestation statement was missing x5c (TPM)")

    if not attestation_statement.sig:
        raise InvalidRegistrationResponse("Attestation statement was missing sig (TPM)")

    att_stmt_ver = attestation_statement.ver
    if att_stmt_ver != "2.0":
        raise InvalidRegistrationResponse(
            f'Attestation statement ver "{att_stmt_ver}" was not "2.0" (TPM)'
        )

    # Validate the certificate chain, including TPM AIK certificate requirements (basic
    # constraints, key usage, EKU with the TCG AIK OID, SAN TPM entries, AAGUID binding)
    try:
        validate_certificate_chain(
            x5c=attestation_statement.x5c,
            pem_root_certs_bytes=pem_root_certs_bytes,
            attestation_type=AttestationCertificateType.TPM,
            aaguid=aaguid,
        )
    except InvalidCertificateChain as err:
        raise InvalidRegistrationResponse(f"{err} (TPM)")

    # Verify that the public key specified by the parameters and unique fields of
    # pubArea is identical to the credentialPublicKey in the attestedCredentialData
    # in authenticatorData.
    pub_area = parse_pub_area(attestation_statement.pub_area)
    decoded_public_key = decode_credential_public_key(credential_public_key)

    if isinstance(pub_area.parameters, TPMPubAreaParametersRSA):
        if not isinstance(decoded_public_key, DecodedRSAPublicKey):
            raise InvalidRegistrationResponse(
                "Public key was not RSA key as indicated in pubArea (TPM)"
            )

        if pub_area.unique.value != decoded_public_key.n:
            unique_hex = pub_area.unique.value.hex()
            pub_key_n_hex = decoded_public_key.n.hex()
            raise InvalidRegistrationResponse(
                f'PubArea unique "{unique_hex}" was not same as public key modulus "{pub_key_n_hex}" (TPM)'
            )

        pub_area_exponent = int.from_bytes(pub_area.parameters.exponent, "big")
        if pub_area_exponent == 0:
            # "When zero, indicates that the exponent is the default of 2^16 + 1"
            pub_area_exponent = 65537

        pub_key_exponent = int.from_bytes(decoded_public_key.e, "big")

        if pub_area_exponent != pub_key_exponent:
            raise InvalidRegistrationResponse(
                f'PubArea exponent "{pub_area_exponent}" was not same as public key exponent "{pub_key_exponent}" (TPM)'
            )
    elif isinstance(pub_area.parameters, TPMPubAreaParametersECC):
        if not isinstance(decoded_public_key, DecodedEC2PublicKey):
            raise InvalidRegistrationResponse(
                "Public key was not ECC key as indicated in pubArea (TPM)"
            )

        pubKeyCoords = b"".join([decoded_public_key.x, decoded_public_key.y])
        if pub_area.unique.value != pubKeyCoords:
            unique_hex = pub_area.unique.value.hex()
            pub_key_xy_hex = pubKeyCoords.hex()
            raise InvalidRegistrationResponse(
                f'Unique "{unique_hex}" was not same as public key [x,y] "{pub_key_xy_hex}" (TPM)'
            )

        try:
            pub_area_crv = TPM_ECC_CURVE_COSE_CRV_MAP[pub_area.parameters.curve_id]
        except KeyError:
            raise InvalidCertificateCurve(
                f'PubArea curve ID "{pub_area.parameters.curve_id}" did not identify a '
                "supported WebAuthn EC curve (TPM)"
            )

        if pub_area_crv != decoded_public_key.crv:
            raise InvalidCertificateCurve(
                f'PubArea curve ID "{pub_area_crv}" was not same as public key crv "{decoded_public_key.crv}" (TPM)'
            )
    else:
        pub_area_param_type = type(pub_area.parameters)
        raise InvalidRegistrationResponse(
            f'Unsupported pub_area.parameters "{pub_area_param_type}" (TPM)'
        )

    # Validate that certInfo is valid:
    cert_info = parse_cert_info(attestation_statement.cert_info)

    # Verify that magic is set to TPM_GENERATED_VALUE.
    # a.k.a. 0xff544347
    magic_int = int.from_bytes(cert_info.magic, "big")
    if magic_int != int(0xFF544347):
        raise InvalidRegistrationResponse(
            f'CertInfo magic "{magic_int}" was not TPM_GENERATED_VALUE 4283712327 (0xff544347) (TPM)'
        )

    # Concatenate authenticatorData and clientDataHash to form attToBeSigned.
    attestation_dict = parse_cbor(attestation_object)
    authenticator_data_bytes: bytes = attestation_dict["authData"]
    client_data_hash = hash_by_alg(client_data_json)
    att_to_be_signed = b"".join(
        [
            authenticator_data_bytes,
            client_data_hash,
        ]
    )

    # Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
    att_to_be_signed_hash = hash_by_alg(att_to_be_signed, attestation_statement.alg)
    if cert_info.extra_data != att_to_be_signed_hash:
        raise InvalidRegistrationResponse(
            "PubArea extra data did not match hash of auth data and client data (TPM)"
        )

    # Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in
    # [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for
    # pubArea, as computed using the algorithm in the nameAlg field of pubArea using
    # the procedure specified in [TPMv2-Part1] section 16.
    pub_area_hash = hash_by_alg(
        attestation_statement.pub_area,
        TPM_ALG_COSE_ALG_MAP[pub_area.name_alg],
    )

    attested_name = b"".join(
        [
            cert_info.attested.name_alg_bytes,
            pub_area_hash,
        ]
    )

    if attested_name != cert_info.attested.name:
        raise InvalidRegistrationResponse(
            "CertInfo attested name did not match PubArea hash (TPM)"
        )

    # Verify the sig is a valid signature over certInfo using the attestation
    # public key in aikCert with the algorithm specified in alg.
    attestation_cert_bytes = attestation_statement.x5c[0]
    attestation_cert = load_x509_certificate(attestation_cert_bytes).cert
    attestation_cert_pub_key = attestation_cert.public_key()

    try:
        verify_signature(
            public_key=attestation_cert_pub_key,
            signature_alg=attestation_statement.alg,
            signature=attestation_statement.sig,
            data=attestation_statement.cert_info,
        )
    except InvalidSignature:
        raise InvalidRegistrationResponse(
            "Could not verify attestation statement signature (TPM)"
        )

    # Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement
    # Certificate Requirements.
    # https://w3c.github.io/webauthn/#sctn-tpm-cert-requirements

    # Version MUST be set to 3.
    if attestation_cert.version != Version.v3:
        raise InvalidRegistrationResponse(
            f'Certificate Version "{attestation_cert.version}" was not "{Version.v3}"" Constraints CA was not False (TPM)'
        )

    # Subject field MUST be set to empty.
    if len(attestation_cert.subject) > 0:
        raise InvalidRegistrationResponse(
            f'Certificate Subject "{attestation_cert.subject}" was not empty (TPM)'
        )

    # The remaining aikCert requirements (Subject Alternative Name TPM entries, Extended Key
    # Usage TCG AIK OID, Basic Constraints CA=false, id-fido-gen-ce-aaguid binding) are enforced
    # centrally by validate_certificate_chain() via attestation_cert_constraints. Only extensions
    # identified there by an explicit OID are treated as verified security attributes.
    #
    # The TPM manufacturer hex ID is additionally cross-checked against the known vendor
    # registry here, since that lookup is TPM-specific policy rather than chain validation.
    try:
        ext_subject_alt_name: SubjectAlternativeName = (
            attestation_cert.extensions.get_extension_for_oid(  # type: ignore[assignment]
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
        )
    except ExtensionNotFound:
        # Already raised as InvalidCertificateExtension during chain validation; defensive guard
        raise InvalidRegistrationResponse(
            f"Certificate missing extension {ExtensionOID.SUBJECT_ALTERNATIVE_NAME} (TPM)"
        )

    tcg_at_tpm_values: GeneralName = ext_subject_alt_name.get_values_for_type(GeneralName)[0]  # type: ignore[arg-type, assignment]
    tcg_at_tpm_manufacturer = None
    for obj in tcg_at_tpm_values:  # type: ignore[attr-defined]
        if obj.oid.dotted_string == TCG_AT_TPM_MANUFACTURER_OID:
            tcg_at_tpm_manufacturer = str(obj.value)
            break

    if not tcg_at_tpm_manufacturer:
        raise InvalidRegistrationResponse(
            f"Certificate Subject Alt Name was missing TPM manufacturer entry (TPM): "
            f"{tcg_at_tpm_values}"
        )

    try:
        # Naively try to map the manufacturer hex ID to a known manufacturer
        map_tpm_manufacturer_id(tcg_at_tpm_manufacturer)
    except KeyError:
        raise InvalidRegistrationResponse(
            f'Unrecognized TPM Manufacturer "{tcg_at_tpm_manufacturer}" (TPM)'
        )

    return True
