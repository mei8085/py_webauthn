class WebAuthnException(Exception):
    pass


class InvalidRegistrationOptions(WebAuthnException):
    pass


class InvalidRegistrationResponse(WebAuthnException):
    pass


class InvalidAuthenticationOptions(WebAuthnException):
    pass


class InvalidAuthenticationResponse(WebAuthnException):
    pass


class InvalidPublicKeyStructure(WebAuthnException):
    pass


class UnsupportedPublicKeyType(WebAuthnException):
    pass


class InvalidJSONStructure(WebAuthnException):
    pass


class InvalidAuthenticatorDataStructure(WebAuthnException):
    pass


class SignatureVerificationException(WebAuthnException):
    pass


class UnsupportedAlgorithm(WebAuthnException):
    pass


class UnsupportedPublicKey(WebAuthnException):
    pass


class UnsupportedEC2Curve(WebAuthnException):
    pass


class InvalidTPMPubAreaStructure(WebAuthnException):
    pass


class InvalidTPMCertInfoStructure(WebAuthnException):
    pass


class InvalidCertificateChain(WebAuthnException):
    pass


class CertificateChainExpired(InvalidCertificateChain):
    """A certificate in the chain is outside of its validity window (expired or not yet valid)"""


class InvalidCertificateOrder(InvalidCertificateChain):
    """The certificates in x5c are not ordered leaf-first with each issuer following its subject"""


class InvalidCertificateCurve(InvalidCertificateChain):
    """An EC certificate in the chain uses a curve that is not permitted for WebAuthn attestation"""


class InvalidCertificateExtension(InvalidCertificateChain):
    """A certificate extension required by the attestation type is missing, malformed, or
    inappropriately marked critical"""


class CertificateAAGUIDMismatch(InvalidCertificateChain):
    """The id-fido-gen-ce-aaguid extension in the certificate does not match the AAGUID in the
    authenticator data, or the extension could not be parsed as a verified security attribute
    """


class InvalidCertificateKeyUsage(InvalidCertificateChain):
    """A certificate's key usage / extended key usage does not permit attestation use"""


class InvalidBackupFlags(WebAuthnException):
    pass


class InvalidCBORData(WebAuthnException):
    pass


class InvalidAttestationObjectStructure(WebAuthnException):
    pass
