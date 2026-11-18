# Evidence 3: Legitimate inputs that pass (no false positives)

Regenerated deterministically by `python -m unittest tests.test_fuzz_registration_authentication_parsing` (seed=20261118). No external services are contacted.

- registration: 37-byte authData (minimum) -> OK
- authentication: 37-byte authData (minimum) -> OK
- registration: credential ID length 16 -> OK
- registration: credential ID length 1023 -> OK
- registration: extensions credProtect + hmac-secret -> OK
- authentication: extensions credProtect + hmac-secret -> OK
- registration: attested credential data + extensions -> OK
- registration: type=public-key -> OK
- authentication: type=public-key -> OK
- type != 'public-key' -> InvalidJSONStructure (true positive)
- registration: transports with unknown values (ignored) -> OK
- authentication: authenticatorAttachment=platform -> OK
- authentication: authenticatorAttachment=cross-platform -> OK
- authentication: userHandle present -> OK
- authentication: userHandle null -> OK
- registration: unknown fmt string -> OK
- attestationObject with unknown CBOR keys (text/int/negative) -> OK
- attStmt with unknown keys -> OK
- authenticatorData extensions with unknown keys -> OK (both paths)
- random unknown JSON fields (top-level + response) -> OK (both paths)
