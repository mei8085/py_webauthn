# Evidence 2: Error-category differences between parse paths

Regenerated deterministically by `python -m unittest tests.test_fuzz_registration_authentication_parsing` (seed=20261118). No external services are contacted.

| Mutation | Registration path | Authentication path | Note |
|---|---|---|---|
| duplicate CBOR key (top-level structure) | `InvalidAttestationObjectStructure (cause: InvalidCBORData)` | `n/a (authentication response carries no top-level CBOR map)` | registration wraps CBOR failure as InvalidAttestationObjectStructure |
| duplicate CBOR key (extensions map) | `InvalidCBORData` | `InvalidCBORData (cause: CBORDecodeError)` | authentication lets InvalidCBORData propagate unwrapped |
| duplicate JSON key (both paths) | `ok (last value wins, undetectable)` | `ok (last value wins, undetectable)` | JSON layer cannot detect duplicates; CBOR layer rejects them |
| inconsistent credential_id_len (authData) | `InvalidCBORData / InvalidAuthenticatorDataStructure` | `InvalidCBORData / InvalidAuthenticatorDataStructure` | identical: both paths share parse_authenticator_data |
| inconsistent CBOR map count (top-level) | `InvalidAttestationObjectStructure (count 1 or >3); ok for count 2 (cbor2 ignores trailing bytes, attStmt is optional)` | `n/a` | documented decoder tolerance, not a false positive |
| nested CBOR length: map_len_overrun | `InvalidAttestationObjectStructure` | `InvalidAuthenticatorDataStructure` | corrupt declared lengths rejected on both paths |
| nested CBOR length: bytes_len_overrun | `InvalidAttestationObjectStructure` | `InvalidAuthenticatorDataStructure` | corrupt declared lengths rejected on both paths |
| nested CBOR length: nested_array_len_overrun | `InvalidAttestationObjectStructure` | `InvalidAuthenticatorDataStructure` | corrupt declared lengths rejected on both paths |
| nested CBOR length: deep_nesting | `InvalidAttestationObjectStructure` | `ok` | deeply nested CBOR is a legal extension value on the authentication path |
| truncated byte string | `InvalidAttestationObjectStructure` | `InvalidAuthenticatorDataStructure` | same mutation, path-specific error category |
| truncated below 37-byte minimum | `InvalidAttestationObjectStructure` | `InvalidAuthenticatorDataStructure` | same mutation, path-specific error category |
| empty input | `InvalidAttestationObjectStructure` | `InvalidAuthenticatorDataStructure` | same mutation, path-specific error category |
