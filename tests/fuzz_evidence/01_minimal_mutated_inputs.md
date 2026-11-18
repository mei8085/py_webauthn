# Evidence 1: Minimal mutated inputs

Regenerated deterministically by `python -m unittest tests.test_fuzz_registration_authentication_parsing` (seed=20261118). No external services are contacted.

Each entry is the smallest input (found by greedy chunk-removal shrinking) that still triggers the same error category. Re-run any entry with the shown snippet.

## Invariant violations

None: every rejection on both parse paths is a `WebAuthnException` subclass.

## Minimal rejected inputs per mutation category

### duplicate_cbor_key / registration

- minimal length: 19 bytes
- hex: `a463666d74646e6f6e6563666d74646f6e6568`
- error: `InvalidAttestationObjectStructure` (cause: `InvalidCBORData`; root: CBORDecodeError: error decoding map: Duplicate map key: 'fmt')
- repro:

```python
from webauthn.helpers.parse_attestation_object import parse_attestation_object
parse_attestation_object(bytes.fromhex("a463666d74646e6f6e6563666d74646f6e6568"))
```

### duplicate_cbor_key / authentication

- minimal length: 64 bytes
- hex: `00000000000000000000000000000000000000000000000000000000000000008100000000a26b6372656450726f74656374036b6372656450726f7465637402`
- error: `InvalidCBORData` (cause: `CBORDecodeError`; root: CBORDecodeError: error decoding map: Duplicate map key: 'credProtect')
- repro:

```python
from webauthn.helpers.parse_authenticator_data import parse_authenticator_data
parse_authenticator_data(bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000008100000000a26b6372656450726f74656374036b6372656450726f7465637402"))
```

### inconsistent_cred_id_len / authentication

- minimal length: 38 bytes
- hex: `1111112258202222222222222222222222222222222222222222222222222222222222222222`
- error: `InvalidAuthenticatorDataStructure` (cause: `-`; root: InvalidAuthenticatorDataStructure: Leftover bytes detected while parsing authenticator data)
- repro:

```python
from webauthn.helpers.parse_authenticator_data import parse_authenticator_data
parse_authenticator_data(bytes.fromhex("1111112258202222222222222222222222222222222222222222222222222222222222222222"))
```

### nested_cbor_length/map_len_overrun / registration

- minimal length: 1 bytes
- hex: `58`
- error: `InvalidAttestationObjectStructure` (cause: `InvalidCBORData`; root: CBORDecodeEOF: premature end of stream (expected to read at least 1 bytes, got 0 instead))
- repro:

```python
from webauthn.helpers.parse_attestation_object import parse_attestation_object
parse_attestation_object(bytes.fromhex("58"))
```

### nested_cbor_length/bytes_len_overrun / registration

- minimal length: 1 bytes
- hex: `44`
- error: `InvalidAttestationObjectStructure` (cause: `InvalidCBORData`; root: CBORDecodeEOF: premature end of stream (expected to read at least 4 bytes, got 0 instead))
- repro:

```python
from webauthn.helpers.parse_attestation_object import parse_attestation_object
parse_attestation_object(bytes.fromhex("44"))
```

### nested_cbor_length/nested_array_len_overrun / registration

- minimal length: 1 bytes
- hex: `6e`
- error: `InvalidAttestationObjectStructure` (cause: `InvalidCBORData`; root: CBORDecodeEOF: premature end of stream (expected to read at least 14 bytes, got 0 instead))
- repro:

```python
from webauthn.helpers.parse_attestation_object import parse_attestation_object
parse_attestation_object(bytes.fromhex("6e"))
```

### nested_cbor_length/deep_nesting / registration

- minimal length: 65 bytes
- hex: `8181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818100`
- error: `InvalidAttestationObjectStructure` (cause: `-`; root: InvalidAttestationObjectStructure: attestationObject was not a dict)
- repro:

```python
from webauthn.helpers.parse_attestation_object import parse_attestation_object
parse_attestation_object(bytes.fromhex("8181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818100"))
```

### truncated_byte_string / registration

- minimal length: 1 bytes
- hex: `74`
- error: `InvalidAttestationObjectStructure` (cause: `InvalidCBORData`; root: CBORDecodeEOF: premature end of stream (expected to read at least 20 bytes, got 0 instead))
- repro:

```python
from webauthn.helpers.parse_attestation_object import parse_attestation_object
parse_attestation_object(bytes.fromhex("74"))
```

### truncated_byte_string / authentication

- minimal length: 1 bytes
- hex: `00`
- error: `InvalidAuthenticatorDataStructure` (cause: `-`; root: InvalidAuthenticatorDataStructure: Authenticator data was 1 bytes, expected at least 37 bytes)
- repro:

```python
from webauthn.helpers.parse_authenticator_data import parse_authenticator_data
parse_authenticator_data(bytes.fromhex("00"))
```
