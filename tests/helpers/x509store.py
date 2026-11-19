import inspect
from datetime import datetime
from unittest.mock import patch

from OpenSSL.crypto import X509Store
from webauthn.helpers import (
    validate_certificate_chain as validate_certificate_chain_func,
)


def patch_validate_certificate_chain_x509store_getter(func):
    """
    This is a very purpose-built decorator to help set a fixed time for X.509 certificate chain
    validation in unittests. It makes the following assumptions, all of which must be true for this
    decorator to remain useful:

    - X.509 certificate chain validation occurs in **webauthn/helpers/validate_certificate_chain.py::**`validate_certificate_chain`
    - `validate_certificate_chain(...)` uses `OpenSSL.crypto.X509Store` to verify certificate chains
    - **webauthn/helpers/__init__.py** continues to re-export `validate_certificate_chain`

    The decorated test receives an `X509Store` as its final positional argument. Calling
    `patched_x509store.set_time(...)` freezes both the OpenSSL store clock and the library's
    explicit validity-window checks at the same moment.

    Usage:

    ```
    from unittest import TestCase
    from datetime import datetime
    from OpenSSL.crypto import X509Store

    from .helpers.x509store import patch_validate_certificate_chain_x509store_getter

    class TestX509Validation(TestCase):
        @patch_validate_certificate_chain_x509store_getter
        def test_validate_x509_chain(self, patched_x509store: X509Store):
            patched_x509store.set_time(datetime(2021, 9, 1, 0, 0, 0))
            # ...
    ```
    """

    def wrapper(*args, **kwargs):
        """
        Using `inspect.getmodule(...)` below helps deal with the fact that, in Python 3.9 and
        Python 3.10, `@patch("webauthn.helpers.validate_certificate_chain._generate_new_cert_store")`
        errors out because `webauthn.helpers.validate_certificate_chain` is understood to be the
        function re-exported via `__all__` in **webauthn/helpers/__init__.py**, not the module of
        the same name.
        """
        module = inspect.getmodule(validate_certificate_chain_func)

        with patch.object(
            module,
            "_generate_new_cert_store",
        ) as mock_generate_new_cert_store:
            new_cert_store = X509Store()
            mock_generate_new_cert_store.return_value = new_cert_store

            time_holder = {"time": None}
            original_set_time = new_cert_store.set_time

            def _set_time(value: datetime) -> None:
                # Keep the OpenSSL store clock and the module's validity-window override at the
                # same moment so both layers of expiry handling agree.
                time_holder["time"] = value
                original_set_time(value)
                module._validation_time_override = value

            new_cert_store.set_time = _set_time  # type: ignore[method-assign]

            try:
                return func(*args, new_cert_store, **kwargs)
            finally:
                module._validation_time_override = None

    return wrapper
