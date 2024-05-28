# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2024 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["DBKDF"]


__doc__ = "A KDF type for `(Async)Database` operations."


from aiootp._typing import Typing as t
from aiootp._constants import MIN_KEY_BYTES
from aiootp._exceptions import KeyAADIssue
from aiootp.keygens import DomainKDF


class DBKDF(DomainKDF, salt_label=b"database_domain_kdf_salt"):
    """
    A KDF type for `(Async)Database` operations.
    """

    def __init__(self, domain: bytes, *data: bytes, key: bytes) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise KeyAADIssue.invalid_key_size(len(key), MIN_KEY_BYTES)
        super().__init__(domain, *data, key=key)


module_api = dict(
    DBKDF=t.add_type(DBKDF),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

