# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
A type for `(Async)Database` domain-separation tasks.
"""

__all__ = ["DBDomains"]


from aiootp._typing import Typing as t
from aiootp.generics import DomainEncoder


class DBDomains(DomainEncoder):
    """
    A container for database-specific domain constants.
    """

    __slots__ = ()

    _SUBCLASS_DOMAIN: bytes = b"database_constants"
    _DEFAULT_SIZE: int = 16

    ROOT_KDF: bytes = b"root_kdf"
    ROOT_FILENAME: bytes = b"root_filename"
    ROOT_SALT: bytes = b"root_salt"
    METATAG: bytes = b"metatag"
    HMAC: bytes = b"hmac"
    GIST: bytes = b"profile_credential_gist"
    TMP_PREKEY: bytes = b"temporary_profile_prekey"
    PROFILE_LOGIN_KEY: bytes = b"profile_login_key"
    MANIFEST: bytes = b"manifest"
    FILENAME: bytes = b"filename"
    METATAG_KEY: bytes = b"metatag_key"
    DEVICE_SALT: bytes = b"device_salt"
    CIPHER: bytes = b"cipher"


module_api = dict(
    DBDomains=t.add_type(DBDomains),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)
