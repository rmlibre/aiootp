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


__all__ = ["DBDomains"]


__doc__ = "A type for `(Async)Database` domain-separation tasks."


from aiootp._typing import Typing as t
from aiootp.generics import DomainEncoder


class DBDomains(DomainEncoder):
    """
    A container for database-specific domain constants.
    """

    __slots__ = ()

    _encode: t.Callable = lambda constant: DomainEncoder.encode_constant(
        constant, domain=b"database_constants", size=16
    )

    ROOT_KDF: bytes = _encode("root_kdf")
    ROOT_FILENAME: bytes = _encode("root_filename")
    ROOT_SALT: bytes = _encode("root_salt")
    METATAG: bytes = _encode("metatag")
    HMAC: bytes = _encode("hmac")
    GIST: bytes = _encode("profile_credential_gist")
    TMP_PREKEY: bytes = _encode("temporary_profile_prekey")
    PROFILE_LOGIN_KEY: bytes = _encode("profile_login_key")
    MANIFEST: bytes = _encode("manifest")
    FILENAME: bytes = _encode("filename")
    METATAG_KEY: bytes = _encode("metatag_key")
    DEVICE_SALT: bytes = _encode(b"device_salt")
    CIPHER: bytes = _encode("cipher")


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

