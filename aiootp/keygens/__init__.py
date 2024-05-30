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


__all__ = [
    "DomainKDF",
    "Ed25519",
    "PackageSigner",
    "PackageVerifier",
    "Passcrypt",
    "X25519",
    "amnemonic",
    "mnemonic",
]


__doc__ = (
    "Interfaces for creating, deriving, & using symmetric & asymmetric "
    "cryptographic keys."
)


from .domain_kdf import *
from .passcrypt import *
from .mnemonics import *
from .curve_25519 import *
from .package_signer import *
from .package_verifier import *


subpackages = dict(curve_25519=curve_25519, passcrypt=passcrypt)


modules = dict(
    domain_kdf=domain_kdf,
    mnemonics=mnemonics,
    package_signer=package_signer,
    package_verifier=package_verifier,
)


module_api = dict(
    DomainKDF=DomainKDF,
    Ed25519=Ed25519,
    PackageSigner=PackageSigner,
    PackageVerifier=PackageVerifier,
    Passcrypt=Passcrypt,
    X25519=X25519,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    amnemonic=amnemonic,
    mnemonic=mnemonic,
)

