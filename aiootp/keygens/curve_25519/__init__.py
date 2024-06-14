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


__all__ = ["Ed25519", "X25519"]


__doc__ = (
    "Curve25519 interfaces & adapters to the `cryptography` package."
)


from .shared_interface import *
from .ed25519 import *
from .double_diffie_hellman_client import *
from .double_diffie_hellman_server import *
from .triple_diffie_hellman_client import *
from .triple_diffie_hellman_server import *
from .x25519 import *


modules = dict(
    double_diffie_hellman_client=double_diffie_hellman_client,
    double_diffie_hellman_server=double_diffie_hellman_server,
    ed25519=ed25519,
    shared_interface=shared_interface,
    triple_diffie_hellman_client=triple_diffie_hellman_client,
    triple_diffie_hellman_server=triple_diffie_hellman_server,
    x25519=x25519,
)


module_api = dict(
    Ed25519=Ed25519,
    X25519=X25519,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

