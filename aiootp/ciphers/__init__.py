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


__all__ = ["ChaCha20Poly1305", "Chunky2048", "Slick256"]


__doc__ = (
    "Implementations & high-level interfaces to the package's online "
    "salt misuse-reuse resistant, fully context committing, tweakable, "
    "AEAD ciphers."
)


from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from aiootp._typing import Typing as t

from .padding import *
from .ciphertext_formatting import *
from .cipher_kdfs import *
from .key_bundle import *
from .stream_hmac import *
from .synthetic_iv import *
from .stream_junction import *
from .cipher_stream_properties import *
from .cipher_streams import *
from .decipher_streams import *
from .dual_output_shake_cipher import *
from .dual_output_shake_cipher_config import *
from .shake_permute_cipher import *
from .shake_permute_cipher_config import *
from .cipher_interface import *
from .chunky_2048_config import *
from .chunky_2048 import *
from .slick_256_config import *
from .slick_256 import *


modules = dict(
    padding=padding,
    ciphertext_formatting=ciphertext_formatting,
    cipher_kdfs=cipher_kdfs,
    key_bundle=key_bundle,
    stream_hmac=stream_hmac,
    synthetic_iv=synthetic_iv,
    stream_junction=stream_junction,
    cipher_stream_properties=cipher_stream_properties,
    cipher_streams=cipher_streams,
    decipher_streams=decipher_streams,
    dual_output_shake_cipher=dual_output_shake_cipher,
    dual_output_shake_cipher_config=dual_output_shake_cipher_config,
    shake_permute_cipher=shake_permute_cipher,
    shake_permute_cipher_config=shake_permute_cipher_config,
    cipher_interface=cipher_interface,
    chunky_2048_config=chunky_2048_config,
    chunky_2048=chunky_2048,
    slick_256_config=slick_256_config,
    slick_256=slick_256,
)


module_api = dict(
    ChaCha20Poly1305=t.add_type(ChaCha20Poly1305),
    Chunky2048=Chunky2048,
    Ciphertext=Ciphertext,
    Padding=Padding,
    Slick256=Slick256,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

