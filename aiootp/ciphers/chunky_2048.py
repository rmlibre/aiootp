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


__all__ = ["Chunky2048"]


__doc__ = (
    "An interface for one of the package's online, salt misuse-reuse "
    "resistant, fully context commiting, tweakable, AEAD ciphers called "
    "`Chunky2048`."
)


from aiootp._typing import Typing as t

from .dual_output_shake_cipher import DualOutputKDFs
from .dual_output_shake_cipher import DualOutputKeyAADBundle
from .dual_output_shake_cipher import DualOutputStreamHMAC
from .dual_output_shake_cipher import DualOutputStreamJunction
from .cipher_interface import CipherInterface
from .chunky_2048_config import chunky2048_spec


class Chunky2048(CipherInterface):
    r"""
    An efficient high-level public interface to an online, salt misuse-
    reuse resistant, fully context committing, tweakable, AEAD cipher.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    import aiootp

    key = aiootp.csprng()
    cipher = aiootp.Chunky2048(key)

    plaintext = b"Hello, Bob!"
    ciphertext = cipher.bytes_encrypt(plaintext)
    assert plaintext == cipher.bytes_decrypt(ciphertext)

    json_plaintext = ["any", {"JSON": "serializable object"}]
    ciphertext = cipher.json_encrypt(json_plaintext)
    assert json_plaintext == cipher.json_decrypt(ciphertext)

    token_plaintext = b"user_id|session_secret"
    token = cipher.make_token(token_plaintext)
    assert token_plaintext == cipher.read_token(token, ttl=3600)

     _____________________________________
    |                                     |
    |     Format Diagram: Ciphertext      |
    |_____________________________________|
     __________________________________________________________________
    |                       |                                          |
    |         Header        |                Ciphertext                |
    |---------|------|------|------|-------|-----------|---------|-----|
    |  shmac  | salt |  iv  | inner-header | plaintext | padding | len |
    |         |      |      |------|-------|           |         |     |
    |         |      |      | time | ikey  |           |         |     |
    |    32   |   8  |   8  |   4  |   16  |     X     |    Y    |  1  |
    |_________|______|______|______|_______|___________|_________|_____|

     _____________________________________
    |                                     |
    |     Algorithm Pseudocode: Init      |
    |_____________________________________|

    e = a canonical, domain-specified encoding / padding function
    S = shmac_kdf = shake_128(e(SALT_S, METADATA, key, salt, aad, iv))
    L = left_kdf = shake_128(e(SALT_L, METADATA, key, salt, aad, iv))
    R = right_kdf = shake_128(e(SALT_R, METADATA, key, salt, aad, iv))
    P = 256-byte plaintext block
    C = 256-byte ciphertext block
    O = 336-byte shmac_kdf output divided for the left & right kdfs
    K_L, K_R = the two 168-byte left & right KDF outputs

    Each block, except for the first (see `SyntheticIV`),
    is processed as such:

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Encryption    |
    |_____________________________________|
                                       ___       ___
                                        |         |
                                        |    ___ _|_
                                        |     |   |
                             -----      |     |   |
                O[0::2] --->|  L  |--->K_L----⊕-->|
               /             -----      |     |   |           /
         -----/                         |     |   |     -----/
        |  S  |                        ---    P   C    |  S  |
         -----\                         |     |   |     -----\
           ^   \             -----      |     |   |       ^   \
           |    O[1::2] --->|  R  |--->K_R----⊕-->|       |
           |                 -----      |     |   |       |
           |                            |    _|_ _|_      |
           |                            |         |       |
           |                           _|_       _|_      |
           |                                      |       |
    --------                                      ---------
     _____________________________________
    |                                     |
    |    Algorithm Diagram: Decryption    |
    |_____________________________________|
                                       ___   ___
                                        |     |
                                        |    _|_ ___
                                        |     |   |
                             -----      |     |   |
                O[0::2] --->|  L  |--->K_L----⊕-->|
               /             -----      |     |   |           /
         -----/                         |     |   |     -----/
        |  S  |                        ---    C   P    |  S  |
         -----\                         |     |   |     -----\
           ^   \             -----      |     |   |       ^   \
           |    O[1::2] --->|  R  |--->K_R----⊕-->|       |
           |                 -----      |     |   |       |
           |                            |    _|_ _|_      |
           |                            |     |           |
           |                           _|_   _|_          |
           |                                  |           |
    --------                                  -------------
    """

    __slots__ = ()

    _KDFs: type = DualOutputKDFs
    _KeyAADBundle: type = DualOutputKeyAADBundle
    _StreamHMAC: type = DualOutputStreamHMAC
    _Junction: type = DualOutputStreamJunction

    _config: t.ConfigType = chunky2048_spec


module_api = dict(
    Chunky2048=t.add_type(Chunky2048),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    chunky2048_spec=chunky2048_spec,
)

