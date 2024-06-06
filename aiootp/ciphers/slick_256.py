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


__all__ = ["Slick256"]


__doc__ = (
    "An interface for one of the package's online salt misuse-reuse "
    "resistant, fully context commiting, tweakable, AEAD ciphers called "
    "`Slick256`."
)


from aiootp._typing import Typing as t

from .shake_permute_cipher import ShakePermuteKDFs
from .shake_permute_cipher import ShakePermuteKeyAADBundle
from .shake_permute_cipher import ShakePermuteStreamHMAC
from .shake_permute_cipher import ShakePermuteStreamJunction
from .cipher_interface import CipherInterface
from .slick_256_config import slick256_spec


class Slick256(CipherInterface):
    r"""
    An efficient high-level public interface to an online, salt misuse-
    reuse resistant, fully context committing, tweakable, RUP-secure,
    AEAD cipher.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    import aiootp

    key = aiootp.csprng()
    cipher = aiootp.Slick256(key)

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
    |  shmac  | salt |  iv  | inner-header | plaintext |     footer    |
    |         |      |      |------|-------|           |---------|-----|
    |         |      |      | time | ikey  |           | padding | len |
    |    24   |   8  |   8  |   4  |   8   |     X     |    Y    |  1  |
    |_________|______|______|______|_______|___________|_________|_____|

     _____________________________________
    |                                     |
    |     Algorithm Pseudocode: Init      |
    |_____________________________________|

    e = a canonical, domain-specified encoding / padding function
    S = shmac_kdf = shake_128(e(SALT_S, METADATA, key, salt, aad, iv))
    K = primer_key = S.digest(336)
    π = permutation = FastAffineXORChain(key=K[168:168+π_key_size])
    P = 32-byte plaintext block
    C = 32-byte ciphertext block
    K_I, K_O, D = (K[:32], K[32:64], K[64:168])

    Each block is processed as such:

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Encryption    |
    |_____________________________________|

                 K_I-------⊕--------       P
                /          ^       |       |                     /
               /           |       v       |                    /
         -----/            P     -----     v              -----/
    --->|  S  |                 |  π  |   (P ║ C ║ D)--->|  S  |
         -----\                  -----         ^          -----\
               \                   |           |                \
                \                  v           |                 \
                 K_O---------------⊕---------->C

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Decryption    |
    |_____________________________________|

                 K_I---------------⊕------>P
                /                  ^       |                     /
               /                   |       |                    /
         -----/                  -----     v              -----/
    --->|  S  |                 |  π  |   (P ║ C ║ D)--->|  S  |
         -----\            C     -----         ^          -----\
               \           |       ^           |                \
                \          v       |           |                 \
                 K_O-------⊕--------           C
    """

    __slots__ = ()

    _KDFs: type = ShakePermuteKDFs
    _KeyAADBundle: type = ShakePermuteKeyAADBundle
    _StreamHMAC: type = ShakePermuteStreamHMAC
    _Junction: type = ShakePermuteStreamJunction

    _config: t.ConfigType = slick256_spec


module_api = dict(
    Slick256=t.add_type(Slick256),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

