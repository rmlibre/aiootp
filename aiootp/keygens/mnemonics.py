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


__all__ = ["akeyed_choices", "keyed_choices", "amnemonic", "mnemonic"]


__doc__ = (
    "Functions for converting random keys or passphrases into a [pseudo-]"
    "random sequences of words."
)


from aiootp._typing import Typing as t
from aiootp._constants import BIG, INT_BYTES, MIN_KEY_BYTES, WORD_LIST
from aiootp._exceptions import Issue
from aiootp._gentools import abatch, batch
from aiootp.generics import Domains, acanonical_pack, canonical_pack
from aiootp.randoms import acsprng, csprng

from .domain_kdf import DomainKDF
from .passcrypt import Passcrypt


async def akeyed_choices(
    choices: t.Sequence[t.Any],
    selection_size: int,
    *,
    domain: bytes = b"",
    key: bytes,
) -> t.AsyncGenerator[t.Any, None]:
    """
    Makes `selection_size` number of selections from an indexable
    sequence of `choices` using subkeys derived from a provided
    `domain` & `key`. Yields each selection one at a time.
    """
    total_choices = len(choices)
    key = await DomainKDF(
        domain,
        total_choices.to_bytes(INT_BYTES, BIG),
        selection_size.to_bytes(INT_BYTES, BIG),
        key=key,
    ).ashake_256(size=16 * selection_size, aad=Domains.PRNG)
    async for index in abatch(key, size=16):
        yield choices[int.from_bytes(index, BIG) % total_choices]


def keyed_choices(
    choices: t.Sequence[t.Any],
    selection_size: int,
    *,
    domain: bytes = b"",
    key: bytes,
) -> t.Generator[t.Any, None, None]:
    """
    Makes `selection_size` number of selections from an indexable
    sequence of `choices` using subkeys derived from a provided
    `domain` & `key`. Yields each selection one at a time.
    """
    total_choices = len(choices)
    key = DomainKDF(
        domain,
        total_choices.to_bytes(INT_BYTES, BIG),
        selection_size.to_bytes(INT_BYTES, BIG),
        key=key,
    ).shake_256(size=16 * selection_size, aad=Domains.PRNG)
    for index in batch(key, size=16):
        yield choices[int.from_bytes(index, BIG) % total_choices]


async def amnemonic(
    passphrase: t.Optional[bytes] = None,
    size: int = 8,
    *,
    salt: t.Optional[bytes] = None,
    words: t.Optional[t.Sequence[t.Any]] = None,
    **passcrypt_settings,
) -> t.List[bytes]:
    """
    Creates list of `size` number of words for a mnemonic key from a
    user `passphrase` & an optional `salt`. If no `passphrase` is
    supplied, then a random value is used to derive a unique mnemonic.
    The `words` used for the mnemonic can be passed, but by default
    are a word-list of 2048 unique, all lowercase english words.
    """
    domain = Domains.MNEMONIC
    words = words if words else WORD_LIST
    salt = await acanonical_pack(salt if salt else b"", domain)
    if passphrase:
        pcrypt = Passcrypt(**passcrypt_settings, tag_size=MIN_KEY_BYTES)
        key = await pcrypt.anew(passphrase, salt)
    elif not passcrypt_settings:
        key = await acsprng()
    else:
        mistake = "passcrypt_settings", "generating a random mnemonic key"
        raise Issue.unused_parameters(*mistake)
    choices = akeyed_choices(words, size, domain=domain, key=key)
    return [word async for word in choices]


def mnemonic(
    passphrase: t.Optional[bytes] = None,
    size: int = 8,
    *,
    salt: t.Optional[bytes] = None,
    words: t.Optional[t.Sequence[t.Any]] = None,
    **passcrypt_settings,
) -> t.List[bytes]:
    """
    Creates list of `size` number of words for a mnemonic key from a
    user `passphrase` & an optional `salt`. If no `passphrase` is
    supplied, then a random value is used to derive a unique mnemonic.
    The `words` used for the mnemonic can be passed, but by default
    are a word-list of 2048 unique, all lowercase english words.
    """
    domain = Domains.MNEMONIC
    words = words if words else WORD_LIST
    salt = canonical_pack(salt if salt else b"", domain)
    if passphrase:
        pcrypt = Passcrypt(**passcrypt_settings, tag_size=MIN_KEY_BYTES)
        key = pcrypt.new(passphrase, salt)
    elif not passcrypt_settings:
        key = csprng()
    else:
        mistake = "passcrypt_settings", "generating a random mnemonic key"
        raise Issue.unused_parameters(*mistake)
    return [*keyed_choices(words, size, domain=domain, key=key)]


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    akeyed_choices=akeyed_choices,
    amnemonic=amnemonic,
    keyed_choices=keyed_choices,
    mnemonic=mnemonic,
)

