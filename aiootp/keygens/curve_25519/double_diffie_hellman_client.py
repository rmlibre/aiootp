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


__all__ = ["DoubleDiffieHellmanClient"]


__doc__ = (
    "The client side of a key exchange protocol which can provide "
    "server-side identity authentication with ephemeral random secrets."
)


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue
from aiootp.commons import FrozenInstance
from aiootp.generics import Domains


class DoubleDiffieHellmanClient(FrozenInstance):
    """
    The client side of a key exchange protocol which can provide server-
    side identity authentication with ephemeral random secrets.

     _____________________________________
    |                                     |
    |          Protocol Diagram:          |
    |_____________________________________|

            -----------------          |         -----------------
            |  Client-side  |          |         |  Server-side  |
            -----------------          |         -----------------
                                       |
                                       |         X25519().generate() = key
                                       |
    client = X25519.dh2_client()       |           key.public_bytes = id_s
                                       |
    eph_c = client.send(id_s)       ------>
                                       |
                                       |         key.dh2_server() = server
                                       |
                                       |       server.receive(eph_c) = kdf
                                       |
                                    <------          server.send() = eph_s
                                       |
    kdf = client.receive(eph_s)        |
                                       |
    ------------------------------------------------------------------------
    """

    __slots__ = (
        "_kdf_type",
        "_key_exchange_type",
        "_my_ephemeral_key",
        "_peer_identity_key",
        "_peer_ephemeral_key",
    )

    def __init__(self, key_exchange_type: type, *, kdf_type: type) -> None:
        if not issubclass(kdf_type, t.DomainKDFType):
            raise Issue.value_must_be_subtype("KDF type", t.DomainKDFType)
        elif not issubclass(key_exchange_type, t.KeyExchangeType):
            raise Issue.value_must_be_subtype("KEX type", t.KeyExchangeType)
        self._kdf_type = kdf_type
        self._key_exchange_type = key_exchange_type

    async def asend(self, peer_identity_key: bytes) -> bytes:
        """
        Receives the identity public key of the intended server & returns
        the instance's ephemeral public key to be sent to the server.
        """
        self._peer_identity_key = peer_identity_key
        self._my_ephemeral_key = await self._key_exchange_type().agenerate()
        return self._my_ephemeral_key.public_bytes

    def send(self, peer_identity_key: bytes) -> bytes:
        """
        Receives the identity public key of the intended server & returns
        the instance's ephemeral public key to be sent to the server.
        """
        self._peer_identity_key = peer_identity_key
        self._my_ephemeral_key = self._key_exchange_type().generate()
        return self._my_ephemeral_key.public_bytes

    async def areceive(self, peer_ephemeral_key: bytes) -> t.DomainKDFType:
        """
        Receives the ephemeral public key that could've been sent from a
        server, & returns the KDF object which has been primed with the
        public & secret values involed in the exchange.
        """
        my_ephemeral_key = self._my_ephemeral_key
        peer_identity_key = self._peer_identity_key
        self._peer_ephemeral_key = peer_ephemeral_key
        shared_key_ad = await my_ephemeral_key.aexchange(peer_identity_key)
        shared_key_cd = await my_ephemeral_key.aexchange(peer_ephemeral_key)
        return self._kdf_type(
            Domains.DH2,
            my_ephemeral_key.public_bytes,
            peer_identity_key,
            peer_ephemeral_key,
            key=shared_key_ad + shared_key_cd,
        )

    def receive(self, peer_ephemeral_key: bytes) -> t.DomainKDFType:
        """
        Receives the ephemeral public key that could've been sent from a
        server, & returns the KDF object which has been primed with the
        public & secret values involed in the exchange.
        """
        my_ephemeral_key = self._my_ephemeral_key
        peer_identity_key = self._peer_identity_key
        self._peer_ephemeral_key = peer_ephemeral_key
        shared_key_ad = my_ephemeral_key.exchange(peer_identity_key)
        shared_key_cd = my_ephemeral_key.exchange(peer_ephemeral_key)
        return self._kdf_type(
            Domains.DH2,
            my_ephemeral_key.public_bytes,
            peer_identity_key,
            peer_ephemeral_key,
            key=shared_key_ad + shared_key_cd,
        )


module_api = dict(
    DoubleDiffieHellmanClient=t.add_type(DoubleDiffieHellmanClient),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

