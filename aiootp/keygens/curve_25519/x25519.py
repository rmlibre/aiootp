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


__all__ = ["X25519"]


__doc__ = "An interface to X25519 protocols."


from aiootp._typing import Typing as t
from aiootp.asynchs import asleep
from aiootp.keygens.domain_kdf import DomainKDF

from .adapter import Curve25519
from .shared_interface import Base25519
from .double_diffie_hellman_client import DoubleDiffieHellmanClient
from .double_diffie_hellman_server import DoubleDiffieHellmanServer
from .triple_diffie_hellman_client import TripleDiffieHellmanClient
from .triple_diffie_hellman_server import TripleDiffieHellmanServer


class X25519(Base25519):
    """
    This class is used to create stateful objects that simplify usage of
    the cryptography library's x25519 protocol.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    user_alice = X25519().generate()
    # Alice wants to create a shared key with Bob. So, Alice sends the
    # public key bytes of her new key to bob ->
    internet.send(user_alice.public_bytes)

    # In a land far away ->
    alices_message = internet.receive()

    # Bob sees the message from Alice! So she creates a key to accept
    # the exchange & sends the public bytes back to Alice ->
    user_bob = await X25519().agenerate()
    shared_key = user_bob.exchange(alices_message)
    internet.send(user_bob.public_bytes)

    # When Alice receives Bob's public key & finishes the exchange, they
    # will have a shared symmetric key to encrypt messages to one
    # another.
    bobs_response = internet.receive()
    shared_key = user_alice.exchange(bobs_response)

    This protocol is not secure against active adversaries that can
    manipulate the information while its in transit between Alice &
    Bob. Each public key should only be used once.
    """

    __slots__ = ("_public_key", "_secret_key")

    _DoubleDiffieHellmanClient: type = DoubleDiffieHellmanClient
    _DoubleDiffieHellmanServer: type = DoubleDiffieHellmanServer
    _TripleDiffieHellmanClient: type = TripleDiffieHellmanClient
    _TripleDiffieHellmanServer: type = TripleDiffieHellmanServer

    PublicKey = Curve25519.X25519PublicKey
    SecretKey = Curve25519.X25519PrivateKey

    async def agenerate(self) -> t.Self:
        """
        Generates a new secret key used for a single elliptic curve
        diffie-hellman exchange, or as an argument to one of the 3dh or
        2dh generators in X25519.protocols. This populates the instance
        with the secret key & its associated public key. This method
        returns the instance for convenience in instantiating a stateful
        object with await X25519().agenerate().
        """
        key = await self._Curve25519.ax25519_key()
        await self.aimport_secret_key(key)
        return self

    def generate(self) -> t.Self:
        """
        Generates a new secret key used for a single elliptic curve
        diffie-hellman exchange, or as an argument to one of the 3dh or
        2dh generators in X25519.protocols. This populates the instance
        with the secret key & its associated public key. This method
        returns the instance for convenience in instantiating a stateful
        object with await X25519().generate().
        """
        key = self._Curve25519.x25519_key()
        self.import_secret_key(key)
        return self

    async def aexchange(
        self, public_key: t.Union[t.X25519PublicKey, bytes, str]
    ) -> bytes:
        """
        Takes in a public key from a communicating party & uses the
        instance's secret key to do an elliptic curve diffie-hellman
        exchange & returns the resulting secret shared bytes.
        """
        await asleep()
        public_key = self._process_public_key(public_key)
        return await self._Curve25519.aexchange(
            self._secret_key,
            await self._Curve25519.apublic_bytes(public_key),
        )

    def exchange(
        self, public_key: t.Union[t.X25519PublicKey, bytes, str]
    ) -> bytes:
        """
        Takes in a public key from a communicating party & uses the
        instance's secret key to do an elliptic curve diffie-hellman
        exchange & returns the resulting secret shared bytes.
        """
        public_key = self._process_public_key(public_key)
        return self._Curve25519.exchange(
            self._secret_key, self._Curve25519.public_bytes(public_key)
        )

    @classmethod
    def dh2_client(cls) -> DoubleDiffieHellmanClient:
        """
        Uses a `X25519` ephemeral secret key & a peer's identity &
        ephemeral public keys to enact the client side of a 2DH deniable
        key exchange.

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
        return cls._DoubleDiffieHellmanClient(
            kdf_type=DomainKDF, key_exchange_type=cls
        )

    def dh2_server(self) -> DoubleDiffieHellmanServer:
        """
        Uses `X25519` identity & ephemeral secret keys, & a peer's
        ephemeral public key to enact the server side of a 2DH deniable
        key exchange.

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
        return self._DoubleDiffieHellmanServer(
            self, kdf_type=DomainKDF, key_exchange_type=self.__class__
        )

    def dh3_client(self) -> TripleDiffieHellmanClient:
        """
        Uses `X25519` identity & ephemeral secret keys, & a peer's
        identity & ephemeral public keys to enact the client side of a
        3DH deniable key exchange.

         _____________________________________
        |                                     |
        |          Protocol Diagram:          |
        |_____________________________________|

                -----------------          |         -----------------
                |  Client-side  |          |         |  Server-side  |
                -----------------          |         -----------------
                                           |
        key = X25519().generate()          |         X25519().generate() = key
                                           |
        client = key.dh3_client()          |           key.public_bytes = id_s
                                           |
        id_c, eph_c = client.send(id_s) ------>
                                           |
                                           |         key.dh3_server() = server
                                           |
                                           | server.receive(id_c, eph_c) = kdf
                                           |
                                        <------          server.send() = eph_s
                                           |
        kdf = client.receive(eph_s)        |
                                           |
        ------------------------------------------------------------------------
        """
        return self._TripleDiffieHellmanClient(
            self, kdf_type=DomainKDF, key_exchange_type=self.__class__
        )

    def dh3_server(self) -> TripleDiffieHellmanServer:
        """
        Uses `X25519` identity & ephemeral secret keys, & a peer's
        identity & ephemeral public keys to enact the server side of a
        3DH deniable key exchange.

         _____________________________________
        |                                     |
        |          Protocol Diagram:          |
        |_____________________________________|

                -----------------          |         -----------------
                |  Client-side  |          |         |  Server-side  |
                -----------------          |         -----------------
                                           |
        key = X25519().generate()          |         X25519().generate() = key
                                           |
        client = key.dh3_client()          |           key.public_bytes = id_s
                                           |
        id_c, eph_c = client.send(id_s) ------>
                                           |
                                           |         key.dh3_server() = server
                                           |
                                           | server.receive(id_c, eph_c) = kdf
                                           |
                                        <------          server.send() = eph_s
                                           |
        kdf = client.receive(eph_s)        |
                                           |
        ------------------------------------------------------------------------
        """
        return self._TripleDiffieHellmanServer(
            self, kdf_type=DomainKDF, key_exchange_type=self.__class__
        )


module_api = dict(
    X25519=t.add_type(X25519),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

