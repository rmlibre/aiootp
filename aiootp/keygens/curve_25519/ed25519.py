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


__all__ = ["Ed25519"]


__doc__ = "An interface to Ed25519 signing & verifying."


from aiootp._typing import Typing as t
from aiootp._exceptions import Issue
from aiootp.asynchs import asleep

from .shared_interface import Base25519


class Ed25519(Base25519):
    """
    This class is used to create stateful objects that simplify usage of
    the cryptography library's ed25519 protocol.

     _____________________________________
    |                                     |
    |            Usage Example:           |
    |_____________________________________|

    from aiootp import Ed25519

    # In a land, long ago ->
    alices_key = Ed25519().generate()
    internet.send(alices_key.public_bytes)

    # Alice wants to sign a document so that Bob can prove she wrote it.
    # So, Alice sends her public key bytes of the key she wants to
    # associate with her identity, the document & the signature ->
    document = b"DesignDocument.cad"
    signed_document = alices_key.sign(document)
    message = {
        "document": document,
        "signature": signed_document,
        "public_key": alices_key.public_bytes,
    }
    internet.send(message)

    # In a land far away ->
    alices_message = internet.receive()

    # Bob sees the message from Alice! Bob already knows Alice's public
    # key & she has reason believe it is genuinely hers. She'll then
    # verify the signed document ->
    assert alices_message["public_key"] == alices_public_key
    alice_verifier = Ed25519().import_public_key(alices_public_key)
    alice_verifier.verify(
        alices_message["signature"], alices_message["document"]
    )
    internet.send(b"Beautiful work, Alice! Thanks ^u^")

    # The verification didn't throw an exception! So, Bob knows the file
    # was signed by Alice.
    """

    __slots__ = ("_public_key", "_secret_key")

    InvalidSignature: type = t.InvalidSignature
    PublicKey: type = t.Ed25519PublicKey
    SecretKey: type = t.Ed25519PrivateKey

    async def asign(self, data: bytes) -> bytes:
        """
        Signs some bytes `data` with the instance's secret key.
        """
        await asleep()
        return self.secret_key.sign(data)

    def sign(self, data: bytes) -> bytes:
        """
        Signs some bytes `data` with the instance's secret key.
        """
        return self.secret_key.sign(data)

    async def averify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: t.Union[None, bytes, t.Ed25519PublicKey] = None,
    ) -> None:
        """
        Receives a `signature` to verify data with the instance's
        public key. If the `public_key` keyword-only argument is
        used, then that key is used instead of the instance key to run
        the verification.
        """
        await asleep()
        self.verify(signature=signature, data=data, public_key=public_key)

    def verify(
        self,
        signature: bytes,
        data: bytes,
        *,
        public_key: t.Union[None, bytes, t.Ed25519PublicKey] = None,
    ) -> None:
        """
        Receives a `signature` to verify data with the instance's
        public key. If the `public_key` keyword-only argument is
        used, then that key is used instead of the instance key to run
        the verification.
        """
        if public_key is None:
            public_key = self.public_key
        else:
            public_key = self._process_public_key(public_key)
        public_key.verify(signature, data)


module_api = dict(
    Ed25519=t.add_type(Ed25519),
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

