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


__all__ = ["report_security_issue"]


__doc__ = "Functionalities to engage with users & security researchers."


import sys
import json
from getpass import getpass
from collections import deque
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from aiootp import __PUBLIC_X25519_KEY__
from aiootp import Domains, DomainKDF, X25519, Database, Chunky2048
from aiootp._constants import CONVERSATION, PERIOD_KEYS, PERIOD_KEY
from aiootp.asynchs import Clock
from aiootp.generics import ByteIO, canonical_pack


def report_security_issue() -> None:
    # allow the user to configure aiootp to report a bug, but not be
    # obligated to.
    if not input("Want to report a security issue? (y/N) ").lower().strip().startswith("y"):
        return

    # generate an ephemeral X25519 key & exchange it with the aiootp
    # public key
    your_public_key: X25519 = X25519().generate()
    aiootp_public_key: bytes = bytes.fromhex(__PUBLIC_X25519_KEY__)
    raw_shared_key: bytes = your_public_key.exchange(aiootp_public_key)

    # get credentials from user to create an encrypted database
    print(
        "\nWe'll ask for your email address & a passphrase to encrypt"
        "\nthe keys, that will be generated automatically, locally on"
        "\nyour device."
    )

    mb: str = input(
        "\nHow much RAM, in Mebibytes (1 MiB == 1024*1024 B), would you"
        "\nlike to use to hash this passphrase?"
        "\n1024 Mebibytes (1 GiB) is recommended, but choose according"
        "\nto what your machine has available, & how much you'd like"
        "\nto protect the passphrase & the conversation keys on your"
        "\ndevice: "
    )

    # give the user the power to choose the strength of the password
    # hashing algorithm
    while True:
        try:
            mb: int = max([int(mb), 1])
            if input(
                f"\nAre you sure you'd like to use {mb} MiB of RAM to hash this"
                "\npassphrase? (Y/n) "
            ).lower().strip().startswith("n"):
                raise PermissionError()
            break
        except ValueError:
            print(f"\nTry again, {mb} is not a valid number.")
        except PermissionError:
            print("\nOk, let's try again.")
        mb: str = input(
            "\nHow much RAM, in Mebibytes (1 MiB == 1024*1024 B), would "
            "\nyou like to use to hash this passphrase? "
        )

    your_email_address: bytes = input("\nYour email address: ").encode()
    PASSPHRASE_PROMPT: str = (
        "\nYour passphrase to continue the conversation (hidden): "
    )

    # open a local encrypted database for the user to store the keys
    # generated to encrypt the report. this allows us to continue the
    # conversation with authentication
    db: Database = Database.generate_profile(
        username=your_email_address,
        passphrase=getpass(PASSPHRASE_PROMPT).encode(),
        salt=aiootp_public_key,
        aad=b"aiootp_security_issue_reports",
        mb=mb,
    )

    # initialize & persist cryptographic values for the user's bug report
    with db:
        if not db[CONVERSATION]:
            db[CONVERSATION] = {PERIOD_KEYS: []}
        db[CONVERSATION][PERIOD_KEYS] = list(deque(db[CONVERSATION][PERIOD_KEYS], maxlen=3))
        db[CONVERSATION][PERIOD_KEYS].append(db.make_token(
            your_public_key.secret_bytes, aad=PERIOD_KEY.encode()
        ).decode())

    # receive the security issue report
    print(
        "\nPlease include the following information to help us to "
        "\nefficiently fix the issue:\n"
        "\n* Type of attack(s) enabled by the issue"
        "\n* Name of source file(s) which participate in the issue"
        "\n* Step-by-step instructions to reproduce the issue"
        "\n* Proof-of-concept or exploit code (if possible)"
        "\n* Whether or not you'd like an email response"
    )
    print(
        "\nPlease type or paste your message here. Hit CTRL-D (or "
        "\nCTRL-Z on Windows) to finish the message:\n"
    )
    message: bytes = Chunky2048._padding.pad_plaintext(
        canonical_pack(
            your_email_address,
            b"".join(line.encode() for line in sys.stdin),
        )
    )

    # derive the user's report keys
    date: bytes = Clock("days").make_timestamp(size=4)
    shared_kdf: DomainKDF = DomainKDF(
        Domains.USER,
        date,
        your_public_key.public_bytes,
        aiootp_public_key,
        key=raw_shared_key,
    )
    siv: bytes = shared_kdf.sha3_256(message, aad=Domains.SIV)
    key: bytes = shared_kdf.sha3_256(siv, aad=Domains.ENCRYPTION_KEY)

    # encrypt the message payload
    encrypted_message: bytes = ChaCha20Poly1305(key).encrypt(
        nonce=siv[:12], data=message, associated_data=siv
    )

    # display ciphertext payload, what to expect & thank yous
    print("\n\nExcellent! Here's the JSON message you can email to us:\n")
    print(json.dumps(dict(
        date=ByteIO.bytes_to_urlsafe(date).decode(),
        public_key=ByteIO.bytes_to_urlsafe(your_public_key.public_bytes).decode(),
        siv=ByteIO.bytes_to_urlsafe(siv).decode(),
        encrypted_message=ByteIO.bytes_to_urlsafe(encrypted_message).decode(),
    ), indent=4))
    print("\nSend it to either rmlibre@riseup.net or gonzo.development@protonmail.com")

    print(
        "\nThanks for your report! You should receive a response "
        "\nwithin two weeks. Your secret key has been saved locally."
    )


module_api = dict(
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
    report_security_issue=report_security_issue,
)

