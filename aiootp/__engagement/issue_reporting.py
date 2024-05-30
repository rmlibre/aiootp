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
from aiootp.ciphers.padding import Padding


def report_security_issue() -> None:
    # allow the user to configure aiootp to report a bug, but not be
    # obligated to.
    if not input("want to report a security issue? (y/N) ").lower().strip().startswith("y"):
        return

    # generate an ephemeral X25519 key & exchange it with the aiootp
    # public key
    your_public_key: X25519 = X25519().generate()
    aiootp_public_key: bytes = bytes.fromhex(__PUBLIC_X25519_KEY__)
    raw_shared_key: bytes = your_public_key.exchange(aiootp_public_key)

    # get credentials from user to create an encrypted database
    print(
        "\nwe'll ask for your email address & a passphrase to encrypt"
        "\nthe keys, that will be generated automatically, locally on"
        "\nyour device."
    )

    mb: str = input(
        "\nhow much RAM, in Mebibytes (1 MiB == 1024*1024 B), would you"
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
                f"\nare you sure you'd like to use {mb} MiB of RAM to hash this"
                "\npassphrase? (Y/n) "
            ).lower().strip().startswith("n"):
                raise PermissionError
            break
        except ValueError:
            print(f"Try again, {mb} is not a valid number.")
        except PermissionError:
            print("Ok, let's try again.")
        mb: str = input(
            "\nhow much RAM, in Mebibytes (1 MiB == 1024*1024 B), would "
            "\nyou like to use to hash this passphrase? "
        )

    your_email_address: bytes = input("your email address: ").encode()
    PASSPHRASE_PROMPT: str = (
        "your passphrase to continue the conversation (hidden): "
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
        "\nplease include the following information to help us to "
        "\nefficiently fix the issue:\n"
        "\n* type of attack(s) enabled by the issue"
        "\n* name of source file(s) which participate in the issue"
        "\n* step-by-step instructions to reproduce the issue"
        "\n* proof-of-concept or exploit code (if possible)"
        "\n* whether or not you'd like an email response"
    )
    print(
        "\nplease type or paste your message here. hit CTRL-D (or "
        "\nCTRL-Z on Windows) to finish the message:\n"
    )
    message: bytes = Padding(Chunky2048._config).pad_plaintext(
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
    siv: bytes = shared_kdf.sha3_256(message, aad=b"message_siv")
    key: bytes = shared_kdf.sha3_256(siv, aad=b"encryption_key")

    # encrypt the message payload
    encrypted_message: bytes = ChaCha20Poly1305(key).encrypt(
        nonce=siv[:12], data=message, associated_data=siv
    )

    # display ciphertext payload, what to expect & thank yous
    print("\n\nExcellent! here's the json message you can email to us:\n")
    print(json.dumps(dict(
        date=ByteIO.bytes_to_urlsafe(date).decode(),
        public_key=ByteIO.bytes_to_urlsafe(your_public_key.public_bytes).decode(),
        siv=ByteIO.bytes_to_urlsafe(siv).decode(),
        encrypted_message=ByteIO.bytes_to_urlsafe(encrypted_message).decode(),
    ), indent=4))
    print("\nsend it to either rmlibre@riseup.net or gonzo.development@protonmail.com")

    print(
        "\nthanks for your report! you should receive a response "
        "\nwithin two weeks. your secret key has been saved locally."
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

