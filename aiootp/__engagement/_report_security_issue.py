# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


import aiootp
from aiootp import *
from constants import *
from misc import *

import sys
import json
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def report_security_issue():
    # allow the user to configure aiootp to report a bug, but not be
    # obligated to.
    want_to_report_a_bug: bytes = input("want to report a security issue? (y/N) ")
    if not want_to_report_a_bug.lower().strip().startswith("y"):
        want_to_report_a_bug = False
        return

    # generate an ephemeral X25519 key & exchange it with the aiootp
    # public key
    your_public_key = X25519().generate()
    aiootp_public_key = bytes.fromhex(aiootp.__PUBLIC_X25519_KEY__)
    raw_shared_key = your_public_key.exchange(aiootp_public_key)

    # get credentials from user to created an encrypted database
    print(
        "\nwe'll ask for your email address & a passphrase to encrypt"
        "\nthe keys, that will be generated automatically, locally on"
        "\nyour device."
    )

    mb = input(
        "\nhow much RAM, in Mibibytes (1 MiB == 1024*1024 B), would you"
        "\nlike to use to hash this passphrase?"
        "\n1024 Mibibytes (1 GiB) is recommended, but choose according"
        "\nto what your machine has available, & how much you'd like"
        "\nto protect the passphrase & the conversation keys on your"
        "\ndevice: "
    )

    # give the user the power to choose the strength of the password
    # hashing algorithm
    while True:
        try:
            mb = max([int(mb), 1])
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
        mb = input(
            "\nhow much RAM, in Mibibytes (1 MiB == 1024*1024 B), would "
            "\nyou like to use to hash this passphrase? "
        )

    your_email_address = input("your email address: ").encode()
    PASSPHRASE_PROMPT: str = (
        "your passphrase to continue the conversation (hidden): "
    )

    # open a local encrypted database for the user to store the keys
    # generated to encrypt the report. this allows us to continue the
    # conversation with authentication
    db = Database.generate_profile(
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
    message = b"".join(line.encode() for line in sys.stdin)

    # derive the report's keys
    date = generics.Clock("days").make_timestamp(size=4)
    guid = GUID(size=12).new()
    shared_kdf = DomainKDF(
        Domains.USER,
        date,
        guid,
        your_email_address,
        your_public_key.public_bytes,
        aiootp_public_key,
        key=raw_shared_key,
    )
    key = shared_kdf.sha3_256(context=b"user_encryption_key")

    # encrypt the message payload
    encrypted_message = ChaCha20Poly1305(key).encrypt(
        nonce=guid,
        data=generics.Padding.pad_plaintext(message),
        associated_data=your_email_address,
    )

    # display ciphertext payload, what to expect & thank yous
    print("\nexcellent! here's the json message you can email to us:\n")
    print(json.dumps(dict(
        date=generics.BytesIO.bytes_to_urlsafe(date).decode(),
        guid=generics.BytesIO.bytes_to_urlsafe(guid).decode(),
        email_address=your_email_address.decode(),
        public_key=generics.BytesIO.bytes_to_urlsafe(your_public_key.public_bytes).decode(),
        encrypted_message=generics.BytesIO.bytes_to_urlsafe(encrypted_message).decode(),
    ), indent=4))
    print("\nsend it to either rmlibre@riseup.net or gonzo.development@protonmail.com")

    print(
        "\nthanks for your report! you should receive a response "
        "\nwithin two weeks. your secret key has been saved locally."
    )

