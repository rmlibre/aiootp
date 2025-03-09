# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2025 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from aiootp.commons.namespaces import OpenNamespace


slick256_test_vector_0 = OpenNamespace(
    plaintext=(
        b"it is not a doctrine to be preached, but a deed to be done."
    ),
    key=bytes.fromhex(
        "54868dc506d99611adb67f1b41eda44fd7151e135860a6d791cad6df6715bd"
        "5204713bc2b064e88a429b93aaa282d9cc7c0c5cdaaffb65cc268b7acedd5e"
        "531a"
    ),
    shmac=bytes.fromhex("5e6011b3b1ae4314b4192a1e6a18b2ca8130bc5cafcd7287"),
    salt=bytes.fromhex("cf3761d57860bdbc"),
    iv=bytes.fromhex("dda31acd46832df9"),
    aad=b"test_vector_I",
    ciphertext=bytes.fromhex(
        "f73e7361a73af3eeabc88247555e06fc5bdaea10482c8351eab3ee9cfcc6fe"
        "f678b1171e6458fcef3d27896bee262769a742f8ffce51cd44db2a8e5673f4"
        "5770df4b907683c881049f15a92bed514613378ec4beb07766e809b5f68e1e"
        "326bc7"
    ),
)
