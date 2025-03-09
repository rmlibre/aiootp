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


chunky2048_test_vector_0 = OpenNamespace(
    plaintext=(
        b"it is not a doctrine to be preached, but a deed to be done."
    ),
    key=bytes.fromhex(
        "54868dc506d99611adb67f1b41eda44fd7151e135860a6d791cad6df6715bd"
        "5204713bc2b064e88a429b93aaa282d9cc7c0c5cdaaffb65cc268b7acedd5e"
        "531a"
    ),
    shmac=bytes.fromhex(
        "f791571464dd45754e16d8e6dea2f1a05204dca2510589be012bc5117dfd98e8"
    ),
    salt=bytes.fromhex("cf3761d57860bdbc"),
    iv=bytes.fromhex("e09d2eee03ae82e6"),
    aad=b"test_vector_I",
    ciphertext=bytes.fromhex(
        "1ce9033362f402390f872fa4f20de14d8a13f32f3906dd302a275b2c62f9f5"
        "f1a8ddb61871a2bab61dffaa2b414c2ca68601a61d9670a944619fc5105469"
        "b95e63c494326678e865a751d2ab0cac40439aa51cec3a8aa9e4cf0255ea96"
        "659a4cce41e2c8dac09f97d5bb05efb39bcf6043c6cd18364f0ecc0c721160"
        "e8204e333b1e336c55bd9a09ba1c0ce08805cc924c1925ad238b785ad17e6c"
        "064b2fe8676dc2fff3a3a895381cbf8d5aa04970c4f210ae323a5274c8f703"
        "4167ba0f7042e17d748d68327d2219c83bf4e4fb9f5d36c0b0c5ca661db09c"
        "b887d2bd39589d2e12f7a799b2e3e1cad7a7dbfd4c9d1a46de6ed5e51d7561"
        "70de526f4c4fa9fb"
    ),
)
