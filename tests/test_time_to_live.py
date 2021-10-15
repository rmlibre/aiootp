# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = ["__all__", "test_ttl_functionality"]


def test_ttl_functionality():
    delta = asynchs.time() - time_start
    if delta < 1:
        asynchs.sleep(1 - delta + 0.001)

    try:
        cipher.json_decrypt(test_json_ciphertext, aad=aad, ttl=1)
    except TimeoutError:
        pass
    else:
        raise AssertionError("Life-time for json ciphertext is malfunctioning.")
    try:
        run(cipher.ajson_decrypt(atest_json_ciphertext, aad=aad, ttl=1))
    except TimeoutError:
        pass
    else:
        raise AssertionError("Life-time for json ciphertext is malfunctioning.")

    try:
        cipher.read_token(test_token_ciphertext, aad=aad, ttl=1)
    except TimeoutError:
        pass
    else:
        raise AssertionError("Life-time for tokens is malfunctioning.")
    try:
        run(cipher.aread_token(atest_token_ciphertext, aad=aad, ttl=1))
    except TimeoutError:
        pass
    else:
        raise AssertionError("Life-time for tokens is malfunctioning.")

