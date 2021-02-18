# This file is part of aiootp, an asynchronous pseudo-one-time-pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigatory Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from init_tests import *


__all__ = [
    "test_incomplete_validation",
    "__all__",
]


def test_incomplete_validation():
    hmac_0 = pad.StreamHMAC(salt=salt)
    hmac_1 = pad.StreamHMAC(salt=salt, pid=pid)
    hmac_2 = pad.StreamHMAC(key=csprng(), salt=salt)
    hmacs = [hmac_0, hmac_1, hmac_2]

    digests = []
    adigests = []
    for hmac in hmacs:
        hmac.update(plaintext_bytes)
        run(hmac.aupdate(plaintext_bytes))
        digests.append(hmac.current_digest())
        adigests.append(run(hmac.acurrent_digest()))

    for i, hmac in enumerate(hmacs):
        hmac.test_current_digest(digests[i])
        run(hmac.atest_current_digest(adigests[i]))

        next_index = (i + 1) % len(hmacs)
        try:
            hmac.test_current_digest(digests[next_index])
        except ValueError:
            pass
        else:
            raise AssertionError("Validators don't detect invalid HMACs.")

        try:
            run(hmac.atest_current_digest(adigests[next_index]))
        except ValueError:
            pass
        else:
            raise AssertionError("Validators don't detect invalid HMACs.")
