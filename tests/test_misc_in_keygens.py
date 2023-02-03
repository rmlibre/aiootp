# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


async def test_mnemonic():
    phrase6 = b"-".join(mnemonic(key, 6, **passcrypt_settings))
    aphrase6 = b"-".join(await amnemonic(key, 6, **passcrypt_settings))
    assert all((word in WORD_LIST) for word in phrase6.lower().split(b"-"))
    assert phrase6 == aphrase6
    assert len(phrase6.split(b"-")) == 6

    phrase12 = b"-".join(mnemonic(key, 12, **passcrypt_settings)).title()
    aphrase12 = b"-".join(await amnemonic(key, 12, **passcrypt_settings)).title()
    assert all((word in WORD_LIST) for word in phrase12.lower().split(b"-"))
    assert phrase12 == aphrase12
    assert len(phrase12.split(b"-")) == 12


    context = "Can supply passcrypt settings to sync mnemonic when not given passphrase"
    with ignore(ValueError, if_else=violation(context)) as relay:
        phrase12 = b"-".join(mnemonic(size=12, **passcrypt_settings)).title()
    assert "parameters are not used" in relay.error.args[0]

    context = "Can supply passcrypt settings to async mnemonic when not given passphrase"
    with ignore(ValueError, if_else=violation(context)) as relay:
        aphrase12 = b"-".join(await amnemonic(size=12, **passcrypt_settings)).title()
    assert "parameters are not used" in relay.error.args[0]


    assert mnemonic() != await amnemonic()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

