## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.22.x  | :white_check_mark: |
| < 0.22  | :x:                |


## Security

We take the security of aiootp very seriously.

If you believe you have found a security vulnerability in aiootp, please report it to us as described below.


## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, send an email to [rmlibre@riseup.net](mailto:rmlibre@riseup.net) or [gonzo.development@protonmail.ch](mailto:gonzo.development@protonmail.ch).

We've provided a terminal utility within the package to automate encrypting security issue reports to us. Running the terminal application, which is demonstrated below, will print an encrypted message to the screen which you can then copy & send as an email:

For reference, here is our X25519 public key:
4457276dbcae91cc5b69f1aed4384b9eb6f933343bb44d9ed8a80e2ce438a450


```console

user@name:~$ python3
```


```python
>>> import aiootp

>>> aiootp.report_security_issue()
want to report a security issue? (y/N) y

we'll ask for your email address & a passphrase to encrypt
the keys, that will be generated automatically, locally on
your device.

how much RAM, in Mebibytes (1 MiB == 1024*1024 B), would you
like to use to hash this passphrase?
1024 Mebibytes (1 GiB) is recommended, but choose according
to what your machine has available, & how much you'd like
to protect the passphrase & the conversation keys on your
device: 1024

are you sure you'd like to use 1024 MiB of RAM to hash this
passphrase? (Y/n) y
your email address: example@email.address
your passphrase to continue the conversation (hidden):

please include the following information to help us to
efficiently fix the issue:

* type of attack(s) enabled by the issue
* name of source file(s) which participate in the issue
* step-by-step instructions to reproduce the issue
* proof-of-concept or exploit code (if possible)
* whether or not you'd like an email response

please type or paste your message here. hit CTRL-D (or
CTRL-Z on Windows) to finish the message:

Here is my message & detailed report to the team.


excellent! here's the json message you can email to us:

{
    "date": "AAACAQ",
    "public_key": "lQgAb8Xg5EHSJYjlj4QlOKlMgqHsxZuJBwr8MjgT5QA",
    "siv": "ciodgIg13h-YUIernVsMhAXljPuNuBOKaDHVlLZl5no",
    "encrypted_message": "rc1v2PNMwonw9wG0ob4Qg96iHVzVQc8YCO0sBnLA-XtSx0ijCfjEVDtHmO-8jyKTAH1cJGgejb1CTQdVpwmLfYXnohBSyHGzcU8qWZaQqeZ2KvJRcQRiLzBKorfKHZUCRa2eRnHPy8fD5FURFYwnbfwbbOYrLfm4OWZOae1XSpALAYmWoJv55BnwtSs77k5bFz3XIwoVvfiRtMIPJKH85FPCQ8fNbvk-gV1Wck1ilEgpEaOkMgdv_c1KalRFXzVT4P6KjdIW4eC0n2q02lArihsLpDpI1t1b7QIfyA7OsxWn3SAx2FCGK7F8pMD6Gbesa0nwwOtUry9r7t4Pr6wA7kEce_uPOb-li6tfykw2a5s"
}

send it to either rmlibre@riseup.net or gonzo.development@protonmail.com

thanks for your report! you should receive a response
within two weeks. your secret key has been saved locally.

>>>
```


## Preferred Languages

Communications are preferred to be in English, or with language declared(, and, if possible, with alternatives).


## License

### This file is part of aiootp, an asynchronous crypto and anonymity library. Home of the Chunky2048 pseudo one-time pad stream cipher.

#### Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
#### Copyright
####           © 2019-2021 Gonzo Investigative Journalism Agency, LLC <gonzo.development@protonmail.ch>
####           © 2019-2023 Richard Machado <rmlibre@riseup.net>

### All rights reserved.

