
## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.23.x  | :white_check_mark: |
| < 0.23  | :x:                |


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
    Want to report a security issue? (y/N) y

    We'll ask for your email address & a passphrase to encrypt
    the keys, that will be generated automatically, locally on
    your device.

    How much RAM, in Mebibytes (1 MiB == 1024*1024 B), would you
    like to use to hash this passphrase?
    1024 Mebibytes (1 GiB) is recommended, but choose according
    to what your machine has available, & how much you'd like
    to protect the passphrase & the conversation keys on your
    device: 1024

    Are you sure you'd like to use 1024 MiB of RAM to hash this
    passphrase? (Y/n)

    Your email address: my.example@email.com

    Your passphrase to continue the conversation (hidden):

    Please include the following information to help us to
    efficiently fix the issue:

    * Type of attack(s) enabled by the issue
    * Name of source file(s) which participate in the issue
    * Step-by-step instructions to reproduce the issue
    * Proof-of-concept or exploit code (if possible)
    * Whether or not you'd like an email response

    Please type or paste your message here. Hit CTRL-D (or
    CTRL-Z on Windows) to finish the message:

    This is my security issue report...


    Excellent! Here's the JSON message you can email to us:

    {
        "date": "AAACBQ",
        "public_key": "zPkXCPaWz2I7yVi9eZIYZdjOFNSMOph_ckr_p7_Cu2g",
        "siv": "jFv9OewJDKF1APTAJIyOCupMJYbqs8elp0qEUrhruVY",
        "encrypted_message": "Z0xlwqdUzqqLDqK-7Utj0upO6pXoZoWWXzbgf1wakaajUR8omQW9E_gBdFFa5BKc587YzUT8p67ZnluUgOCFMauvcYtfKQFuWDkRJH-M6BTTUEfPPiDRfXn66Zdv_fjZQk8aMQftduC_BNJVoBJ1P5VAid8wskehq1E44TERzjcixei68xsQz-86RgOCgNJ2nP3hQCZSghndQ-64aK1JEQCxVStYRUcSyPhqYYYeaPpGTkI1XAaW7QWp5_WoHhbtQwh0KB1Og3VY_7570huALj5N1qNabDwcaneoIvuV_MLUgF1NFmNnvPKzfLhkXiM9kUz6pFndDwXb0umzSuNHxuSPst-NJmYlGiMZ_pJhgVQ"
    }

    Send it to either rmlibre@riseup.net or gonzo.development@protonmail.com

    Thanks for your report! You should receive a response
    within two weeks. Your secret key has been saved locally.

    >>>
```


## Preferred Languages

Communications are preferred to be in English, or with language declared(, and, if possible, with alternatives).


## License

### This file is part of aiootp:

#### a high-level async cryptographic anonymity library to scale, simplify, & automate privacy best practices for secure data & identity processing, communication, & storage.

#### Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
#### Copyright
####           © 2019-2021 Gonzo Investigative Journalism Agency, LLC, <gonzo.development@protonmail.ch>
####           © 2019-2024 Ricchi (Richard) Machado, <rmlibre@riseup.net>

### All rights reserved.

