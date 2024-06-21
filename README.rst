
.. image:: https://raw.githubusercontent.com/rmlibre/aiootp/main/logo.png
    :target: https://raw.githubusercontent.com/rmlibre/aiootp/main/logo.png
    :alt: aiootp python package logo




aiootp — an async privacy, anonymity, & cryptography library.
==============================================================

``aiootp`` is a high-level async cryptographic anonymity library to scale, simplify, & automate privacy best practices for secure data & identity processing, communication, & storage.

It's home to a family of novel online, salt misuse-reuse resistant, tweakable, & fully context committing AEAD ciphers. A 256-byte block-wise stream cipher named ``Chunky2048``. And, a robust 32-byte hybrid block-cipher / stream-cipher called ``Slick256``. The design goals behind this family of ciphers are to be simple & efficient, while achieving modern security notions, wide security margins, & aiming towards incorporating information theoretic undecidability guarantees where possible.

We hope to give users & applications empowering developer-friendly privacy enhancing tools with strong, biased defaults. In so doing, increase the overall security, privacy, & anonymity in the digital world. Users will find ``aiootp`` to be easy to write, easy to read, & fun.




.. image:: https://img.shields.io/pypi/v/aiootp
    :target: https://img.shields.io/pypi/v/aiootp
    :alt: version

.. image:: https://img.shields.io/pypi/pyversions/aiootp?color=black
    :target: https://img.shields.io/pypi/pyversions/aiootp?color=black
    :alt: python-versions

.. image:: https://img.shields.io/badge/License-AGPL%20v3-red.svg
    :target: https://img.shields.io/badge/License-AGPL%20v3-red.svg
    :alt: license

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://img.shields.io/badge/code%20style-black-000000.svg
    :alt: code-style

.. image:: https://img.shields.io/pypi/wheel/aiootp
    :target: https://img.shields.io/pypi/wheel/aiootp
    :alt: python-wheel-availability

.. image:: https://github.com/rmlibre/aiootp/actions/workflows/linux-python-app.yml/badge.svg
    :target: https://github.com/rmlibre/aiootp/actions/workflows/linux-python-app.yml/badge.svg
    :alt: linux-build-status

.. image:: https://github.com/rmlibre/aiootp/actions/workflows/windows-python-app.yml/badge.svg
    :target: https://github.com/rmlibre/aiootp/actions/workflows/windows-python-app.yml/badge.svg
    :alt: windows-build-status

.. image:: https://github.com/rmlibre/aiootp/actions/workflows/macos-python-app.yml/badge.svg
    :target: https://github.com/rmlibre/aiootp/actions/workflows/macos-python-app.yml/badge.svg
    :alt: macos-build-status




Quick Install
-------------

.. code-block:: shell

    $ sudo apt-get install python3 python3-setuptools python3-pip

    $ pip3 install --user --upgrade pip typing aiootp




Run Tests
---------

.. code-block:: shell

    $ pip3 install --user --upgrade pytest pytest-asyncio coverage

    $ coverage run --source aiootp -p -m pytest -vv tests/test_aiootp.py

    $ coverage combine && coverage html && coverage report




.. warning::

    ``aiootp`` is **experimental software** that works with Python 3.8+. It's a work in progress. Its algorithms & programming API are likely to change with future updates, & it isn't bug free.

    ``aiootp`` provides security tools & misc utilities that're designed to be developer-friendly & privacy preserving.

    As a security tool, ``aiootp`` needs to be tested & improved extensively by the programming & cryptography communities to ensure its implementations are sound. We provide no guarantees.

    This software hasn't yet been audited by 3rd-party security professionals.




_`Table Of Contents`
--------------------

- `Transparently Encrypted Databases`_

  a) `Ideal Initialization`_

  b) `User Profiles`_

  c) `Tags`_

  d) `Metatags`_

  e) `Basic Management`_

  g) `Encrypt / Decrypt`_


- `Chunky2048 & Slick256 Ciphers`_

  a) `High-level Functions`_

  b) `High-level Generators`_

  c) `Chunky2048 Algorithm`_

  d) `Slick256 Algorithm`_


- `Passcrypt`_

  a) `Hashing & Verifying Passphrases`_

  b) `Passcrypt Algorithm Overview`_


- `X25519 & Ed25519`_

  a) `X25519`_

  b) `Ed25519`_




_`Transparently Encrypted Databases` .............. `Table Of Contents`_
------------------------------------------------------------------------

The package's ``AsyncDatabase`` & ``Database`` classes are very powerful data persistence utilities. They're key-value type databases, & they automatically handle encryption & decryption of user data & metadata, providing a Pythonic interface for storing & retrieving any bytes or JSON serializable objects. They're designed to seamlessly bring encrypted bytes at rest to users as dynamic objects in use.


_`Ideal Initialization` ........................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Make a new user key with a fast, cryptographically secure pseudo-random number generator. Then this strong 64-byte key can be used to create a database object.

.. code-block:: python

    from aiootp import acsprng, AsyncDatabase


    key = await acsprng()

    db = await AsyncDatabase(key)


_`User Profiles` .................................. `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

With User Profiles, passphrases may be used instead to open a database. Often, passwords & passphrases contain very little entropy. So, they aren't recommended for that reason. However, profiles provide a succinct way to use passphrases more safely. They do this by deriving strong keys from low entropy user input using the memory/cpu hard passcrypt algorithm, & a secret salt which is automatically generated & stored on the user's filesystem.

.. code-block:: python

    db = await AsyncDatabase.agenerate_profile(

        b"server-url.com",     # Here an unlimited number of bytes-type
                               # arguments can be passed as additional
        b"address@email.net",  # optional credentials.

        username=b"username",

        passphrase=b"passphrase",

        salt=b"optional salt keyword argument",
                  # Optional passcrypt configuration:
        mb=256,   # The memory cost in Mebibytes (MiB)

        cpu=2,    # The computational complexity & number of iterations

        cores=8,  # How many parallel processes passcrypt will utilize

    )


_`Tags` ........................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Data within databases are values that are primarily organized by Tag keys. Tags are simply string labels, and the data stored under them can be any bytes or JSON serializable objects.

Using bracketed assignment adds tags to the cache. Changes in the cache are saved to disk when the database context closes.

.. code-block:: python

    async with db:

        db["tag"] = {"any": ["JSON", "serializable", "object"]}

        db["8b362accfdf600ea"] = b"some amount of data."


All instance tags are viewable. Each tag has its data saved to a separate, independent file, which is quite convenient when working in asynchronous, concurrent, & distributed settings.

.. code-block:: python

    db.tags
    >>> {'tag', '8b362accfdf600ea'}

    db.filenames
    >>> {'0z0l10btu_yd-n4quc8tsj9baqu8xmrxz87ix',
     '197ulmqmxg15lebm26zaahpqnabwr8sprojuh'}


Learning how to manage tags stored in the cache vs. saved to disk is essential.

.. code-block:: python

    # stores data in the cache ->

    await db.aset_tag("new_tag", ["data", "goes", "here"])


    # reads from disk if not in the cache ->

    await db.aquery_tag("new_tag")
    >>> ['data', 'goes', 'here']


    # saved in the cache, still not to disk ->

    tag_path = db.path / await db.afilename("new_tag")

    assert "new_tag" in db

    assert not tag_path.is_file()


    # now it gets saved to disk ->

    await db.asave_tag("new_tag")

    assert tag_path.is_file()


Unsaved changes in the cache can be rolled back, & data saved to disk can be popped from the database.

.. code-block:: python

    db["new_tag"].append("!")

    db["new_tag"]
    >>> ['data', 'goes', 'here', '!']

    await db.arollback_tag("new_tag")

    db["new_tag"]
    >>> ['data', 'goes', 'here']

    await db.apop_tag("new_tag")
    >>> ['data', 'goes', 'here']

    "new_tag" in db
    >>> False

    tag_path.is_file()
    >>> False

    db["new_tag"]
    >>>


    #

Access to data is open to the user, so care must be taken not to let external API calls touch the database without accounting for how that can go wrong.


_`Metatags` ....................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Metatags are used to organize data by string names & domain-separated cryptographic material. They're fully-fledged databases all on their own, with their own distinct key material too. They're accessible from the parent through an attribute that's added to the parent instance with the same name as the metatag. When the parent is saved, or deleted, then their descendants are also.


.. code-block:: python

    async with db:

        db_0 = await db.ametatag("process_0")

        assert db_0 is db.process_0


        db_1 = await db.ametatag("process_1")

        assert db_1 is db.process_1


    assert all(

        isinstance(metatag, AsyncDatabase)

        for metatag in [db_0, db_1]

    )


They can contain their own sets of tags (and metatags). If metatags, or tags, are used as partitions that are accessed across distributed or concurrent contexts, it's highly recommended that each partition have only one distinct caller or object reference with write & cache access.

.. code-block:: python

    db = await AsyncDatabase(key)  # distinct object reference

    assert db_0 is not db.process_0

    assert db_1 is not db.process_1


    async with db_0:

        db_0["data"] = b"data added within process 0."

    #      cache access                            disk read
    #       vvvvvvvvvv                            vvvvvvvvvvv
    assert db_0["data"] == await db.process_0.aquery_tag("data")


    async with db_1:

        db_1["data"] = b"data added within process 1."

    #      cache access                            disk read
    #       vvvvvvvvvv                            vvvvvvvvvvv
    assert db_1["data"] == await db.process_1.aquery_tag("data")


Deleting a metatag from an instance recursively deletes all of its own tags & metatags. To avoid inconsistencies, this should only be done from the original parent whose metatag reference ``is`` the metatag object with write & cache access.

.. code-block:: python

    metatag_manifest_file = db_0._root_path

    assert metatag_manifest_file.is_file()


    assert db_0 is db.process_0  # using the original parent object

    async with db:

        await db.adelete_metatag("process_0")


    db.metatags
    >>> {'process_1'}

    assert not hasattr(db, "process_0")

    assert not metatag_manifest_file.is_file()


    #


_`Basic Management` ............................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There's a few settings & public methods on databases for users to manage their instances & data. This includes general utilities for saving & deleting databases to & from the filesystem, as well as fine-grained controls for how data is handled.

.. code-block:: python

    # The path attribute is set within the instance's __init__

    # using a keyword-only argument. It's the directory where the

    # instance will store all of its files.

    db.path
    >>> PosixPath('site-packages/aiootp/aiootp/db')


    # Write database changes to disk with transparent encryption ->

    await db.asave_database()


    # Entering the instance's context also saves data to disk ->

    async with db:

        print("Saving to disk...")


    # Delete a database from the filesystem ->

    await db.adelete_database()


As databases grow in the number of tags, metatags & the size of data within, it becomes desireable to load data from them as needed, instead of all at once into the cache during initialization. This is why the ``preload`` boolean keyword-only argument is set to ``False`` by default.

.. code-block:: python

    # Let's create some test values to show the impact preloading has ->

    async with (await AsyncDatabase(key, preload=True)) as db:

        db["favorite_foods"] = ["justice", "community"]

        routines = await db.ametatag("exercise_routines")

        routines["gardening"] = {"days": ["monday", "wednesday"]}

        routines["swimming"] = {"days": ["thursday", "saturday"]}


    # Again, preloading into the cache is toggled off by default ->

    uncached_db = await AsyncDatabase(key)


    # To retrieve elements, ``aquery_tag`` isn't necessary when

    # preloading is used, since the tag is already in the cache ->

    async with uncached_db:

        db["favorite_foods"]
        >>> ["justice", "community"]

        uncached_db["favorite_foods"]
        >>> None

        value = await uncached_db.aquery_tag("favorite_foods", cache=True)

        assert value == ["justice", "community"]

        assert uncached_db["favorite_foods"] == ["justice", "community"]


        # Metatags will be loaded, but their tags won't be ->

        uncached_db.exercise_routines["gardening"]
        >>> None

        await uncached_db.exercise_routines.aquery_tag("gardening", cache=True)
        >>> {"days": ["monday", "wednesday"]}

        uncached_db.exercise_routines["gardening"]
        >>> {"days": ["monday", "wednesday"]}


        # But, tags can also be queried without caching their values,

        value = await uncached_db.exercise_routines.aquery_tag("swimming")

        value
        >>> {"days": ["thursday", "saturday"]}

        uncached_db.exercise_routines["swimming"]
        >>> None


        # However, changes to mutable values won't be transmitted to the

        # database if they aren't retrieved from the cache ->

        value["days"].append("sunday")

        value
        >>> {"days": ["thursday", "saturday", "sunday"]}

        await uncached_db.exercise_routines.aquery_tag("swimming")
        >>> {"days": ["thursday", "saturday"]}


    #


_`Encrypt / Decrypt` .............................. `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Although databases handle encryption & decryption of files automatically, users may want to utilize their databases' keys to do manual cryptographic procedures. There are a few public functions which provide such functionality.

.. code-block:: python

    json_plaintext = {"some": "JSON data can go here..."}

    bytes_plaintext = b"some bytes plaintext goes here..."

    token_plaintext = b"some token data goes here..."

    json_ciphertext = await db.ajson_encrypt(json_plaintext)

    bytes_ciphertext = await db.abytes_encrypt(bytes_plaintext)

    token_ciphertext = await db.amake_token(token_plaintext)


    assert json_plaintext == await db.ajson_decrypt(json_ciphertext)

    assert bytes_plaintext == await db.abytes_decrypt(bytes_ciphertext)

    assert token_plaintext == await db.aread_token(token_ciphertext)


Filenames & other associated data may be added to classify & tweak ciphertexts.

.. code-block:: python

    filename = "grocery-list"

    groceries = ["carrots", "taytoes", "rice", "beans"]

    ciphertext = await db.ajson_encrypt(
        groceries, filename=filename, aad=b"test"
    )

    assert groceries == await db.ajson_decrypt(
        ciphertext, filename=filename, aad=b"test"
    )

    await db.ajson_decrypt(
        ciphertext, filename="wrong filename", aad=b"test"
    )
    >>> "InvalidSHMAC: Invalid StreamHMAC hash for the given ciphertext."


Time-based expiration checking is available for all ciphertexts.

.. code-block:: python

    from aiootp.asynchs import asleep


    await asleep(6)

    await db.ajson_decrypt(json_ciphertext, ttl=1)
    >>> "TimestampExpired: Timestamp expired by <5> seconds."

    await db.abytes_decrypt(bytes_ciphertext, ttl=1)
    >>> "TimestampExpired: Timestamp expired by <5> seconds."

    await db.aread_token(token_ciphertext, ttl=1)
    >>> "TimestampExpired: Timestamp expired by <5> seconds."

    try:

        await db.abytes_decrypt(bytes_ciphertext, ttl=1)

    except db.TimestampExpired as error:

        assert error.expired_by == 5


    #




_`Chunky2048 & Slick256 Ciphers` .................. `Table Of Contents`_
------------------------------------------------------------------------

``Chunky2048`` & ``Slick256`` are novel cipher designs that use SHA3 extendable-output functions for key derivation & data authentication. They're distinct by being online, salt misuse-reuse resistant, fully context committing, & tweakable, AEADs.

``Chunky2048`` is a stream cipher that processes blocks of data 256 bytes at a time. It accepts any length of key larger than 64 bytes, with a maximum internal entropy of 600 bytes.

``Slick256`` on the other hand is a 32 byte combined stream & block cipher. Each round it XOR's an independent stream key with data, passes that sum through a keyed permutation, & XOR's the result with another independent stream key. It also accepts any length of key larger than 64 bytes, with a maximum internal entropy of 200 bytes.

They're each designed to be easy to use, difficult to misuse, & future-proof with very wide security margins.


_`High-level Functions` .......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These premade recipes allow for the easiest usage of the cipher. First, choose a cipher interface.

.. code-block:: python

    import aiootp


    cipher = aiootp.Chunky2048(key)

    cipher = aiootp.Slick256(key)


Symmetric encryption of JSON data.

.. code-block:: python

    json_data = {"account": 33817, "names": ["queen b"], "id": None}

    encrypted_json = cipher.json_encrypt(json_data, aad=b"demo")


    assert json_data == cipher.json_decrypt(

        encrypted_json, aad=b"demo", ttl=120

    )


Symmetric encryption of binary data.

.. code-block:: python

    binary_data = b"some plaintext data..."

    encrypted_binary = cipher.bytes_encrypt(binary_data, aad=b"demo")


    assert binary_data == cipher.bytes_decrypt(

        encrypted_binary, aad=b"demo", ttl=30

    )


Encrypted URL-safe Base64 encoded tokens.

.. code-block:: python

    from collections import deque

    from aiootp.generics import canonical_pack, canonical_unpack


    token_data = deque([b"user_id", b"session_id", b"secret_value"])

    encrypted_token = cipher.make_token(

        canonical_pack(*token_data, int_bytes=1), aad=b"demo"

    )


    assert token_data == canonical_unpack(

        cipher.read_token(encrypted_token, aad=b"demo", ttl=3600)

    )


    #


_`High-level Generators` .......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

With these generators, the online nature of the Chunky2048 cipher can be utilized. This means that any arbitrary amount of data can be processed in streams of controllable, buffered chunks. These streaming interfaces automatically handle message padding & depadding, ciphertext validation & detection of out-of-order message blocks.


Encryption:
***********

Choose a cipher interface.

.. code-block:: python

    from aiootp import Chunky2048, Slick256


    cipher = Chunky2048(key)

    cipher = Slick256(key)


Let's imagine we are serving some data over a network. This will manage encrypting a stream of data.

.. code-block:: python

    receiver = SomeRemoteConnection(session).connect()

    ...

    stream = cipher.astream_encrypt(aad=session.transcript)


We'll have to send the salt & iv in some way.

.. code-block:: python

    receiver.transmit(salt=stream.salt, iv=stream.iv)


Now we can buffer the plaintext we are going to encrypt.

.. code-block:: python

    for plaintext in receiver.upload.buffer(4 * stream.PACKETSIZE):

        await stream.abuffer(plaintext)


        # The stream will now produce encrypted blocks of ciphertext

        # as well as the block ID which authenticates each block ->

        async for block_id, ciphertext in stream:

            # The receiver needs both the block ID & ciphertext ->

            receiver.send_packet(block_id + ciphertext)


Once done with buffering-in the plaintext, the ``afinalize`` method is called so the remaining encrypted data will be flushed out of the buffer to the user.

.. code-block:: python

    async for block_id, ciphertext in stream.afinalize():

        receiver.send_packet(block_id + ciphertext)


    # Now we have to send the final authentication tag ->

    receiver.transmit(shmac=stream.shmac.result)


    #


Decryption:
***********

Choose the correct cipher interface.

.. code-block:: python

    from aiootp import Chunky2048, Slick256

    cipher = Chunky2048(key)

    cipher = Slick256(key)


Here let's imagine we'll be downloading some data. The key, salt, aad & iv will need to be the same for both parties.

.. code-block:: python

    source = SomeRemoteConnection(session).connect()

    ...

    stream = cipher.astream_decrypt(

        salt=source.salt, aad=session.transcript, iv=source.iv

    )


If authentication succeeds, the plaintext is produced from the downloaded ciphertext buffer chunks.

.. code-block:: python

    for ciphertext in source.download.buffer(4 * stream.PACKETSIZE):

        # Here stream.shmac.InvalidBlockID is raised if an invalid or

        # out-of-order block is detected within the last 4 packets ->

        try:

            await stream.abuffer(ciphertext)

        except cipher.InvalidBlockID as error:

            pass


        async for plaintext in stream:

            yield plaintext


After all the ciphertext is downloaded, ``afinalize`` is called to finish processing the stream & flush out the plaintext. The final authenticity tag has to be checked once the stream is finished.

.. code-block:: python

    async for plaintext in stream.afinalize():

        yield plaintext

    await stream.shmac.atest_shmac(source.shmac)


    #


_`Chunky2048 Algorithm` ........................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


.. code-block:: bash

    '''

    S = SHMAC KDF
    L = Left KDF
    R = Right KDF
    P = 256-byte plaintext block
    C = 256-byte ciphertext block
    O = Two concatenated 168-byte SHMAC KDF outputs
    K_L, K_R = the two 168-byte left & right KDF outputs

    Each block, except for the first, is processed as such:

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Encryption    |
    |_____________________________________|
                                       ___       ___
                                        |         |
                                        |    ___ _|_
                                        |     |   |
                             -----      |     |   |
                O[0::2] --->|  L  |--->K_L----⊕-->|
               /             -----      |     |   |           /
         -----/                         |     |   |     -----/
        |  S  |                        ---    P   C    |  S  |
         -----\                         |     |   |     -----\
           ^   \             -----      |     |   |       ^   \
           |    O[1::2] --->|  R  |--->K_R----⊕-->|       |
           |                 -----      |     |   |       |
           |                            |    _|_ _|_      |
           |                            |         |       |
           |                           _|_       _|_      |
           |                                      |       |
    --------                                      ---------
     _____________________________________
    |                                     |
    |    Algorithm Diagram: Decryption    |
    |_____________________________________|
                                       ___   ___
                                        |     |
                                        |    _|_ ___
                                        |     |   |
                             -----      |     |   |
                O[0::2] --->|  L  |--->K_L----⊕-->|
               /             -----      |     |   |           /
         -----/                         |     |   |     -----/
        |  S  |                        ---    C   P    |  S  |
         -----\                         |     |   |     -----\
           ^   \             -----      |     |   |       ^   \
           |    O[1::2] --->|  R  |--->K_R----⊕-->|       |
           |                 -----      |     |   |       |
           |                            |    _|_ _|_      |
           |                            |     |           |
           |                           _|_   _|_          |
           |                                  |           |
    --------                                  -------------


    '''


_`Slick256 Algorithm` ............................. `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


.. code-block:: bash

    '''

    S = SHMAC KDF
    π = Permutation()
    P = 32-byte plaintext block
    C = 32-byte ciphertext block
    K_I, K_O, D = (K_i[:32], K_i[32:64], K_i[64:168])

    Each block is processed as such:

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Encryption    |
    |_____________________________________|

                 K_I-------⊕--------       P
                /          ^       |       |                     /
               /           |       v       |                    /
         -----/            P     -----     v              -----/
    --->|  S  |                 |  π  |   (P ║ C ║ D)--->|  S  |
         -----\                  -----         ^          -----\
               \                   |           |                \
                \                  v           |                 \
                 K_O---------------⊕---------->C

     _____________________________________
    |                                     |
    |    Algorithm Diagram: Decryption    |
    |_____________________________________|

                 K_I---------------⊕------>P
                /                  ^       |                     /
               /                   |       |                    /
         -----/                  -----     v              -----/
    --->|  S  |                 |  π  |   (P ║ C ║ D)--->|  S  |
         -----\            C     -----         ^          -----\
               \           |       ^           |                \
                \          v       |           |                 \
                 K_O-------⊕--------           C


    '''




_`Passcrypt` .............................. `Table Of Contents`_
------------------------------------------------------------------------

The ``Passcrypt`` algorithm is a data independent memory & computationally hard password-based key derivation function. It's built from a single primitive, the SHAKE-128 extendable output function from the SHA-3 family. Its resource costs are measured by three parameters: ``mb``, which represents an integer number of Mebibytes (MiB); ``cpu``, which is a linear integer measure of computational complexity & the number of iterations of the algorithm over the memory cache; and ``cores``, which is an integer which directly assigns the number of separate processes that will be pooled to complete the algorithm. The number of bytes of the output tag are decided by the integer ``tag_size`` parameter. And, the number of bytes of the automatically generated ``salt`` are decided by the integer ``salt_size`` parameter.


_`Hashing & Verifying Passphrases` .......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


By far, the dominating measure of difficulty for ``Passcrypt`` is determined by the ``mb`` Mebibyte memory cost. It's recommended that increases to desired difficulty are first translated into higher ``mb`` values, where resource limitations of the machines executing the algorithm permit. If more difficulty is desired than can be obtained by increasing ``mb``, then increases to the ``cpu`` parameter should be used. The higher this parameter is the less likely an adversary is to benefit from expending less than the intended memory cost, & increases the execution time & complexity of the algorithm. The final option that should be considered, if still more difficulty is desired, is to lower the ``cores`` parallelization parameter, which will just cause each execution to take longer to complete.


The class accepts an optional (but recommended) static "pepper" which is applied as additional randomness to all hashes computed by the class. It's a secret random bytes value of any size that is expected to be stored somewhere inaccessible by the database which contains the hashed passphrases.

.. code-block:: python

    from aiootp import Passcrypt, hash_bytes


    with open(SECRET_PEPPER_PATH, "rb") as pepper_file:

        Passcrypt.PEPPER = pepper_file.read()


When preparing to hash passphrases, it's a good idea to use any & all of the static data / credentials available which are specific to the context of the registration.

.. code-block:: python

    APPLICATION = b"my-application-name"

    PRODUCT = b"the-product-being-accessed-by-this-registration"

    STATIC_CONTEXT = [APPLICATION, PRODUCT, PUBLIC_CERTIFICATE]


A ``Passcrypt`` instance is initialized with the desired difficulty settings.

.. code-block:: python

    pcrypt = Passcrypt(
        mb=1024,      # 1 GiB
        cpu=2,        # 2 iterations
        cores=8,      # 8 parallel cores
        tag_size=16,  # 16-byte hash
    )


Now we can start hashing any user information that arrives.

.. code-block:: python

    username = form["username"].encode()

    passphrase = form["passphrase"].encode()

    email_address = form["email_address"].encode()


The ``hash_bytes`` function can then be used to automatically encode then hash the multi-input data so as to prevent the chance of canonicalization (&/or length extension) attacks.

.. code-block:: python

    aad = hash_bytes(*STATIC_CONTEXT, username, email_address)

    hashed_passphrase = pcrypt.hash_passphrase(passphrase, aad=aad)

    assert type(hashed_passphrase) is bytes

    assert len(hashed_passphrase) == 38


Later, a hashed passphrase can be used to authenticate a user.

.. code-block:: python

    untrusted_username = form["username"].encode()

    untrusted_passphrase = form["passphrase"].encode()

    untrusted_email_address = form["email_address"].encode()

    aad = hash_bytes(

        *STATIC_CONTEXT, untrusted_username, untrusted_email_address

    )

    try:

        pcrypt.verify(

            hashed_passphrase, untrusted_passphrase, aad=aad, ttl=3600

        )

    except pcrypt.InvalidPassphrase as auth_fail:

        # If the passphrase does not hash to the same value as the

        # stored hash, then this exception is raised & can be handled

        # by the application ->

        app.post_mortem(error=auth_fail)

    except pcrypt.TimestampExpired as registration_expired:

        # If the timestamp on the stored hash was created more than

        # ``ttl`` seconds before the current time, then this exception

        # is raised. This is helpful for automating registrations which

        # expire after a certain amount of time, which in this case was

        # 1 hour ->

        app.post_mortem(error=registration_expired)

    else:

        # If no exception was raised, then the user has been authenticated

        # by their passphrase, username, email address & the context of

        # the registration ->

        app.login_user(username, email_address)


    #


_`Passcrypt Algorithm Overview` .......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By being secret-independent, ``Passcrypt`` is resistant to side-channel attacks. This implementation is also written in pure python. Significant attention was paid to design the algorithm so as to suffer minimally from the performance inefficiencies of python, since doing so would help to equalize the cost of computation between regular users & dedicated attackers with custom hardware / software. Below is a diagram that depicts how an example execution works:

.. code-block:: bash

    """

           ___________________ # of rows ___________________
          |                                                 |
          |              initial memory cache               |
          |  row  # of columns == 2 * max([1, cpu // 2])    |
          |   |   # of rows == ⌈1024*1024*mb/168*columns⌉   |
          v   v                                             v
    column|---'-----------------------------------------'---| the initial cache
    column|---'-----------------------------------------'---| of size ~`mb` is
    column|---'-----------------------------------------'---| built very quickly
    column|---'-----------------------------------------'---| using SHAKE-128.
    column|---'-----------------------------------------'---| each (row, column)
    column|---'-----------------------------------------'---| coordinate holds
    column|---'-----------------------------------------'---| one element of
    column|---'-----------------------------------------'---| 168-bytes.
                                                        ^
                                                        |
                           reflection                  row
                          <-   |
          |--------------------'-------'--------------------| each row is
          |--------------------'-------'--------------------| hashed then has
          |--------------------'-------'--------------------| a new 168-byte
          |--------------------'-------'--------------------| digest overwrite
          |--------------------'-------'--------------------| the current pointer
          |--------------------'-------'--------------------| in an alternating
          |--------------------Xxxxxxxx'xxxxxxxxxxxxxxxxxxxx| sequence, first at
          |oooooooooooooooooooo'oooooooO--------------------| the index, then at
                                       |   ->                 its reflection.
                                     index


          |--'-------------------------------------------'--| this continues
          |--'-------------------------------------------'--| until the entire
          |--'-------------------------------------------Xxx| cache has been
          |ooO-------------------------------------------'--| overwritten.
          |xx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'xx| a single `shake_128`
          |oo'ooooooooooooooooooooooooooooooooooooooooooo'oo| object (H) is used
          |xx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'xx| to do all of the
          |oo'ooooooooooooooooooooooooooooooooooooooooooo'oo| hashing.
             |   ->                                 <-   |
           index                                     reflection


          |xxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| finally, the whole
          |ooooooooooo'ooooooooooooooooooooooooooooooooooooo| cache is quickly
          |xxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| hashed `cpu` + 2
          |ooooooooooo'ooooooooooooooooooooooooooooooooooooo| number of times.
          |Fxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| after each pass an
          |foooooooooo'ooooooooooooooooooooooooooooooooooooo| 84-byte digest is
          |fxxxxxxxxxx'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| inserted into the
          |foooooooooo'ooooooooooooooooooooooooooooooooooooo| cache, ruling out
                      |   ->                                  hashing state cycles.
                      | hash cpu + 2 # of times               Then a `tag_size`-
                      v                                       byte tag is output.
                  H(cache)

          tag = H.digest(tag_size)


    """




_`X25519 & Ed25519` ............................... `Table Of Contents`_
------------------------------------------------------------------------

Asymmetric curve 25519 tools are available from these high-level interfaces over the ``cryptography`` package.


_`X25519` ......................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Elliptic Curve25519 Diffie-Hellman key exchange protocols.


Basic Elliptic Curve Diffie-Hellman
***********************************

.. code-block:: python

    from aiootp import X25519, DomainKDF, GUID, Domains


    guid = GUID().new()

    my_ecdhe_key = X25519().generate()

    yield guid, my_ecdhe_key.public_bytes  # send this to Bob

    raw_shared_secret = my_ecdhe_key.exchange(bobs_public_key)

    shared_kdf = DomainKDF(  # Use this to create secret shared keys

        Domains.ECDHE,

        guid,

        bobs_public_key,

        my_ecdhe_key.public_bytes,

        key=raw_shared_secret,

    )


Triple ECDH Key Exchange:
*************************

.. code-block:: bash

    '''
     _____________________________________
    |                                     |
    |          Protocol Diagram:          |
    |_____________________________________|

            -----------------          |         -----------------
            |  Client-side  |          |         |  Server-side  |
            -----------------          |         -----------------
                                       |
    key = X25519().generate()          |         X25519().generate() = key
                                       |
    client = key.dh3_client()          |           key.public_bytes = id_s
                                       |
    id_c, eph_c = client.send(id_s) ------>
                                       |
                                       |         key.dh3_server() = server
                                       |
                                       | server.receive(id_c, eph_c) = kdf
                                       |
                                    <------          server.send() = eph_s
                                       |
    kdf = client.receive(eph_s)        |
                                       |

    '''


Double ECDH Key Exchange:
*************************

.. code-block:: bash

    '''
     _____________________________________
    |                                     |
    |          Protocol Diagram:          |
    |_____________________________________|

            -----------------          |         -----------------
            |  Client-side  |          |         |  Server-side  |
            -----------------          |         -----------------
                                       |
                                       |         X25519().generate() = key
                                       |
    client = X25519.dh2_client()       |           key.public_bytes = id_s
                                       |
    eph_c = client.send(id_s)       ------>
                                       |
                                       |         key.dh2_server() = server
                                       |
                                       |       server.receive(eph_c) = kdf
                                       |
                                    <------          server.send() = eph_s
                                       |
    kdf = client.receive(eph_s)        |
                                       |

    '''




_`Ed25519` ........................................ `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Edwards curve 25519 signing & verification.

.. code-block:: python

    from aiootp import Ed25519


    # In a land, long ago ->

    alices_key = Ed25519().generate()

    internet.send(alices_key.public_bytes)


    # Alice wants to sign a document so that Bob can prove she wrote it.

    # So, Alice sends the public key bytes of the key she wants to

    # associate with her identity, the document & the signature ->

    document = b"DesignDocument.cad"

    signed_document = alices_key.sign(document)

    message = {
        "document": document,
        "signature": signed_document,
        "public_key": alices_key.public_bytes,
    }

    internet.send(message)


    # In a land far away ->

    alices_message = internet.receive()

    # Bob sees the message from Alice! Bob already knows Alice's public

    # key & she has reason believe it is genuinely Alice's. So, she'll

    # import Alice's known public key to verify the signed document ->

    assert alices_message["public_key"] == alices_public_key

    alice_verifier = Ed25519().import_public_key(alices_public_key)

    alice_verifier.verify(
        alices_message["signature"], alices_message["document"]
    )

    internet.send(b"Beautiful work, Alice! Thanks ^u^")

The verification didn't throw an exception! So, Bob knows the file was signed by Alice.



