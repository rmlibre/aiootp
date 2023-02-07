.. image:: https://raw.githubusercontent.com/rmlibre/aiootp/main/logo.png
    :target: https://raw.githubusercontent.com/rmlibre/aiootp/main/logo.png
    :alt: aiootp python package logo




aiootp - Asynchronous pseudo one-time pad based crypto and anonymity library.
=============================================================================

``aiootp`` is an asynchronous library providing access to cryptographic 
primatives and abstractions, transparently encrypted / decrypted file 
I/O and databases, as well as powerful, pythonic utilities that 
simplify data processing & cryptographic procedures in python code. 
This library's online, salt reuse / misuse resistant, tweakable AEAD cipher, called 
``Chunky2048``, is an implementation of the **pseudo one-time pad**. The 
aim is to create a simple, standard, efficient implementation that's 
indistinguishable from the unbreakable one-time pad cipher; to give 
users and applications access to user-friendly cryptographic tools; and, 
to increase the overall security, privacy, and anonymity on the web, and 
in the digital world. Users will find ``aiootp`` to be easy to write, 
easy to read, and fun. 




Important Disclaimer
--------------------

``aiootp`` is experimental software that works with Python 3.6+. 
It's a work in progress. The programming API could change with 
future updates, and it isn't bug free. ``aiootp`` provides powerful 
security tools and misc utilities that're designed to be 
developer-friendly and privacy preserving. 
As a security tool, ``aiootp`` needs to be tested and reviewed 
extensively by the programming and cryptography communities to 
ensure its implementations are sound. We provide no guarantees. 
This software hasn't yet been audited by third-party security 
professionals.




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

  $ sudo apt-get install python3-setuptools python3-pip

  $ pip3 install --user --upgrade pip typing aiootp




Run Tests
---------

.. code-block:: shell

  $ cd ~/aiootp/tests

  $ coverage run --source aiootp -m pytest -vv test_aiootp.py




_`Table Of Contents`
--------------------

- `Transparently Encrypted Databases`_

  a) `Ideal Initialization`_
  
  b) `User Profiles`_
  
  c) `Tags`_
  
  d) `Metatags`_
  
  e) `Basic Management`_
  
  f) `Mirrors`_
  
  g) `Public Cryptographic Functions`_

     I. `Encrypt / Decrypt`_
     
     II. `HMACs`_
     

- `Chunky2048 Cipher`_
  
  a) `High-level Functions`_
  
  b) `High-level Generators`_
  

- `Passcrypt`_

  a) `Hashing & Verifying Passphrases`_

  b) `Passcrypt Algorithm Overview`_


- `X25519 & Ed25519`_
  
  a) `X25519`_
  
  b) `Ed25519`_
  

- `Comprende`_
  
  a) `Synchronous Generators`_
  
  b) `Asynchronous Generators`_
  

- `Module Overview`_
  

- `FAQ`_
  

- `Changelog`_
  

- `Known Issues`_




_`Transparently Encrypted Databases` .............. `Table Of Contents`_
------------------------------------------------------------------------

The package's ``AsyncDatabase`` & ``Database`` classes are very powerful data persistence utilities. They automatically handle encryption & decryption of user data & metadata, providing a pythonic interface for storing & retrieving any bytes or JSON serializable objects. They're designed to seamlessly bring encrypted bytes at rest to users as dynamic objects in use.


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

    # Automatically convert any available user credentials into 

    # cryptographic tokens which help to safely open databases ->

    db = await AsyncDatabase.agenerate_profile(
    
        b"server-url.com",     # Here an unlimited number of bytes-type
                               # arguments can be passed as additional
        b"address@email.net",  # optional credentials.
        
        username=b"username",
        
        passphrase=b"passphrase",
        
        salt=b"optional salt keyword argument",
                  # Optional passcrypt configuration:
        mb=256,   # The memory cost in Mibibytes (MiB)

        cpu=2,    # The computational complexity & number of iterations

        cores=8,  # How many parallel processes passcrypt will utilize
        
    )


_`Tags` ........................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Data within databases are primarily organized by Tags. Tags are simply string labels, and the data stored under them can be any bytes or JSON serializable objects.

.. code-block:: python

    async with db:
    
        # Using bracketed assignment adds tags to the cache
    
        db["tag"] = {"data": "can be any JSON serializable object"}
        
        db["hobby"] = b"fash smasher"
        
        db["bitcoin"] = "0bb6eee10d2f8f45f8a"
        
        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}
        
        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]
        
        # Changes in the cache are saved to disk when the context closes.
        
        
    # View an instance's tags ->

    db.tags
    >>> {'tag', 'hobby', 'bitcoin', 'lawyer', 'safehouses'}


    # View the filenames that locate the data for each tag ->
    
    db.filenames
    >>> {'0z0l10btu_yd-n4quc8tsj9baqu8xmrxz87ix',
     '197ulmqmxg15lebm26zaahpqnabwr8sprojuh',
     '248piaop3j9tmcvqach60qk146mt5xu6kjc-u',
     '2enwc3crove2cnrx7ks963d8_se25k6cdn6q9',
     '5dm-60yspq8yhah4ywxcp52kztq_9toj0owm2'}


    # There are various ways of working with tags ->

    await db.aset_tag("new_tag", ["data", "goes", "here"])  # stored only in cache

    await db.aquery_tag("new_tag")  # reads from disk if not in the cache
    >>> ['data', 'goes', 'here']

    tag_path = db.path / await db.afilename("new_tag")

    "new_tag" in db
    >>> True

    tag_path.is_file()  # the tag is saved in the cache, not to disk yet
    >>> False

    await db.asave_tag("new_tag")
    
    tag_path.is_file()  # now it's saved to disk
    >>> True
    
    
    # This removes the tag from cache, & any of its unsaved changes ->

    await db.arollback_tag("new_tag")


    # Or, the user can take the tag out of the database & the filesystem ->

    await db.apop_tag("new_tag")
    >>> ['data', 'goes', 'here']

    "new_tag" in db
    >>> False

    tag_path.is_file()
    >>> False

Access to data is open to the user, so care must be taken not to let external API calls touch the database without accounting for how that can go wrong.


_`Metatags` ....................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Metatags are used to organize data by string names & domain separate cryptographic material. They are fully-fledged databases all on their own, with their own distinct key material too. They're accessible from the parent through an attribute that's added to the parent instance with the same name as the metatag. When the parent is saved, or deleted, then their descendants are also.

.. code-block:: python

    # Create a metatag database ->

    molly = await db.ametatag("molly")


    # They can contain their own sets of tags (and metatags) ->
    
    molly["hobbies"] = ["skipping", "punching"]
    
    molly["hobbies"].append("reading")


    # The returned metatag & the reference in the parent are the same ->

    assert molly["hobbies"] is db.molly["hobbies"]
    
    assert isinstance(molly, AsyncDatabase)
    

    # All of an instance's metatags are viewable ->

    db.metatags
    >>> {'molly'}
    

    # Delete a metatag from an instance ->

    await db.adelete_metatag("molly")
    
    db.metatags
    >>> set()
    
    assert not hasattr(db, "molly")


_`Basic Management` ............................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There's a few settings & public methods on databases for users to manage their instances & data. This includes general utilities for saving & deleting databases to & from the filesystem, as well as fine-grained controls for how data is handled. 

.. code-block:: python

    # The path attribute is set within the instance's __init__

    # using a keyword-only argument. It's the directory where the

    # instance will store all of its files.

    db.path
    >>> PosixPath('site-packages/aiootp/aiootp/databases')
    
    
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
    
        await db.ametatag("exercise_routines") 

        db.exercise_routines["gardening"] = {"days": ["moday", "wednesday"]}
        
        db.exercise_routines["swimming"] = {"days": ["thursday", "saturday"]}
        

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
    
        assert type(uncached_db.exercise_routines) == AsyncDatabase
        
        uncached_db.exercise_routines["gardening"]
        >>> None
        
        await uncached_db.exercise_routines.aquery_tag("gardening", cache=True)
        >>> {"days": ["moday", "wednesday"]}
        
        uncached_db.exercise_routines["gardening"]
        >>> {"days": ["moday", "wednesday"]}
        
        
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
    
    
_`Mirrors` ........................................ `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
Database mirrors allow users to make copies of all files within a database under new encryption keys. This is useful if users simply want to make backups, or if they'd like to update / change their database keys. 
    
.. code-block:: python
    
    # A unique login key / credentials are needed to create a new 
    
    # database ->
    
    new_key = await acsprng()
    
    new_db = await AsyncDatabase(new_key)
    
    
    # Mirroring an existing database is done like this ->
    
    await new_db.amirror_database(db)
    
    assert (
    
        await new_db.aquery_tag("favorite_foods") 
        
        is await db.aquery_tag("favorite_foods")
        
    )
    
    
    # If the user is just updating their database keys, then the old
    
    # database should be deleted ->
    
    await db.adelete_database()
    
    
    # Now, the new database can be saved to disk & given an appropriate 
    
    # name ->
    
    async with new_db as db:
    
        pass
    

_`Public Cryptographic Functions` ................. `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Although databases handle encryption & decryption automatically, users may want to utilize their databases' keys to do custom cryptographic procedures manually. There are a few public functions available to users if they should want such functionality.


_`Encrypt / Decrypt` .............................. `Table Of Contents`_
************************************************************************

.. code-block:: python

    # Either JSON serializable or bytes-type data can be encrypted ->

    json_plaintext = {"some": "JSON data can go here..."}
    
    bytes_plaintext = b"some bytes plaintext goes here..."
    
    token_plaintext = b"some token data goes here..."

    json_ciphertext = await db.ajson_encrypt(json_plaintext)

    bytes_ciphertext = await db.abytes_encrypt(bytes_plaintext)
    
    token_ciphertext = await db.amake_token(token_plaintext)


    # Those values can just as easily be decrypted ->

    assert json_plaintext == await db.ajson_decrypt(json_ciphertext)

    assert bytes_plaintext == await db.abytes_decrypt(bytes_ciphertext)
    
    assert token_plaintext == await db.aread_token(token_ciphertext)


    # Filenames may be added to classify ciphertexts. They also alter the 

    # key material used during encryption in such a way, that without the

    # correct filename, the data cannot be decrypted ->

    filename = "grocery-list"

    groceries = ["carrots", "taytoes", "rice", "beans"]

    ciphertext = await db.ajson_encrypt(groceries, filename=filename)

    assert groceries == await db.ajson_decrypt(ciphertext, filename=filename)
    
    await db.ajson_decrypt(ciphertext, filename="wrong filename")
    >>> "InvalidSHMAC: Invalid StreamHMAC hash for the given ciphertext."



    # Time-based expiration of ciphertexts is also available for all 

    # encrypted data this package produces ->

    from aiootp.asynchs import asleep


    await asleep(6)

    await db.ajson_decrypt(json_ciphertext, ttl=1)
    >>> "TimestampExpired: Timestamp expired by <5> seconds."

    await db.abytes_decrypt(bytes_ciphertext, ttl=1)
    >>> "TimestampExpired: Timestamp expired by <5> seconds."

    await db.aread_token(token_ciphertext, ttl=1)
    >>> "TimestampExpired: Timestamp expired by <5> seconds."


    # The number of seconds that are exceeded may be helpful to know. In

    # which case, this is how to retrieve that integer value ->

    try: 
    
        await db.abytes_decrypt(bytes_ciphertext, ttl=1)

    except db.TimestampExpired as error:

        assert error.expired_by == 5


_`HMACs` .......................................... `Table Of Contents`_
************************************************************************

Besides encryption & decryption, databases can also be used to manually verify the authenticity of bytes-type data with HMACs.

.. code-block:: python

    # Creating an HMAC of some data with a database is done this way ->

    data = b"validate this data!"

    hmac = await db.amake_hmac(data)

    await db.atest_hmac(hmac, data)  # Runs without incident


    # Data that is not the same will be caught ->

    altered_data = b"valiZate this data!"

    await db.atest_hmac(hmac, altered_data)
    >>> "InvalidHMAC: Invalid HMAC hash for the given data."
    

    # Any number of bytes-type arguments can be run thorugh the function, 

    # the collection of items is canonically encoded automagically ->

    arbitrary_data = (b"uid_\x0f\x12", b"session_id_\xa1")

    hmac = await db.amake_hmac(*arbitrary_data)
    
    await db.atest_hmac(hmac, *arbitrary_data)  # Runs without incident


    # Additional qualifying information can be specified with the ``aad``

    # keyword argument ->

    from time import time

    timestamp = int(time()).to_bytes(8, "big")

    hmac = await db.amake_hmac(*arbitrary_data, aad=timestamp)
    
    await db.atest_hmac(hmac, *arbitrary_data)
    >>> "InvalidHMAC: Invalid HMAC hash for the given data."

    await db.atest_hmac(hmac, *arbitrary_data, aad=timestamp) # Runs fine


    # This is most helpful for domain separation of the HMAC outputs.

    # Each distinct setting & purpose of the HMAC should be specified

    # & NEVER MIXED ->

    uuid = await db.amake_hmac(user_name, aad=b"uuid")

    hmac = await db.amake_hmac(user_data, aad=b"data-authentication")
    
    
    #




_`Chunky2048 Cipher` .............................. `Table Of Contents`_
------------------------------------------------------------------------

The ``Chunky2048`` cipher is the built from generators & SHA3-based key-derivation functions. It's designed to be easy to use, difficult to misuse & future-proof with large security margins. 


_`High-level Functions` .......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These premade recipes allow for the easiest usage of the cipher.

.. code-block:: python

    import aiootp
    
    
    cipher = aiootp.Chunky2048(key)
    
    
    # Symmetric encryption of JSON data ->
    
    json_data = {"account": 33817, "names": ["queen b"], "id": None}
    
    encrypted_json_data = cipher.json_encrypt(json_data, aad=b"demo")
    
    decrypted_json_data = cipher.json_decrypt(
    
        encrypted_json_data, aad=b"demo", ttl=120
        
    )
    
    assert decrypted_json_data == json_data
    
    
    # Symmetric encryption of binary data ->
    
    binary_data = b"some plaintext data..."
    
    encrypted_binary_data = cipher.bytes_encrypt(binary_data, aad=b"demo")
    
    decrypted_binary_data = cipher.bytes_decrypt(
    
        encrypted_binary_data, aad=b"demo", ttl=30
        
    )
    
    assert decrypted_binary_data == binary_data
    
    
    # encrypted URL-safe Base64 encoded tokens ->
    
    token_data = b"some plaintext token data..."
    
    encrypted_token_data = cipher.make_token(token_data, aad=b"demo")
    
    decrypted_token_data = cipher.read_token(
    
        encrypted_token_data, aad=b"demo", ttl=3600
        
    )
    
    assert decrypted_token_data == token_data


_`High-level Generators` .......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

With these generators, the online nature of the Chunky2048 cipher can be utilized. This means that any arbitrary amount of data can be processed in streams of controllable, buffered chunks. These streaming interfaces automatically handle message padding & depadding, ciphertext validation & detection of out-of-order message blocks.

Encryption:

.. code-block:: python
    
    from aiootp import AsyncCipherStream
    
    
    # Let's imagine we are serving some data over a network ->

    receiver = SomeRemoteConnection(session).connect()


    # This will manage encrypting a stream of data ->

    stream = await AsyncCipherStream(key, aad=session.transcript)


    # We'll have to send the salt & iv in some way ->

    receiver.transmit(salt=stream.salt, iv=stream.iv)


    # Now we can buffer the plaintext we are going to encrypt ->

    for plaintext in receiver.upload.buffer(4 * stream.PACKETSIZE):

        await stream.abuffer(plaintext)


        # The stream will now produce encrypted blocks of ciphertext

        # as well as the block ID which authenticates each block ->

        async for block_id, ciphertext in stream:

            # The receiver needs both the block ID & ciphertext ->

            receiver.send_packet(block_id + ciphertext)


    # Once done with buffering-in the plaintext, the ``afinalize`` 

    # method is called so the remaining encrypted data will be 

    # flushed out of the buffer to the user ->

    async for block_id, ciphertext in stream.afinalize():

        receiver.send_packet(block_id + ciphertext)


    # Here we can give an optional check of further authenticity, 

    # also cryptographically asserts the stream is finished ->

    receiver.transmit(shmac=await stream.shmac.afinalize())


Decryption / Authentication:

.. code-block:: python
    
    from aiootp import AsyncDecipherStream

    
    # Here let's imagine we'll be downloading some data ->

    source = SomeRemoteConnection(session).connect()


    # The key, salt, aad & iv must be the same for both parties ->

    stream = await AsyncDecipherStream(

        key, salt=source.salt, aad=session.transcript, iv=source.iv

    )

    # The downloaded ciphertext will now be buffered & the stream

    # object will produce the plaintext ->

    for ciphertext in source.download.buffer(4 * stream.PACKETSIZE):

        # Here stream.shmac.InvalidBlockID is raised if an invalid or

        # out-of-order block is detected within the last 4 packets ->

        await stream.abuffer(ciphertext) 


        # If authentication succeeds, the plaintext is produced ->

        async for plaintext in stream:

            yield plaintext


    # After all the ciphertext is downloaded, ``afinalize`` is called

    # to finish processing the stream & flush out the plaintext ->

    async for plaintext in stream.afinalize():

        yield plaintext


    # An optional check for further authenticity which also

    # cryptographically asserts the stream is finished ->

    await stream.shmac.afinalize()

    await stream.shmac.atest_shmac(source.shmac)


    #




_`Passcrypt` .............................. `Table Of Contents`_
------------------------------------------------------------------------

The ``Passcrypt`` algorithm is a data independent memory & computationally hard password-based key derivation function. It's built from a single primitive, the SHAKE-128 extendable output function from the SHA-3 family. Its resource costs are measured by three parameters: ``mb``, which represents an integer number of Mibibytes (MiB); ``cpu``, which is a linear integer measure of computational complexity & the number of iterations of the algorithm over the memory cache; and ``cores``, which is an integer which directly assigns the number of separate processes that will be pooled to complete the algorithm. The number of bytes of the output tag are decided by the integer ``tag_size`` parameter. And, the number of bytes of the automatically generated ``salt`` are decided by the integer ``salt_size`` parameter.


_`Hashing & Verifying Passphrases` .......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


By far, the dominating measure of difficulty for ``Passcrypt`` is determined by the ``mb`` Mibibyte memory cost. It's recommended that increases to desired difficulty are first translated into higher ``mb`` values, where resource limitations of the machines executing the algorithm permit. If more difficulty is desired than can be obtained by increasing ``mb``, then increases to the ``cpu`` parameter should be used. The higher this parameter is the less likely an adversary is to benefit from expending less than the intended memory cost, & increases the execution time & complexity of the algorithm. The final option that should be considered, if still more difficulty is desired, is to lower the ``cores`` parallelization parameter, which will just cause each execution to take longer to complete.

.. code-block:: python
    
    from aiootp import Passcrypt, hash_bytes


    # The class accepts an optional (but recommended) static "pepper"

    # which is applied as additional randomness to all hashes computed

    # by the class. It's a secret random bytes value of any size that is

    # expected to be stored somewhere inaccessible by the database which

    # contains the hashed passphrases ->

    with open(SECRET_PEPPER_PATH, "rb") as pepper_file:

        Passcrypt.PEPPER = pepper_file.read()


    # when preparing to hash passphrases, it's a good idea to use any &

    # all of the static data / credentials available which are specific 

    # to the context of the registration ->

    APPLICATION = b"my-application-name"

    PRODUCT = b"the-product-being-accessed-by-this-registration"

    STATIC_CONTEXT = [APPLICATION, PRODUCT, PUBLIC_CERTIFICATE]


    # If the same difficulty settings are going to be used for every 

    # hash, then a ``Passcrypt`` instance can be initialized to

    # automatically pass those static settings ->

    pcrypt = Passcrypt(mb=1024, cpu=2, cores=8)  # 1 GiB, 8 cores


    # Now that the static credentials / settings are ready to go, we

    # can start hashing any user information that arrives ->

    username = form["username"].encode()

    passphrase = form["passphrase"].encode()

    email_address = form["email_address"].encode()


    # The ``hash_bytes`` function can then be used to automatically

    # encode then hash the multi-input data so as to prevent the chance

    # of canonicalization (&/or length extension) attacks ->

    aad = hash_bytes(*STATIC_CONTEXT, username, email_address)

    hashed_passphrase = pcrypt.hash_passphrase(passphrase, aad=aad)

    assert type(hashed_passphrase) is bytes

    assert len(hashed_passphrase) == 38


    # Later, a hashed passphrase can be used to authenticate a user ->

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

.. code-block:: python

    #
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

    #




_`X25519 & Ed25519` ............................... `Table Of Contents`_
------------------------------------------------------------------------

Asymmetric curve 25519 tools are available from these high-level interfaces over the ``cryptography`` package.


_`X25519` ......................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Elliptic curve 25519 diffie-hellman exchange protocols.

.. code-block:: python

    from aiootp import X25519, DomainKDF, GUID, Domains


    # Basic Elliptic Curve Diffie-Hellman ->

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
    
    
    # Triple ECDH Key Exchange client initialization ->
    
    with ecdhe_key.dh3_client() as exchange:
    
        response = internet.post(exchange())
        
        exchange(response)
        
    clients_kdf = exchange.result()


    # Triple ECDH Key Exchange for a receiving peer ->
    
    identity_key, ephemeral_key = client_public_keys = internet.receive()
    
    server = ecdhe_key.dh3_server(identity_key, ephemeral_key)
    
    with server as exchange:
    
        internet.post(exchange.exhaust())
        
    servers_kdf = exchange.result()
    

    # Success! Now both the client & server peers share an identical
    
    # ``DomainKDF`` hashing object to create shared keys ->

    assert (

        clients_kdf.sha3_512(context=b"test") 

        == servers_kdf.sha3_512(context=b"test")

    )
    
    
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
    
    
    
    
_`Comprende` ...................................... `Table Of Contents`_
------------------------------------------------------------------------

This magic with generators is made simple with the ``comprehension`` decorator. It wraps them in ``Comprende`` objects with access to myriad data processing pipeline utilities right out of the box.


_`Synchronous Generators` ......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    from aiootp.gentools import comprehension
    
    
    @comprehension()
    
    def gen(x: int, y: int):
    
        z = yield x + y
        
        return x * y * z
    
    
    # Drive the generator forward with a context manager ->
    
    with gen(x=1, y=2) as example:
    
        z = 5
        
        
        # Calling the object will send ``None`` into the coroutine by default ->
        
        sum_of_x_y = example()
        
        assert sum_of_x_y == 3


        # Passing ``z`` will send it into the coroutine, cause it to reach the 
        
        # return statement & exit the context manager ->
        
        example(z)
    
    
    # The result returned from the generator is now available ->
    
    product_of_x_y_z = example.result()
    
    assert product_of_x_y_z == 10
    
    
    # Here's another example ->
    
    @comprehension()
    
    def one_byte_numbers():
    
        for number in range(256):
        
            yield number
    
    
    # Chained ``Comprende`` generators are excellent inline data processors ->
    
    base64_data = one_byte_numbers().int_to_bytes(1).to_base64().list()
    
    # This converted each number to bytes then base64 encoded them into a list.


    # We can wrap other iterables to add functionality to them ->

    @comprehension()
    
    def unpack(iterable):
    
        for item in iterable:
    
            yield item


    # This example just hashes each output then yields them

    for digest in unpack(base64_data).sha3_256():
        
        print(digest)


_`Asynchronous Generators` ........................ `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Async ``Comprende`` coroutines have almost exactly the same interface as synchronous ones.

.. code-block:: python

    from aiootp.asynchs import asleep

    from aiootp.gentools import Comprende, comprehension


    @comprehension()
    
    async def gen(x: int, y: int):
    
        # Because having a return statement in an async generator is a
        
        # SyntaxError, the return value is expected to be passed into
        
        # Comprende.ReturnValue, and then raised to propagate upstream. 

        # It's then available from the instance's ``aresult`` method ->
        
        z = yield x + y
        
        raise Comprende.ReturnValue(x * y * z)
        
        
    # Drive the generator forward.
    
    async with gen(x=1, y=2) as example:
    
        z = 5
        
        
        # Awaiting the ``__call__`` method will send ``None`` into the

        # coroutine by default ->
        
        sum_of_x_y = await example()
        
        assert sum_of_x_y == 3


        # Passing ``z`` will send it into the coroutine, cause it to reach the
        
        # raise statement which will exit the context manager gracefully ->
        
        await example(z)
    
    
    # The result returned from the generator is now available ->
    
    product_of_x_y_z = await example.aresult()
    
    assert product_of_x_y_z == 10
    
    
    # Let's see some other ways async generators mirror synchronous ones ->
    
    @comprehension()
    
    async def one_byte_numbers():

        # It's probably a good idea to pass control to the event loop at

        # least once or twice, even if async sleeping after each iteration

        # may be excessive when no real work is being demanded by range(256).

        # This consideration is more or less significant depending on the 

        # expectations placed on this generator by the calling code.

        await asleep()
    
        for number in range(256):
        
            yield number

        await asleep()
    
    
    # This is asynchronous data processing ->
    
    base64_data = await one_byte_numbers().aint_to_bytes(1).ato_base64().alist()
    
    # This converted each number to bytes then base64 encoded them into a list.


    # We can wrap other iterables to add asynchronous functionality to them ->

    @comprehension()
    
    async def unpack(iterable):
    
        for item in iterable:
    
            yield item


    # Want only the first twenty results? ->

    async for digest in unpack(base64_data).asha3_256()[:20]:
    
        # Then you can slice the generator.
        
        print(digest)
        
        
    # Users can slice generators to receive more complex output rules, like:
    
    # Getting every second result starting from the 4th result to the 50th ->
    
    async for result in unpack(base64_data)[3:50:2]:
    
        print(result)


    # Although, negative slice numbers are not supported.

``Comprende`` generators have loads of tooling for users to explore. Play around with it and take a look at the other chainable generator methods in ``aiootp.Comprende.lazy_generators``.




_`Module Overview` ................................ `Table Of Contents`_
------------------------------------------------------------------------

Here's a quick overview of this package's modules:


.. code-block:: python

    import aiootp
    
    
    # Commonly used constants, datasets & functionality across all modules ->
    
    aiootp.commons
    
    
    # The basic utilities & abstractions of the package's architecture ->
    
    aiootp.generics
    
    
    # A collection of the package's generator utilities ->
    
    aiootp.gentools
    
    
    # This module is responsible for providing entropy to the package ->
    
    aiootp.randoms
    
    
    # The high & low level abstractions used to implement the Chunky2048 cipher ->
    
    aiootp.ciphers
    
    
    # The higher-level abstractions used to create / manage key material ->
    
    aiootp.keygens
    
    
    # Common system paths & the ``pathlib.Path`` utility ->
    
    aiootp.paths
    
    
    # Global async / concurrency functionalities & abstractions ->
    
    aiootp.asynchs
    
    
    #




