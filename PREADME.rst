.. image:: https://raw.githubusercontent.com/rmlibre/aiootp/main/logo.png
    :target: https://raw.githubusercontent.com/rmlibre/aiootp/main/logo.png
    :alt: aiootp python package logo




aiootp - Asynchronous pseudo one-time pad based crypto and anonymity library.
=============================================================================

``aiootp`` is an asynchronous library providing access to cryptographic 
primatives and abstractions, transparently encrypted / decrypted file 
I/O and databases, as well as powerful, pythonic utilities that 
simplify data processing & cryptographic procedures in python code. 
This library's online MRAE / AEAD cipher, called ``Chunky2048``, is an 
implementation of the **pseudo one-time pad**. The aim is to create a simple, 
standard, efficient implementation that's indistinguishable from the 
unbreakable one-time pad cipher; to give users and applications access to 
user-friendly cryptographic tools; and, to increase the overall security, 
privacy, and anonymity on the web, and in the digital world. Users will 
find ``aiootp`` to be easy to write, easy to read, and fun. 




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

.. image:: https://github.com/rmlibre/aiootp/actions/workflows/linux-python-app.yml/badge.svg
    :target: https://github.com/rmlibre/aiootp/actions/workflows/linux-python-app.yml/badge.svg
    :alt: linux-build-status

.. image:: https://img.shields.io/badge/License-AGPL%20v3-red.svg
    :target: https://img.shields.io/badge/License-AGPL%20v3-red.svg
    :alt: license

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://img.shields.io/badge/code%20style-black-000000.svg
    :alt: code-style




Quick Install
-------------

.. code-block:: shell

  $ sudo apt-get install python3-setuptools python3-cryptography

  $ pip3 install --user --upgrade aiootp




Run Tests
---------

.. code-block:: shell

  $ cd ~/aiootp/tests

  $ coverage run --source aiootp -m pytest test_aiootp.py -vv




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
  
  a) `High-level Interfaces`_
  
  b) `Low-level Generators`_
  
  c) `Nuts & Bolts`_
  

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

    from aiootp import AsyncKeys, AsyncDatabase
    
    
    key = await AsyncKeys.acsprng()

    db = await AsyncDatabase(key)
    

_`User Profiles` .................................. `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

With User Profiles, passphrases may be used instead to open a database. Often, passwords & passphrases contain very little entropy. So, they aren't recommended for that reason. However, profiles provide a succinct way to use passphrases more safely. They do this by deriving strong keys from low entropy user input, the memory/cpu hard passcrypt algorithm, & a secret salt which is automatically generated & stored on the user's filesystem.

.. code-block:: python

    # Convert any available user credentials into cryptographic tokens ->

    tokens = await AsyncDatabase.agenerate_profile_tokens(
    
        "server-url.com",     # An unlimited number of arguments can be passed
        
        "address@email.net",  # here as additional, optional credentials.
        
        username="username",
        
        passphrase="passphrase",
        
        salt="optional salt keyword argument",
        
    )


    # Finally, use those special tokens to open a database instance ->

    db = await AsyncDatabase.agenerate_profile(tokens)


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


    # View the filenames of an instance's tags ->
    
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

    tag_path = db.directory / await db.afilename("new_tag")

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

Access to data is open to the user, so care must be taken not to let external api calls touch the database without accounting for how that can go wrong.


_`Metatags` ....................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Metatags are used to organize & create children of parent databases. They are fully-fledged databases all on their own, with their own distinct key material too. They're accessible from the parent through an attribute that's added to the parent instance with the same name as the metatag. When the parent is saved, or deleted, then their children are also.

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

    # The directory attribute is set within the instance's __init__

    # using a keyword-only argument. It's the directory where the

    # instance will store all of its files.

    db.directory
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
    
    new_key = await AsyncKeys.acsprng()
    
    new_db = await AsyncDatabase(new_key)
    
    
    # Mirroring an existing database is done like this ->
    
    await new_db.amirror_database(db)
    
    assert (
    
        await new_db.aquery_tag("favorite_foods") 
        
        == await db.aquery_tag("favorite_foods")
        
    )

    assert (
    
        await new_db.aquery_tag("favorite_foods") 
        
        is not await db.aquery_tag("favorite_foods")
        
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
    >>> "ValueError: Invalid HMAC of data stream!"


    # Time-based expiration of ciphertexts is also available for all 

    # encrypted data this package produces ->

    from aiootp.asynchs import asleep


    await asleep(6)

    await db.ajson_decrypt(json_ciphertext, ttl=1)
    >>> "TimeoutError: Timestamp expired by <5> seconds."

    await db.abytes_decrypt(bytes_ciphertext, ttl=1)
    >>> "TimeoutError: Timestamp expired by <5> seconds."

    await db.aread_token(token_ciphertext, ttl=1)
    >>> "TimeoutError: Timestamp expired by <5> seconds."


    # The number of seconds that are exceeded may be helpful to know. In

    # which case, this is how to retrieve that integer value ->

    try: 
    
        await db.abytes_decrypt(bytes_ciphertext, ttl=2)

    except TimeoutError as error:

        seconds_expired = error.seconds_expired


_`HMACs` .......................................... `Table Of Contents`_
************************************************************************

Besides encryption & decryption, databases can also be used to manually verify the authenticity of data with HMACs.

.. code-block:: python

    # Creating an HMAC of some data with a database is done this way ->

    data = b"validate this data!"

    hmac = await db.amake_hmac(data)

    await db.atest_hmac(data, hmac)
    >>> True


    # Data that is not the same, or is altered, will be caught ->

    altered_data = b"valiZate this data!"

    await db.atest_hmac(altered_data, hmac)
    >>> "ValueError: HMAC of the data stream isn't valid."
    

    # Any type of data can be run thorugh the function, it's the repr

    # of the data which is evaluated ->

    arbitrary_data = {"id": 1234, "payload": "message"}

    hmac = await db.amake_hmac(arbitrary_data)
    
    await db.atest_hmac(arbitrary_data, hmac)
    >>> True


    # Beware: Datatypes where order of values is not preserved may fail 

    # to validate even if they are functionally equivalent -> 

    order_swapped_data = {"payload": "message", "id": 1234}

    assert order_swapped_data == arbitrary_data
    
    await db.atest_hmac(order_swapped_data, hmac) 
    >>> "ValueError: HMAC of the data stream isn't valid."
    
    
    #




_`Chunky2048 Cipher` .............................. `Table Of Contents`_
------------------------------------------------------------------------

The ``Chunky2048`` cipher is the built from generators & SHA3-based key-derivation functions. It's designed to be easy to use, difficult to misuse & future-proof with large security margins. 


_`High-level Interfaces` .......................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
    
    
    # URL-safe Base64 encoded encrypted tokens ->
    
    token_data = b"some plaintext token data..."
    
    encrypted_token_data = cipher.make_token(token_data, aad=b"demo")
    
    decrypted_token_data = cipher.read_token(
    
        encrypted_token_data, aad=b"demo", ttl=3600
        
    )
    
    assert decrypted_token_data == token_data


_`Low-level Generators` ........................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The cipher can also be used as an online cipher, handling blocks of data 256-bytes at a time. Using these generators is more difficult, giving more fine-grained control to the user.

.. code-block:: python
    
    from aiootp import gentools
    
    from aiootp import csprng, Padding, KeyAADBundle, StreamHMAC
    
    
    key = csprng()  # <---Must be known by the decrypting party
    
    aad = b"any associated data"  # <---Must be known by the decrypting party

    key_bundle = KeyAADBundle(key, aad=aad).sync_mode()
    
    plaintext = b"example plaintext..."
    
    
    # Yields padded plaintext in chunks of 256 bytes ->
    
    stream = gentools.plaintext_stream(plaintext, key_bundle)
    
    
    # This is used to authenticate the ciphertext & associated data ->
    
    shmac = StreamHMAC(key_bundle).for_encryption()
    
    
    # Iterates over the plaintext ``stream`` generator, in this case, 
    
    # returning the enciphered data in one ``join`` call ->
    
    ciphertext = stream.bytes_encipher(key_bundle, shmac).join(b"")
    
    assert type(ciphertext) == bytes
        
    hmac = shmac.finalize()  # <---Must be shared with the decrypting party
        
    siv = key_bundle.siv  # <---Must be shared with the decrypting party
    
    salt = key_bundle.salt  # <---Must be shared with the decrypting party
        
        
    # When receiving ciphertext, the user must first validate the hmac of 
    
    # the ciphertext before trusting the plaintext that's revealed! ->
    
    key_bundle = KeyAADBundle(key, salt=salt, aad=aad, siv=siv).sync_mode()
    
    shmac = StreamHMAC(key_bundle).for_decryption()
    
    
    # Yields the ciphertext 256-bytes at a time.
    
    stream = gentools.data(ciphertext)
    
    with stream.bytes_decipher(key_bundle, shmac) as decrypting:
        
        # Consumes the ciphertext stream, deciphering it simultaneously ->
        
        padded_data = decrypting.join(b"")
        
        shmac.finalize()
        
        shmac.test_hmac(hmac)
        
        # If no ValueError was raised, the authentication has passed! 
        
    
    # Continue with processing the plaintext ->
    
    depadded_data = Padding.depad_plaintext(padded_data, key_bundle, ttl=60)
    
    depadded_data == plaintext
    >>> True

This example was a low-level look at the encryption algorithm. And it was only a few lines of code. The Comprende class makes working with generators a breeze, & working with generators makes solving problems in bite-sized chunks a breeze.


_`Nuts & Bolts` ................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's take a deep dive into the low-level xor procedure used to implement the ``Chunky2048`` cipher.

.. code-block:: python

    from aiootp.ciphers import SyntheticIV
    
    from aiootp.gentools import comprehension
    
    
    # It's a ``Comprende`` generator ->
    
    @comprehension()
    
    # ``data`` is an iterable which produces 256-bytes of either plaintext 
    
    # or ciphertext data on each iteration. ``key`` should be an instance 

    # of the ``bytes_keys`` generator. And, ``validator`` should be an 

    # instance of the ``StreamHMAC`` class. ->
    
    def xor(data, *, key, validator):
    
        # Return the necessary method & coroutine pointers ->
        
        datastream, keystream, validated_xor, shmac_hexdigest = (
        
            _xor_shortcuts(data, key, validator)
            
        )
        
        # We use the first block of plaintext (which is prepended with an 

        # 8-byte timestamp & a 16-byte random, ephemeral & automatically 

        # generated SIV-key) to derive a syntheic IV, seeding the keystream 
        
        # & validator with globally unique entropy -> 
        
        yield SyntheticIV.validated_xor(datastream, keystream, validator)
        
        for block in datastream:
        
            # We use the output of the validator's current state to 

            # continuously seed the keystream with message dependent entropy ->
            
            seed = shmac_digest()
            
            # We contantenate two 128-byte key chunks together ->
            
            key_chunk = keystream(seed) + keystream(seed)
            
            # Then xor the 256-byte key chunk & 256-byte data block, & 
            
            # update the validator with the ciphertext ->
            
            yield validated_xor(block, key_chunk)

This is a very efficient, online-AEAD, salt-reuse/misuse resistant, pseudo-one-time-pad cipher algorithm. Being built on generators makes it simple to grok & compose with additional funcitonality. It's backed by an infinite stream of non-repeating key material, efficiently produced from a finite-sized key, an ephemeral salt, authenticated associated data, message content, & SHA3 hashing.




_`X25519 & Ed25519` ............................... `Table Of Contents`_
------------------------------------------------------------------------

Asymmetric curve 25519 tools are available from these high-level interfaces over the ``cryptography`` package.


_`X25519` ......................................... `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Elliptic curve 25519 diffie-hellman exchange protocols.

.. code-block:: python

    from aiootp import X25519
    
    
    # Triple Diffie-Hellman Key Exchange client initialization ->
    
    ecdhe_key = X25519().generate()
    
    with ecdhe_key.dh3_client() as exchange:
    
        response = internet.post(exchange())
        
        exchange(response)
        
    clients_kdf = exchange.result()


    # Triple Diffie-Hellman Key Exchange for a receiving peer ->

    ecdhe_key = X25519().generate()
    
    identity_key, ephemeral_key = client_public_keys = internet.receive()
    
    server = ecdhe_key.dh3_server(identity_key, ephemeral_key)
    
    with server as exchange:
    
        internet.post(exchange.exhaust())
        
    servers_kdf = exchange.result()
    

    # Success! Now both the client & server peers share an identical
    
    # sha3_512 hashing object to create shared keys ->

    assert clients_kdf.digest() == servers_kdf.digest()
    
    
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
    
    # key & she has reason believe it is genuinely hers. So, she'll
    
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

This magic with generators is made simple with the ``comprehension`` decorator. It wraps them in ``Comprende`` objects with access to myriad data processing & cryptographic utilities right out of the box.


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

    for hex_digest in unpack(base64_data).sha3__256():
        
        print(hex_digest)


_`Asynchronous Generators` ........................ `Table Of Contents`_
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Async ``Comprende`` coroutines have almost exactly the same interface as synchronous ones.

.. code-block:: python

    from aiootp.gentools import comprehension


    @comprehension()
    
    async def gen(x: int, y: int):
    
        # Because having a return statement in an async generator is a
        
        # SyntaxError, the return value is expected to be passed into
        
        # UserWarning, and then raised to propagate upstream. It's then
        
        # available from the instance's ``aresult`` method ->
        
        z = yield x + y
        
        raise UserWarning(x * y * z)
        
        
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
    
        for number in range(256):
        
            yield number
    
    
    # This is asynchronous data processing ->
    
    base64_data = await one_byte_numbers().aint_to_bytes(1).ato_base64().alist()
    
    # This converted each number to bytes then base64 encoded them.


    # We can wrap other iterables to add asynchronous functionality to them ->

    @comprehension()
    
    async def unpack(iterable):
    
        for item in iterable:
    
            yield item


    # Want only the first twenty results? ->

    async for hex_hash in unpack(base64_data).asha3__256()[:20]:
    
        # Then you can slice the generator.
        
        print(hex_hash)
        
        
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
    
    
    # Global async functionalities & abstractions ->
    
    aiootp.asynchs
    
    
    # Decorators & classes able to benchmark async/sync functions & generators ->
    
    aiootp.debuggers
    
    
    #




