.. image:: https://raw.githubusercontent.com/rmlibre/aiootp/master/logo.png
    :target: https://raw.githubusercontent.com/rmlibre/aiootp/master/logo.png
    :alt: logo for python package named aiootp




aiootp - Asynchronous pseudo-one-time-pad based crypto and anonymity library.
=============================================================================

``aiootp`` is an asynchronous library providing access to cryptographic 
primatives and abstractions, transparently encrypted / decrypted file 
I/O and databases, as well as powerful, pythonic utilities that 
simplify data processing & cryptographic procedures in python code. 
This library's online MRAE / AEAD cipher, called ``Chunky2048``, is an 
implementation of the **pseudo-one-time-pad**. The aim is to create a simple, 
standard, efficient implementation that's indistinguishable from the 
unbreakable one-time-pad cipher; to give users and applications access to 
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




Quick install
-------------

``pip3 install --user --upgrade aiootp``




Table Of Contents
-----------------

- `Transparently Encrypted Databases`_
- 
  a) `Ideal Initialization`_
  b) `User Profiles`_
  c) `Tags`_
  d) `Metatags`_
  e) `Basic Management`_
  f) `Mirrors`_
  g) `Namespaces`_
  h) `Public Cryptographic Functions`_

     I. `Encrypt / Decrypt`_
     II. `HMACs`_
     III. `UUIDs`_
     IV. `Passcrypt`_

- `Other Tutorials`_
- 
  a) (more coming soon)




_`Transparently Encrypted Databases`
------------------------------------

The package's ``AsyncDatabase`` & ``Database`` classes are very powerful data persistence utilities. They automatically handle encryption & decryption of user data & metadata, providing a pythonic interface for storing & retrieving any json serializable objects. They're designed to seamlessly bring encrypted bytes at rest, to dynamic objects in use.


_`Ideal Initialization`
^^^^^^^^^^^^^^^^^^^^^^^

Make a new user key with a fast, cryptographically secure pseudo-random number generator. Then this strong 512-bit key can be used to create a database object.

.. code-block:: python

    from aiootp import AsyncKeys, AsyncDatabase
    
    
    key = await AsyncKeys.acsprng()

    db = await AsyncDatabase(key)
    

_`User Profiles`
^^^^^^^^^^^^^^^^

With User Profiles, passwords may be used instead to open a database. Often, passwords & passphrases contain very little entropy. So, they aren't recommended for that reason. However, profiles provide a succinct way to use passwords more safely. They do this by deriving strong keys from low entropy user input, the memory/cpu hard passcrypt algorithm, & a secret salt which is automatically generated & stored on the user's filesystem.

.. code-block:: python

    # Convert any available user credentials into cryptographic tokens ->

    tokens = await AsyncDatabase.agenerate_profile_tokens(
    
        "server-url.com",     # An unlimited number of arguments can be passed
        
        "address@email.net",  # here as additional, optional credentials.
        
        username="username",
        
        password="password",
        
        salt="optional salt keyword argument",
        
    )


    # Finally, use those special tokens to open a database instance ->

    db = await AsyncDatabase.agenerate_profile(tokens)


_`Tags`
^^^^^^^

Data within databases are primarily organized by Tags. Tags are simply json serializable labels, and the data stored under them can also be any json serializable objects.

.. code-block:: python

    # Open a context to automatically save data to disk when closed ->

    async with db:
    
        db["tag"] = {"data": "can be any json serializable object"}
        
        db["hobby"] = await db.abase64_encode(b"fash smasher")
        
        db["bitcoin"] = "0bb6eee10d2f8f45f8a"
        
        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}
        
        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]


    # Instead of saving the entire database when a single new tag is 

    # added, a tag can be saved to disk individually ->

    await db.asave_tag("lawyer")


    # View an instance's tags ->

    db.tags
    >>> ['tag', 'hobby', 'bitcoin', 'lawyer', 'safehouses']


    # Set & query tags in the instance's cache with dedicated method ->

    await db.aset("pseudonym", "Free The People")

    await db.aquery("pseudonym")
    >>> 'Free The People'

    assert "pseudonym" in db


    # Remove a tag from the cache & its associated data on the filesystem ->

    await db.apop("pseudonym")
    >>> 'Free The People'

    assert "pseudonym" not in db

Access to data is open to the user, so care must be taken not to let external api calls touch the database without accounting for how that can go wrong.


_`Metatags`
^^^^^^^^^^^

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
    

    # All of an instance's metatags are quickly viewable ->

    db.metatags
    >>> ['molly']
    

    # Delete a metatag from an instance ->

    await db.adelete_metatag("molly")
    
    db.metatags
    >>> []
    
    assert not hasattr(db, "molly")


_`Basic Management`
^^^^^^^^^^^^^^^^^^^

There's a few settings & public methods on databases for users to manage their instances & data. This includes general utilities for saving & deleting databases to & from the filesystem, as well as fine-grained controls for how data is handled. 

.. code-block:: python

    # The directory attribute is set within the instance's __init__

    # using a keyword-only argument. It's the directory where the

    # instance will store all of its files.

    db.directory
    >>> PosixPath('site-packages/aiootp/aiootp/databases')
    
    
    # Write database changes to disk with transparent encryption ->
    
    await db.asave()


    # Entering the instance's context also saves data to disk ->

    async with db:
    
        print("Saving to disk...")
    

    # Delete a database from the filesystem ->
    
    await db.adelete_database()
    
    
As databases grow in the number of tags, metatags & the size of data within, it may become desireable to load data from them as needed, instead of all at once during initialization. This can be done with the ``preload`` boolean keyword argument.

.. code-block:: python

    # Let's create some test values to show the impact preloading has ->

    async with (await AsyncDatabase(key)) as db:

        db["favorite_foods"] = ["justice", "community"]
    
        await db.ametatag("exercise_routines") 
    

    # This is how to toggle preloading off during initialization ->

    quick_db = await AsyncDatabase(key, preload=False)
    
    
    # Now to retrieve elements from an async database, the ``aquery`` 

    # method must first be used to load a tag into the cache ->

    async with quick_db:
    
        quick_db["favorite_foods"]
        >>> None
    
        loaded_value = await quick_db.aquery("favorite_foods")
    
        assert loaded_value == ["justice", "community"]
    
        assert quick_db["favorite_foods"] == ["justice", "community"]
    
    
        # Metatags need to be loaded manually as well ->
    
        quick_db.exercise_routines
        >>> AttributeError:
    
        await quick_db.ametatag("exercise_routines")
    
        assert type(quick_db.exercise_routines) == AsyncDatabase


_`Mirrors`
^^^^^^^^^^

Database mirrors allow users to make copies of all files within a database under new encryption keys. This is useful if users simply want to make backups, or if they'd like to update / change their database keys. 

.. code-block:: python

    # A unique login key / credentials are needed to create a new 

    # database ->
    
    new_key = await AsyncKeys.acsprng()
    
    new_db = await AsyncDatabase(new_key)


    # Mirroring an existing database is done like this ->
    
    await new_db.amirror_database(db)

    assert new_db["favorite_foods"] is db["favorite_foods"]


    # If the user is just updating their database keys, then the old

    # database should be deleted ->

    await db.adelete_database()


    # Now the new database can be saved to disk & given an appropriate 

    # name ->

    async with new_db as db:

        pass


_`Namespaces`
^^^^^^^^^^^^^

Database Tags can be loaded into ``Namespace`` objects. This saves lots of time & cpu effort on lookups. This is because databases use cryptographic hashes of Tags to find their associtated data within themselves. This can be up to a couple thousand times slower than the dotted lookups on a ``Namespace`` object. This is a great way to load lots of encrypted values but then use them very efficiently in calculations.

.. code-block:: python

    # Loading a database's tags into a Namespace is done this way ->

    namespace = await db.ainto_namespace()
    
    assert namespace.favorite_foods is db["favorite_foods"]


    # View all the Namespace's tags ->

    list(namespace.keys())
    >>> ["favorite_foods"]


    # View all the Namespace's values ->

    list(namespace.values())
    >>> [["justice", "community"]]


    # Namespace's yield their key & value pairs whien iterated over ->

    for tag, value in namespace:
    
        print(tag, value)
        
    >>> "favorite_foods" ["justice", "community"]


_`Public Cryptographic Functions`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Although databases handle encryption & decryption automatically, users may want to utilize their databases' keys to do custom cryptographic procedures manually. There are a few public functions available to users if they should want such functionality.


_`Encrypt / Decrypt`
********************

.. code-block:: python

    # Either json serializable or bytes-type data can be encrypted ->

    json_plaintext = {"some": "json data can go here"}
    
    bytes_plaintext = b"some bytes plaintext goes here"

    jciphertext = await db.ajson_encrypt(json_plaintext)

    bciphertext = await db.abytes_encrypt(bytes_plaintext)


    # Those values can just as easily be decrypted ->

    assert json_plaintext == await db.ajson_decrypt(jciphertext)

    assert bytes_plaintext == await db.abytes_decrypt(bciphertext)


    # Filenames may be added to classify ciphertexts. They also alter the 

    # key material used during encryption in such a way, that without the

    # correct filename, the data cannot be decrypted ->

    filename = "grocery list"

    groceries = ["carrots", "taytoes", "rice", "beans"]

    ciphertext = await db.ajson_encrypt(groceries, filename=filename)

    assert groceries == await db.ajson_decrypt(ciphertext, filename=filename)


    # Time-based expiration of ciphertexts is also available for all 

    # encrypted data this package produces ->

    from aiootp.asynchs import asleep


    await asleep(6)

    await db.ajson_decrypt(jciphertext, ttl=2)
    >>> TimeoutError: Timestamp expired by <4> seconds.

    await db.abytes_decrypt(bciphertext, ttl=2)
    >>> TimeoutError: Timestamp expired by <4> seconds.


    # The number of seconds that are exceeded may be helpful to know. In

    # which case, this is how to retrieve that integer value ->

    try: 
    
        await db.abytes_decrypt(bciphertext, ttl=2)

    except TimeoutError as error:

        seconds_expired_by = error.value


_`HMACs`
********

Besides encryption & decryption, databases can also be used to manually verify the authenticity of data with HMACs.

.. code-block:: python

    # Creating an HMAC of some data with a database is done this way ->

    data = "validate this data!"

    hmac = await db.ahmac(data)

    await db.atest_hmac(data, hmac=hmac)
    >>> True


    # Data that is not the same, or is altered, will be caught ->

    altered_data = "valiZate this data!"

    await db.atest_hmac(altered_data, hmac=hmac)
    >>> ValueError: "HMAC of the data stream isn't valid."
    

    # Any type of data can be run thorugh the function, it's the repr

    # of the data which is evaluated ->

    arbitrary_data = {"id": 1234, "payload": "message"}

    hmac = await db.ahmac(arbitrary_data)
    
    await db.atest_hmac(arbitrary_data, hmac=hmac)
    >>> True


    # Beware: Datatypes where order of values is not preserved may fail 

    # to validate even if they are functionally equivalent -> 

    order_swapped_data = {"payload": "message", "id": 1234}

    assert order_swapped_data == arbitrary_data
    
    await db.atest_hmac(order_swapped_data, hmac=hmac) 
    >>> ValueError: "HMAC of the data stream isn't valid."
    

_`UUIDs`
********

Instances can create special generator coroutines that are used to hash sensitive tags, or other data, into hexidecimal UUIDs of arbitrary size. These hashes are secured with the database instance's keys, & a salt value which is either passed in manually by the user, or if not, is automatically generated. The salt is available at the end of the coroutine's usage by calling for it to be returned & for the coroutine to be exited. 

.. code-block:: python

    # Organizing databases with metatags improves readability & safely 

    # isolates cryptographic domains, because metatags use their own

    # sets of keys. Their keys also can't be used to derive their 

    # parent's keys ->

    await db.ametatag("clients")


    # Choosing a category for the coroutine also separates domains ->
    
    email_uuids = await db.clients.auuids("emails", size=24, salt=None)


    # Then a user can hash any values by sending them into the coroutine ->

    for email_address in ["brittany@email.com", "john.doe@email.net"]:
    
        hashed_tag = await email_uuids(email_address)
        
        db.clients[hashed_tag] = "client account data"


    # Once finished hashing, the salt that was used can be retrieved ->
    
    db["clients salt"] = await email_uuids.aresult(exit=True)


_`Passcrypt`
************

``Passcrypt`` is the package's Argon2id-like password-based key derivation function. It was designed to be resistant to time-memory tradeoffs & cache timing side-channel attacks. When passwords (or data in general) are processed through an instance's passcrypt method, then they're also protected by being hashed together with the database's keys.

.. code-block:: python

    # This is an example usage of the databases' passcrypt methods ->

    from getpass import getpass
    

    password = getpass("Enter password: ")

    salt = await db.agenerate_salt()

    await db.apasscrypt(password, salt)
    >>> '''938db60e0deab983ed1eed5ca96980a0557f4a450fcac2ca16e45cc2c36ac0
    40669d30c7f55e3537658d6c91d24a5026a04e2dfe98c59574c02b782a194ccdc1'''


    # The difficulty settings for the algorithm can be controlled too ->

    settings = dict(
    
        kb=16*1024,  # This means 16MB of ram are used to create the hash

        cpu=7,  # This means 7 passes over the memory cache are done

        hardness=2048,  # This is the minimum # of columns in the cache
        
    )


    # They go into the method as keyword-only arguments, so we can use

    # the ** syntax ->

    password_hash = await db.apasscrypt(password, salt, **settings)


    #




_`Other Tutorials`
------------------

What other tools are available to users?

.. code-block:: python

    #
    
    import aiootp   
    
    
    # Async & synchronous versions of almost everything in the library ->
    
    assert await aiootp.asha_512("data") == aiootp.sha_512("data")
    
    key = aiootp.csprng()
    
    db = aiootp.Database(key)
    
    async_db = await aiootp.AsyncDatabase(key)
    
    assert db._root_filename == async_db._root_filename
    
    
    # Precomputed & organized values that can aid users, like:
    
    # A dictionary of prime numbers grouped by their bit-size ->
    
    aiootp.primes[513][0]    # <- The first 65 byte prime
    
    aiootp.primes[2048][-1]    # <- The last 256 byte prime
    
    
    # Elliptic curve 25519 diffie-hellman exchange protocols ->
    
    ecdhe_key = aiootp.X25519().generate()
    
    with ecdhe_key.dh3_client() as exchange:
    
        response = internet.post(exchange())
        
        exchange(response)
        
    clients_kdf = exchange.result()


    # This is how a peer can accept the exchange ->

    ecdhe_key = aiootp.X25519().generate()
    
    pkB, pkD = client_public_keys = internet.receive()
    
    server = ecdhe_key.dh3_server(peer_identity_key=pkB, peer_ephemeral_key=pkD)
    
    with server as exchange:
    
        internet.post(exchange.exhaust())
        
    servers_kdf = exchange.result()
    

    # Success! Now both the client & server peers share an identical
    
    # sha3_512 hashing object to create shared keys with ->

    assert clients_kdf.digest() == servers_kdf.digest()
    
    
    # Edwards curve 25519 signing & verification ->
    
    # In a land, long ago ->
    
    user_alice = Ed25519().generate()
    
    internet.send(user_alice.public_bytes.hex())
    

    # Alice wants to sign a document so that Bob can prove she wrote it.
    
    # So, Alice sends the public key bytes of the key she wants to
    
    # associate with her identity, the document & the signature ->
    
    document = b"DesignDocument.cad"
    
    signed_document = user_alice.sign(document)

    message = {
        "document": document,
        "signature": signed_document,
        "public_key": user_alice.public_bytes.hex(),
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

    # The verification didn't throw an exception! So, Bob knows the file
    
    # was signed by Alice.
    
    
    # Symmetric pseudo-one-time-pad encryption of json data ->
    
    plaintext = {"account": 3311149, "titles": ["queen b"]}
    
    encrypted = aiootp.json_encrypt(plaintext, key=key)
    
    decrypted = aiootp.json_decrypt(encrypted, key=key)
    
    assert decrypted == plaintext
    
    
    # Symmetric pseudo-one-time-pad encryption of binary data ->
    
    binary_data = b"This bytes string is also valid plaintext."
    
    encrypted = aiootp.bytes_encrypt(binary_data, key=key)
    
    decrypted = aiootp.bytes_decrypt(encrypted, key=key)
    
    assert decrypted == binary_data
    
    
    # The Chunky2048 class carries the key so users don't have to pass
    
    # it around every where ->
    
    pad = aiootp.Chunky2048(key)
    
    encrypted = pad.bytes_encrypt(binary_data)
    
    decrypted = pad.bytes_decrypt(encrypted)
    
    
    # The class also has access to an encoder for transforming 
    
    # ciphertext to & from its default dictionary format ->
    
    bytes_ciphertext = pad.io.json_to_bytes(encrypted)
    
    dict_ciphertext = pad.io.bytes_to_json(bytes_ciphertext)
    
    
    # As well as tools for saving ciphertext to files on disk as bytes ->
    
    path = aiootp.DatabasePath() / "testing_ciphertext"
    
    pad.io.write(path, encrypted)
    
    assert encrypted == pad.io.read(path)
    
    
    # Or ciphertext can be encoded to & from a urlsafe string ->
    
    urlsafe_ciphertext = pad.io.bytes_to_urlsafe(bytes_ciphertext)
    
    bytes_ciphertext = pad.io.urlsafe_to_bytes(urlsafe_ciphertext)


    # These urlsafe tokens have their own convenience functions ->
    
    token = pad.make_token(b"binary data")
    
    assert b"binary data" == pad.read_token(token)
    
    
    # Ratcheting Opaque Password Authenticated Key Exchange (ROPAKE) with 
    
    # online services -> 
    
    db = aiootp.Database(pad.key)
    
    with aiootp.Ropake.client_registration(db) as registration:
    
        server_response = internet.post("service-url.com", json=registration())
    
        registration(server_response)
    
    shared_keys = registration.result()
        
        
    # The client is securely registered with the service if there was no 

    # active adversary in the middle. The user can now authenticate & login ->
    
    with aiootp.Ropake.client(db) as authentication:
    
        server_response = internet.post("service-url.com", authentication())
    
        authentication(server_response)
    
    shared_keys = authentication.result()
        
        
    # Upon the first uncompromised registration or authentication, then 

    # future authentications will be immune to adversaries in the middle 

    # because the protocol generates new keys by combining the prior key, 

    # the current ecdhe ephemeral key, & the revealed keyed password that 

    # was transmitted with an extra mask during the prior exchange. The 

    # keyed password authenticates the user & the server to each other when 

    # the commit is revealed, the ephemeral ecdhe key assures future security, 

    # & the prior key encrypts & HMACs the authentication packets which 

    # provides privacy, & added authentication, & the KDF which combines all 

    # these keys to ensure forward security. 
    
    
    # 




Generators under-pin most procedures in the library, let's take a look ->

.. code-block:: python

    #
    
    
    from aiootp import Chunky2048, json
    
    
    pad = Chunky2048()   # <---Auto-generates an encryption key
    
    salt = pad.generate_salt()    # <---A NEW salt MUST be used every encryption!
    
    pid = aiootp.sha_256("any additional data")   # <---Must be known by the decrypting party
    
    plaintext_bytes = json.dumps({"message": "secretsssss"}).encode()
    
    
    # Yields padded plaintext in chunks of 256 bytes ->
    
    plaintext_stream = pad.plaintext_stream(plaintext_bytes, salt=salt, pid=pid)
    
    datastream = plaintext_stream.bytes_to_int()
    
    
    # An endless stream of forward + semi-future secure hex keys ->
    
    keystream = pad.keys(salt=salt, pid=pid)
    
    
    # This is used to authenticate the ciphertext & additional data ->
    
    hmac = pad.StreamHMAC(salt=salt, pid=pid).for_encryption()
    
    
    # xor's the plaintext chunks with key chunks ->
    
    with pad.xor(datastream, key=keystream, validator=hmac) as encrypting:
        
        # ``list`` returns all generator results in a list
        
        ciphertext = encrypting.list()
        
        ciphertext_authentication = hmac.finalize()
        
        siv = hmac.siv
        
        
    # When receiving ciphertext, the user must first validate the hmac of 

    # the ciphertext before trusting the plaintext that's revealed ->
    
    hmac = pad.StreamHMAC(salt=salt, pid=pid, siv=siv).for_decryption()
        
        
    keystream.reset()
    
    decipher = pad.xor(ciphertext, key=keystream, validator=hmac)
    
    with decipher.int_to_bytes() as decrypting:
    
        padding_key = pad.padding_key(salt=salt, pid=pid)

        padded_data = decrypting.join(b"")
        
        hmac.finalize()

        hmac.test_hmac(ciphertext_authentication)
        
        # If no ValueError was raised, the authentication has passed! 


    # Continue with processing the plaintext ->
    
    decrypted = pad.io.depad_plaintext(padded_data, padding_key=padding_key)
    
    plaintext_bytes == decrypted
    >>> True
    
    
    # This example was a low-level look at the encryption algorithm. And it 
    
    # was only a few lines of code. The Comprende class makes working with 
    
    # generators a breeze, & working with generators makes solving problems 
    
    # in bite-sized chunks a breeze. ->
    
    padded_plaintext = pad.plaintext_stream(plaintext_bytes, salt=salt, pid=pid).list()
    
    assert isinstance(padded_plaintext, list)
    
    for block in padded_plaintext:
    
        assert len(block) == 256
    
    
    # We just used the ``list`` end-point to get the full series 

    # of results from the underlying generator. These results are lru-cached 

    # to facilitate their efficient reuse for alternate computations. The 

    # ``Comprende`` context managers clear the opened instance's cache on exit, 

    # this clears every instance's cache ->

    aiootp.Comprende.clear_class()
    
    
    # The other end-points can be found under ``aiootp.Comprende.eager_methods`` ->
    
    {
        'adeque',
        'adict',
        'aexhaust',    # <- Doesn't cache results, only returns the last element
        'ajoin',
        'alist',
        'aset',
        'deque',
        'dict',
        'exhaust',    # <- Doesn't cache results, only returns the last element
        'join',
        'list',
        'set',
    }
    
    
    # A lot of this magic with generators is made possible with a sweet little
    
    # ``comprehension`` decorator. It reimagines the generator interface by 
    
    # wrapping generators in the innovative ``Comprende`` class, giving every 
    
    # generator access to a plethora of data processing & cryptographic utilities 
    
    # right out of the box ->
    
    @aiootp.comprehension()
    
    def gen(x=None, y=None):
    
        z = yield x + y
        
        return x * y * z
    
    
    # Drive the generator forward with a context manager ->
    
    with gen(x=1, y=2) as example:
    
        z = 3
        
        
        # Calling the object will send ``None`` into the coroutine by default ->
        
        sum_of_x_y = example()
        
        assert sum_of_x_y == 3


        # Passing ``z`` will send it into the coroutine, cause it to reach the 
        
        # return statement & exit the context manager ->
        
        example(z)
    
    
    # The result returned from the generator is now available ->
    
    product_of_x_y_z = example.result()
    
    assert product_of_x_y_z == 6
    
    
    # The ``example`` variable is actually the ``Comprende`` object,

    # which redirects values to the wrapped generator's ``send()``
    
    # method using the instance's ``__call__()`` method.
    
    
    # Here's another example ->
    
    @aiootp.comprehension() 
    
    def one_byte_numbers():
    
        for number in range(256):
        
            yield number
    
    
    # Chained ``Comprende`` generators are excellent inline data processors ->
    
    base64_data = [
    
        b64_byte
        
        for b64_byte
        
        in one_byte_numbers().int_to_bytes(1).to_base64()
        
    ]
    
    # This converted each number to bytes then base64 encoded them.


    # We can wrap other iterables to add functionality to them ->

    @aiootp.comprehension()
    
    def unpack(iterable):
    
        for item in iterable:
    
            yield item


    # This example just hashes each output then yields them

    for hex_hash in unpack(base64_data).sha_256():
        
        print(hex_hash)


    # Async ``Comprende`` coroutines have almost exactly the same interface as
    
    # synchronous ones ->
    
    @aiootp.comprehension()
    
    async def gen(x=None, y=None):
    
        # Because having a return statement in an async generator is a
        
        # SyntaxError, the return value is expected to be passed into
        
        # UserWarning, and then raised to propagate upstream. It's then
        
        # available from the instance's ``aresult`` method ->
        
        z = yield x + y
        
        result = x * y * z
        
        raise UserWarning(result)
        
        
    # Drive the generator forward.
    
    async with gen(x=1, y=2) as example:
    
        z = 3
        
        
        # Awaiting the ``__call__`` method will send ``None`` into the

        # coroutine by default ->
        
        sum_of_x_y = await example()
        
        assert sum_of_x_y == 3


        # Passing ``z`` will send it into the coroutine, cause it to reach the
        
        # raise statement which will exit the context manager gracefully ->
        
        await example(z)
    
    
    # The result returned from the generator is now available ->
    
    product_of_x_y_z = await example.aresult()
    
    assert product_of_x_y_z == 6
    
    
    # Let's see some other ways async generators mirror synchronous ones ->
    
    @aiootp.comprehension() 
    
    async def one_byte_numbers():
    
        for number in range(256):
        
            yield number
    
    
    # This is asynchronous data processing ->
    
    base64_data = [
    
        b64_byte
        
        async for b64_byte
        
        in one_byte_numbers().aint_to_bytes(1).ato_base64()
        
    ]
    
    # This converted each number to bytes then base64 encoded them.


    # We can wrap other iterables to add asynchronous functionality to them ->

    @aiootp.comprehension()
    
    async def unpack(iterable):
    
        for item in iterable:
    
            yield item


    # Want only the first twenty results? ->

    async for hex_hash in unpack(base64_data).asha_256()[:20]:
    
        # Then you can slice the generator.
        
        print(hex_hash)
        
        
    # Users can slice generators to receive more complex output rules, like:
    
    # Getting every second result starting from the third result to the 50th ->
    
    async for result in unpack(base64_data)[3:50:2]:
    
        print(result)


    # Although, negative slice numbers are not supported.
    
    
    # ``Comprende`` generators have loads of tooling for users to explore. 
    
    # Play around with it and take a look at the other chainable generator 

    # methods in ``aiootp.Comprende.lazy_generators``.
    
    {
        "_agetitem",
        "_getitem",
        "aascii_to_int",
        "abin",
        "abytes",
        "abytes_decipher",
        "abytes_encipher",
        "abytes_to_hex",
        "abytes_to_int",
        "adebugger",
        "adecode",
        "adelimit",
        "adelimited_resize",
        "adepad_plaintext",
        "aencode",
        "afeed",
        "afeed_self",
        "afrom_base",
        "afrom_base64",
        "ahalt",
        "ahex",
        "ahex_to_bytes",
        "aindex",
        "aint",
        "aint_to_ascii",
        "aint_to_bytes",
        "ajson_dumps",
        "ajson_loads",
        "apad_plaintext",
        "apasscrypt",
        "arandom_sleep",
        "areplace",
        "aresize",
        "ascii_to_int",
        "asha_256",
        "asha_256_hmac",
        "asha_512",
        "asha_512_hmac",
        "aslice",
        "asplit",
        "astr",
        "asum_passcrypt",
        "asum_sha_256",
        "asum_sha_512",
        "atag",
        "atimeout",
        "ato_base",
        "ato_base64",
        "axor",
        "azfill",
        "bin",
        "bytes",
        "bytes_decipher",
        "bytes_encipher",
        "bytes_to_hex",
        "bytes_to_int",
        "debugger",
        "decode",
        "delimit",
        "delimited_resize",
        "depad_plaintext",
        "encode",
        "feed",
        "feed_self",
        "from_base",
        "from_base64",
        "halt",
        "hex",
        "hex_to_bytes",
        "index",
        "int",
        "int_to_ascii",
        "int_to_bytes",
        "json_dumps",
        "json_loads",
        "pad_plaintext",
        "passcrypt",
        "random_sleep",
        "replace",
        "resize",
        "sha_256",
        "sha_256_hmac",
        "sha_512",
        "sha_512_hmac",
        "slice",
        "split",
        "str",
        "sum_passcrypt",
        "sum_sha_256",
        "sum_sha_512",
        "tag",
        "timeout",
        "to_base",
        "to_base64",
        "xor",
        "zfill",
    }

    #




Let's take a deep dive into the low-level xor procedure used to implement the pseudo-one-time-pad:

.. code-block:: python

    #
    
    import aiootp
    
    # It is a ``Comprende`` generator ->
    
    @aiootp.comprehension()
    
    # ``data`` is an iterable of 256 byte integers that are either plaintext
    
    # or ciphertext. ``key`` should be an instance of the ``keys`` generator. 
    
    # And, ``validator`` should be an instance of the ``StreamHMAC`` class. ->
    
    def xor(data, *, key, validator):
    
        # Return the necessary method & coroutine pointers ->
        
        datastream, keystream, validated_xor, hmac_hexdigest = (
        
            xor_shortcuts(data, key, validator)
            
        )
        
        # We use the first block of plaintext (which is prepended with an 

        # 8-byte timestamp & a 16-byte random, ephemeral & automatically 

        # generated SIV-key) to derive a syntheic IV, & use it to seed the 

        # keystream & validator with globally unique entropy -> 
        
        yield SyntheticIV.validated_xor(datastream, keystream, validator)
        
        for chunk in datastream:
        
            # We use the output of the validator's current state to 

            # continuously seed the keystream with message dependent entropy ->
            
            seed = hmac_hexdigest()
            
            # We contantenate two 128 byte key chunks together ->
            
            key_chunk = int(keystream(seed) + keystream(seed), 16)
            
            # Then xor the 256 byte key chunk with the 256 byte data chunk 
            
            # and use the validator to update the HMAC with the ciphertext ->
            
            result = validator.validated_xor(chunk, key_chunk)
            
            if result >> 2048:
                
                # If the result is for some reason larger than 256 bytes,
                
                # (2048-bits), we abort the procedure, & warn the user ->
                
                raise ValueError(EXCEEDED_BLOCKSIZE)
                
            # Then we yield the result ->
           
            yield result


    # This is a very efficient, online-AEAD, salt-reuse/misuse resistant, 

    # pseudo-one-time-pad cipher algorithm. It's built on generators, 

    # which makes it simple to grok & compose with additional funcitonality. 

    # It's backed by an infinite stream of non-repeating key material, 
    
    # efficiently produced from a finite-sized key, an ephemeral salt, 

    # context & content data, & the sha3_512 algorithm.
    
    
    #




Here's a quick overview of this package's modules:

.. code-block:: python

    #
    
    import aiootp
    
    
    # Commonly used constants, datasets & functionality across all modules ->
    
    aiootp.commons
    
    
    # The basic utilities & abstractions of the package's architecture ->
    
    aiootp.generics
    
    
    # This module is responsible for providing entropy to the package ->
    
    aiootp.randoms
    
    
    # The higher-level abstractions used to implement the pseudo-one-time pad ->
    
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




