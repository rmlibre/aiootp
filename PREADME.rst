.. image:: https://github.com/rmlibre/aiootp/blob/master/logo.png
    :target: https://github.com/rmlibre/aiootp/blob/master/logo.png
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




Some Examples
-------------

Users can create and modify transparently encrypted databases:

.. code-block:: python

    #

    import aiootp
    
    
    # Make a new user key for encryption / decryption with a fast,
    
    # cryptographically secure pseudo-random number generator ->
    
    key = await aiootp.acsprng()
    
    
    # Create a database object with it ->
    
    db = await aiootp.AsyncDatabase(key)
    
    
    # Users can also use passwords to open a database, if necessary.

    # Although passwords & passphrases are low-entropy, & not recommended,

    # here's how to use them more safely ->

    tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
        "server_url",     # An unlimited number of arguments can be passed
        "email_address",  # here as additional, optional credentials.
        username="username",
        password="password",
        salt="optional salt keyword argument",
    )
    
    db = await aiootp.AsyncDatabase.agenerate_profile(tokens)
    
    
    # Data within databases are organized by ``tag``s ->
    
    async with db:    #  <---Context saves data to disk when closed
    
        db["tag"] = {"data": "can be any json serializable object"}
        
        db["bitcoin"] = "0bb6eee10d2f8f45f8a"
        
        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}
        
        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]
    

    # Databases also have access to conversion functions for saving 

    # bytes type data ->
    
    db["bytes data"] = await db.abase64_encode(b"fash smasher")

    assert b"fash smasher" == await db.abase64_decode(db["bytes data"])


    # Access to data is open to the user, so care must be taken
    
    # not to let external api calls touch the database without
    
    # accounting for how that can go wrong.
    
    
    # Sensitive tags can be hashed into uuids of arbitrary size ->

    await db.ametatag("clients")
    
    email_uuids = await db.clients.auuids("emails", size=64)
    
    for email_address in ["brittany@email.com", "john.doe@email.net"]:
    
        hashed_tag = await email_uuids(email_address)
        
        db.clients[hashed_tag] = "client account data"
    
    db["clients salt"] = await email_uuids.aresult(exit=True)
    
    
    # Data of any type can be verified using an hmac ->
    
    hmac = await db.ahmac({"id": 1234, "payload": "message"})
    
    await db.atest_hmac({"id": 1234, "payload": "message"}, hmac=hmac)
    
 >>> True
    
    # Although, datatypes where order of values is not preserved may fail to 
    
    # validate -> 
    
    await db.atest_hmac({"payload": "message", "id": 1234}, hmac=hmac) 
    
 >>> ValueError: "HMAC of the data stream isn't valid."
    
    
    # Create child databases accessible from the parent by a ``metatag`` ->
    
    metatag = "child"
    
    molly = await db.ametatag(metatag)
    
    molly["hobbies"] = ["skipping", "punching"]
    
    molly["hobbies"].append("reading")
    
    molly["hobbies"] is db.child["hobbies"]
    
 >>> True
    
    assert isinstance(molly, aiootp.AsyncDatabase)
    
    
    # If the user no longer wants a piece of data, pop it out ->
    
    await molly.apop("hobbies")

 >>> ["skipping", "punching", "reading"]
    
    
    "hobbies" in molly
    
 >>> False
    
    
    # Delete a child database from the filesystem ->
    
    await db.adelete_metatag("child")
    
    db.child["hobbies"]
    
 >>> AttributeError: 'AsyncDatabase' object has no attribute 'child'
    
    
    # Write database changes to disk with transparent encryption ->
    
    await db.asave()
    
    
    # Make mirrors of databases ->
    
    new_key = await aiootp.acsprng()
    
    new_db = await aiootp.AsyncDatabase(new_key)
    
    await new_db.amirror_database(db)
    
    assert new_db["lawyer"] is db["lawyer"]
    
    
    # Or make namespaces out of databases for very efficient lookups ->
    
    namespace = await new_db.ainto_namespace()
    
    assert namespace.bitcoin == new_db["bitcoin"]
    
    assert namespace.lawyer is new_db["lawyer"]
    
    
    # Delete a database from the filesystem ->
    
    await db.adelete_database()
    
    
    # Initialization of a database object is more computationally expensive
    
    # than entering its context manager. So keeping a reference to a

    # preloaded database is a great idea, either call ``asave`` / ``save``

    # periodically, or open a context with the reference whenever wanting to

    # capture changes to the filesystem ->
    
    async with new_db as db:
    
        print("Saving to disk...")
        
        
    # As databases grow in the number of tags & metatags & the size of
    
    # the data within, it may become desireable to load data from them
    
    # as needed, instead of all at once during initialization. This can

    # be done with the ``preload`` boolean keyword argument ->
    
    db["tag_test"] = "test value"
    
    await db.ametatag("metatag_test")
    
    await db.asave()
    
    quick_db = await aiootp.AsyncDatabase(key, preload=False)
    
    
    # Although, now to retrieve elements from an async database, the
    
    # ``aquery`` method must first be used to load tags into the cache ->
    
    quick_db["tag_test"]
    
 >>> None
    
    loaded_value = await quick_db.aquery("tag_test")
    
    assert loaded_value == "test value"
    
    assert quick_db["tag_test"] == "test value"
    
    
    # Metatags need to be loaded manually as well ->
    
    quick_db.metatag_test
    
 >>> AttributeError:
    
    await quick_db.ametatag("metatag_test")
    
    assert type(quick_db.metatag_test) == aiootp.AsyncDatabase
    
    
    # Transparent and automatic encryption makes persisting sensitive 
    
    # information very simple. Though, if users do want to encrypt / 
    
    # decrypt things manually, then databases allow that too ->
    
    data_name = "saturday clients"
    
    clients = ["Tony", "Maria"]
    
    encrypted = await db.aencrypt(filename=data_name, plaintext=clients)
    
    decrypted = await db.adecrypt(filename=data_name, ciphertext=encrypted)
    
    clients == decrypted
    
 >>> True
    
    
    # All encrypted messages have timestamps that can be used to enforce

    # limits on how old messages can be (in seconds) before they are

    # rejected ->
    
    decrypted = await db.adecrypt(data_name, encrypted, ttl=25)
    
 >>> TimeoutError: Timestamp expired by <10> seconds.
    
    
    #




What other tools are available to users?:

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
    
    decrypted = pad.io.depad_bytes(padded_data, salted_key=padding_key)
    
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
        "abytes_decrypt",
        "abytes_encrypt",
        "abytes_to_hex",
        "abytes_to_int",
        "adebugger",
        "adecode",
        "adecrypt",
        "adelimit",
        "adelimited_resize",
        "adepad_plaintext",
        "aencode",
        "aencrypt",
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
        "amap_decipher",
        "amap_encipher",
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
        "bytes_decrypt",
        "bytes_encrypt",
        "bytes_to_hex",
        "bytes_to_int",
        "debugger",
        "decode",
        "decrypt",
        "delimit",
        "delimited_resize",
        "depad_plaintext",
        "encode",
        "encrypt",
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
        "map_decipher",
        "map_encipher",
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
    
    
    # Let's look at a more complicated example with the one-time pad 
    
    # keystreams. There are many uses for endless streams of deterministic 
    
    # key material outside of one-time pad cipher keys. They can, for instance, 
    
    # give hash tables order that's cryptographically determined & obscured -> 
    
    ordered_entries = {}
    
    salt = await aiootp.asalt()
    
    names = aiootp.akeys(key, salt=salt)
    
    
    # Resize each output of ``names`` to 32 characters, tag each output with
    
    # an incrementing number, & stop the stream after 0.01 seconds ->
    
    async for index, name in names.aresize(32).atag().atimeout(0.01):
    
        ordered_entries[name] = f"{index} data organized by the stream of hashes"
    
    
    # Retrieving items in the correct order requires knowing both ``key`` & ``salt``
    
    async for index, name in aiootp.akeys(key, salt=salt).aresize(32).atag():
    
        try:
        
            assert ordered_entries[name] == f"{index} data organized by the stream of hashes"
            
        except KeyError:
        
            print(f"There are no more entries after {index} iterations.")
            
            assert index == len(ordered_entries) + 1
            
            break
            
            
    # There's a prepackaged ``Comprende`` generator function that does
    
    # encryption / decryption of key ordered hash maps. It needs bytes
    
    # data to work on though. First let's make an actual encryption key
    
    # stream that's different from ``names`` ->
    
    pid = aiootp.sha_256(key, salt, "any additional data")
    
    key_stream = aiootp.akeys(key, salt=salt, pid=pid)
    
    
    # And example plaintext ->
    
    plaintext = 100 * b"Some kinda message..."
    
    
    # We'll have to safely pad the plaintext to a multiple of 256 bytes ->
    
    padding_key = aiootp.padding_key(key, salt=salt, pid=pid)
    
    padded_data = aiootp.pad_plaintext(plaintext, salted_key=padding_key)
    
    
    # We can now stream the data & ciphertext authentication process ->
    
    data_stream = aiootp.adata(padded_data)
    
    hmac = aiootp.StreamHMAC(key, salt=salt, pid=pid).for_encryption()
    
    
    # And let's make sure to clean up after ourselves with a context manager ->
    
    async with data_stream.amap_encipher(names, key_stream, validator=hmac) as encrypting:
    
        # ``adata`` takes a sequence, & ``amap_encipher`` takes two iterables,
        
        # a stream of names for the hash map, & the stream of key material.
        
        ciphertext_hashmap = await encrypting.adict()
        
        ciphertext_authentication = await hmac.afinalize()
        
        siv = hmac.siv
        
        
    # Now we'll pick the chunks out in the order produced by ``names`` to 

    # decrypt them ->
    
    ciphertext_stream = aiootp.apick(names, ciphertext_hashmap)
    
    
    # The decrypting party will likely have to instantiate their own 
    
    # keystream object, but we'll just reset ours for convenience ->
    
    await key_stream.areset()
    
    
    # Next we'll authenticate & decrypt the ciphertext hashmap in the 
    
    # correct order ->
    
    hmac = aiootp.StreamHMAC(key, salt=salt, pid=pid, siv=siv).for_decryption()
    
    async with ciphertext_stream.amap_decipher(key_stream, validator=hmac) as decrypting:
    
        decrypted = await decrypting.ajoin(b"")
        
        await hmac.afinalize()
        
        await hmac.atest_hmac(ciphertext_authentication)
        
        
    # We can now remove any padding from the data to reveal the plaintext ->
        
    assert plaintext == aiootp.depad_plaintext(decrypted, salted_key=padding_key)
    
    
    # This is neat, & makes sharding & authenticating encrypted data 
    
    # incredibly easy.
    
    
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




