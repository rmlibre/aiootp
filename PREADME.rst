aiootp - Asynchronous one-time-pad based crypto and anonymity library.
======================================================================

``aiootp`` is an asynchronous library providing access to cryptographic 
primatives and abstractions, transparently encrypted / decrypted file 
I/O and databases, as well as powerful, pythonic utilities that 
simplify data processing & cryptographic procedures in python code. 
This library's cipher is an implementation of the **one-time pad**. 
The aim is to create a simple, standard, efficient implementation of 
this unbreakable cipher, to give users and applications access to 
user-friendly cryptographic tools, and to increase the overall 
security, privacy, and anonymity on the web, and in the digital world. 
Users will find ``aiootp`` to be easy to write, easy to read, and fun. 




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

.. code:: python

    #

    import aiootp
    
    
    # Make a new user key for encryption / decryption with a fast,
    
    # cryptographically secure pseudo-random number generator ->
    
    key = await aiootp.acsprng()
    
    
    # Create a database object with it ->
    
    db = await aiootp.AsyncDatabase(key)
    
    
    # Users can also use passwords to open a database, if necessary.
    
    # Although it's not recommended, here's how to do it ->
    
    tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
        "my username",
        "my password",
        *[any, b"collection", 0x0f, "credentials"],
        salt="anything with randomness a user can remember",
    )
    
    db = await aiootp.AsyncDatabase.agenerate_profile(tokens)
    
    
    # Data within databases are organized by ``tag``s ->
    
    async with db:    #  <---Context saves data to disk when closed
    
        db["tag"] = {"data": "can be any json serializable object"}
        
        db["bitcoin"] = "0bb6eee10d2f8f45f8a"
        
        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}
        
        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]
    
    
    # Access to data is open to the user, so care must be taken
    
    # not to let external api calls touch the database without
    
    # accounting for how that can go wrong.
    
    
    # Sensitive tags can be hashed into uuids of arbitrary size ->

    clients = await db.ametatag("clients")
    
    email_uuids = await clients.auuids("emails", size=64)
    
    for email_address in ["brittany@email.com", "john.doe@email.net"]:
    
        hashed_tag = await email_uuids(email_address)
        
        clients[hashed_tag] = "client account data"
    
    db["clients salt"] = await email_uuids.aresult(exit=True)
    
    
    # Data of any type can be verified using an hmac ->
    
    hmac = await db.ahmac({"id": 1234, "payload": "message"})
    
    await db.atest_hmac({"id": 1234, "payload": "message"}, hmac=hmac)
    
 >>>True
    
    # Although, datatypes where order of values is not preserved may fail to 
    
    # validate -> 
    
    await db.atest_hmac({"payload": "message", "id": 1234}, hmac=hmac) 
    
 >>>ValueError: "HMAC of ``data`` isn't valid." 
    
    
    # Create child databases accessible from the parent by a ``metatag`` ->
    
    metatag = "child"
    
    molly = await db.ametatag(metatag)
    
    molly["hobbies"] = ["skipping", "punching"]
    
    molly["hobbies"].append("reading")
    
    molly["hobbies"] is db.child["hobbies"]
    
 >>>True
    
    assert isinstance(molly, aiootp.AsyncDatabase)
    
    
    # If the user no longer wants a piece of data, pop it out ->
    
    await molly.apop("hobbies")
    
    "hobbies" in molly
    
 >>> False
    
    
    # Delete a child database from the filesystem ->
    
    await db.adelete_metatag("child")
    
    db.child["hobbies"]
    
 >>>AttributeError: 'AsyncDatabase' object has no attribute 'child'
    
    
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
        
        
    # Transparent and automatic encryption makes persisting sensitive 
    
    # information very simple. Though, if users do want to encrypt / 
    
    # decrypt things manually, then databases allow that too ->
    
    data_name = "saturday clients"
    
    clients = ["Tony", "Maria"]
    
    encrypted = await db.aencrypt(filename=data_name, plaintext=clients)
    
    decrypted = await db.adecrypt(filename=data_name, ciphertext=encrypted)
    
    clients == decrypted
    
 >>>True
    
    
    # Encrypted messages have timestamps that can be used to enforce 
    
    # limits on how old messages can be (in seconds) before they are 
    
    # rejected ->
    
    decrypted = await db.adecrypt(data_name, encrypted, ttl=25)
    
 >>> TimeoutError: Timestamp expired by <10> seconds.
    
    
    #




What other tools are available to users?:

.. code:: python

    #
    
    import aiootp   
    
    
    # Async & synchronous versions of almost everything in the library ->
    
    assert await aiootp.asha_512("data") == aiootp.sha_512("data")
    
    key = aiootp.csprng()
    
    assert aiootp.Database(key)._root_filename == (await aiootp.AsyncDatabase(key))._root_filename
    
    
    # Precomputed & organized values that can aid users, like:
    
    # A dictionary of prime numbers grouped by their bit-size ->
    
    aiootp.primes[513][0]    # <- The first 65 byte prime
    
    aiootp.primes[2048][-1]    # <- The last 256 byte prime
    
    
    # Symmetric one-time-pad encryption of json data ->
    
    plaintext = {"account": 3311149, "titles": ["queen b"]}
    
    encrypted = aiootp.json_encrypt(plaintext, key=key)
    
    decrypted = aiootp.json_decrypt(encrypted, key=key)
    
    assert decrypted == plaintext
    
    
    # Symmetric one-time-pad encryption of binary data ->
    
    binary_data = b"This bytes string is also valid plaintext."
    
    encrypted = aiootp.bytes_encrypt(binary_data, key=key)
    
    decrypted = aiootp.bytes_decrypt(encrypted, key=key)
    
    assert decrypted == binary_data
    
    
    # The OneTimePad class carries the key so users don't have to pass
    
    # it around every where ->
    
    pad = aiootp.OneTimePad(key)
    
    encrypted = pad.bytes_encrypt(binary_data)
    
    decrypted = pad.bytes_decrypt(encrypted)
    
    
    # The class also has access to an efficient encoder for saving
    
    # ciphertext to files on disk as bytes ->
    
    path = aiootp.DatabasePath() / "testing_ciphertext"
    
    pad.io.write(path, encrypted)
    
    assert encrypted == pad.io.read(path)
    
    
    # Ratcheting Opaque Password Authenticated Key Exchange (ROPAKE) with 
    
    # online services -> 
    
    uuid = aiootp.sha_256("service-url.com", "username")
    
    db = aiootp.Ropake.client_database(uuid, password, *any_other_credentials)
    
    client = aiootp.Ropake.client_registration(db)
    
    client_hello = client()
    
    server_response = internet.post("service-url.com", json=client_hello)
    
    try:
    
        client(server_response)
        
    except StopIteration:
    
        shared_keys = client.result()
        
        
    # The client is securely registered with the service if there was no 

    # active adversary in the middle, & the user can authenticate & login ->
    
    client = aiootp.Ropake.client(db)
    
    client_hello = client()
    
    server_response = internet.post("service-url.com", client_hello)
    
    try:
    
        client(server_response)
        
    except StopIteration:
    
        shared_keys = client.result()
        
        
    # Upon the first uncompromised registration or authentication, then 

    # future authentications will be immune to adversaries in the middle 

    # because the protocol generates new keys by combining the prior key, 

    # the current ecdhe ephemeral key, & the revealed keyed password that 

    # was transmitted with an extra mask during the prior exchange. The 

    # keyed password authenticates the user & the server to each other when 

    # the commit is revealed, the ephemeral ecdhe key assures future security, 

    # & the prior key encrypts & HMACs the authentication packets which 

    # provides privacy, & added authentication, & the KDF which combines all 

    # these keys ensures forward security.
    
    
    #




Generators under-pin most procedures in the library, let's take a look ->

.. code:: python

    #
    
    
    from aiootp import OneTimePad, json
    
    
    pad = OneTimePad()   # <---Auto-generates an encryption key
    
    salt = pad.salt()    # <---A new salt MUST be used every encryption!
    
    plaintext_bytes = json.dumps({"message": "secretsssss"}).encode()
    
    
    # Yields padded plaintext in chunks of 256 bytes ->
    
    plaintext_stream = pad.plaintext_stream(plaintext_bytes, salt=salt)
    
    
    # An endless stream of forward + semi-future secure hex keys ->
    
    keystream = pad.keys(salt=salt)
    
    
    # xor's the plaintext chunks with key chunks ->
    
    with pad.xor(plaintext_stream.bytes_to_int(), key=keystream) as encrypting:
        
        # ``list`` returns all generator results in a list
        
        ciphertext = encrypting.list()
        
    
    with pad.xor(ciphertext, key=keystream.reset()).int_to_bytes() as decrypting:
        
        decrypted = pad.io.depad_bytes(
        
            decrypting.join(b""), salted_key=pad.padding_key(salt=salt)
            
        )
        
    
    plaintext_bytes == decrypted
    
 >>> True
    
    
    # This example was a low-level look at the encryption algorithm. And it 
    
    # was seven lines of code. The Comprende class makes working with 
    
    # generators a breeze, & working with generators makes solving problems 
    
    # in bite-sized chunks a breeze. ->
    
    ciphertext = aiootp.json_encode(plaintext).encrypt(key, salt=salt).list()
    
    # We didn't pad the plaintext bytes, so we have to remove the null 
    
    # bytes ->
    
    plaintext_json = aiootp.unpack(ciphertext).decrypt(key, salt=salt).join().replace("\x00", "")
    
    
    # We just used the ``list`` & ``join`` end-points to get the full series 

    # of results from the underlying generators. These results are lru-cached 

    # to facilitate their efficient reuse for alternate computations. The 

    # ``Comprende`` context manager clears the opened instance's cache on exit, 

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
    
    def squares(numbers=20):
    
        for number in range(numbers):
        
            yield number ** 2
    
    
    for hashed_square in squares().sha_256():
    
        # This is an example chained generator that hashes then yields each output.
        
        print(hashed_square)
    
    
    # Chained ``Comprende`` generators are excellent inline data processors ->
    
    base64_data = []
    
    for result in squares().str().to_base64():
    
        # This will stringify each output of the generator, then base64 encode them ->
        
        base64_data.append(result)


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
    
    async def squares():
    
        number = 0
        
        while True:
        
            yield number ** 2
            
            number += 1
    
    
    # This is a chained async generator that salts then hashes then yields

    # each output ->
    
    salt = await aiootp.acsprng()
    
    hashed_squares = squares().asha_512(salt)


    # Want only the first twenty results? ->
    
    async for hashed_square in hashed_squares[:20]:
    
        # Then you can slice the generator.
        
        print(hashed_square)
        
        
    # Users can slice generators to receive more complex output rules, like:
    
    # Getting every second result starting from the third result to the 50th ->
    
    async for result in hashed_squares[3:50:2]:
    
        print(result)
    
    
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
        "adelimit_resize",
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
        "amap_decrypt",
        "amap_encrypt",
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
        "delimit_resize",
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
        "map_decrypt",
        "map_encrypt",
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
    
    salt = await aiootp.acsprng()
    
    names = aiootp.akeys(key, salt=salt)
    
    
    # Resize each output of ``names`` to 32 characters, tag each output with
    
    # an incrementing number, & stop the stream after 0.1 seconds ->
    
    async for index, name in names.aresize(32).atag().atimeout(0.1):
    
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
    
    key_stream = aiootp.akeys(key, salt=salt, pid=aiootp.sha_256(key, salt))
    
    
    # And example plaintext ->
    
    plaintext = 100 * b"Some kinda message..."
    
    
    # And let's make sure to clean up after ourselves with a context manager ->
    
    pad_key = aiootp.Keys.padding_key(key, salt=salt)
    
    padded_data = aiootp.pad_bytes(plaintext, salted_key=pad_key)
    
    data_stream = aiootp.adata(padded_data)
    
    async with data_stream.amap_encrypt(names, key_stream) as encrypting:
    
        # ``adata`` takes a sequence, & ``amap_encrypt`` takes two iterables,
        
        # a stream of names for the hash map, & the stream of key material.
        
        ciphertext_hashmap = await encrypting.adict()
        
        
    # Now we'll pick the chunks out in the order produced by ``names`` to 

    # decrypt them ->
    
    ciphertext_stream = aiootp.apick(names, ciphertext_hashmap)
    
    async with ciphertext_stream.amap_decrypt(await key_stream.areset()) as decrypting:
    
        decrypted = await decrypting.ajoin(b"")
        
    assert plaintext == aiootp.depad_bytes(decrypted, salted_key=pad_key)
    
    
    # This is really neat, & makes sharding encrypted data incredibly easy.
    
    
    #




Let's take a deep dive into the low-level xor procedure used to implement the one-time-pad:

.. code:: python

    #
    
    import aiootp
    
    # It is a ``Comprende`` generator ->
    
    @aiootp.comprehension()
    
    # ``data`` is an iterable of 256 byte integers that are either plaintext
    
    # or ciphertext. ``key`` is by default the ``keys`` generator. ->
    
    def xor(data=None, *, key=None):
        
        keystream = key.send
        
        # We use the first output of the keystream as a seed of entropy
        
        # for all key chunks pulled from the generator ->
        
        seed = aiootp.sha_256(keystream(None))
        
        for chunk in data:
            
            # We contantenate two 128 byte key chunks together ->
            
            key_chunk = int(await keystream(seed) + await keystream(seed), 16)
            
            # Then xor the 256 byte key chunk with the 256 byte data chunk ->
            
            result = chunk ^ key_chunk
            
            if result.bit_length() > 2048:
                
                # If the result is for some reason larger than 256 bytes,
                
                # we abort the procedure, & warn the user ->
                
                raise ValueError("Data MUST NOT exceed 256 bytes.")
                
           # Then we yield the result ->
           
            yield result
            
    # This is a very space-efficient algorithm for a one-time-pad that adapts
    
    # dynamically to increased plaintext & ciphertext sizes. Both because 
    
    # it's built on generators, & because an infinite stream of key material
    
    # can efficiently be produced from a finite-sized key & an ephemeral salt.
    
    # This version of the algorithm is much simpler & much more efficient 
    
    # than that from previous versions.
    
    
    #




Here's a quick overview of this package's modules:

.. code:: python

    #
    
    import aiootp
    
    
    # Commonly used constants, datasets & functionality across all modules ->
    
    aiootp.commons
    
    
    # The basic utilities & abstractions of the package's architecture ->
    
    aiootp.generics
    
    
    # This module is responsible for providing entropy to the package ->
    
    aiootp.randoms
    
    
    # The higher-level abstractions used to implement the one-time pad ->
    
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




FAQ
---

**Q: What is the one-time-pad?**

A: It's a provably unbreakable cipher. It's typically thought to be too cumbersome a cipher because it has strict requirements. Key size is one requirement, since keys must be at least as large as the plaintext in order to ensure this unbreakability. We've simplified this requirement by using a forward secret and semi-future secret key ratchet algorithm, with ephemeral salts for each stream, allowing users to securely produce endless streams of key material as needed from a single finite size 512-bit long-term key. This algorithmic approach lends itself to great optimizations, since hash processing hardware/sorftware is continually pushed to the edges of efficiency.


**Q: What do you mean the ``aiootp.keys`` generator produces forward & semi-future secure key material?**

A: The infinite stream of key material produced by that generator has amazing properties. Under the hood it's a ``hashlib.sha3_512`` key ratchet algorithm. It's internal state consists of a seed hash, & three ``hashlib.sha3_512`` objects primed iteratively with the one prior and the seed hash. The first object is updated with the seed, its prior output, and the entropy that may be sent into the generator as a coroutine. This first object is then used to update the last two objects before yielding the last two's concatenated results. The seed is the hash of a primer seed, which itself is the hash of the input key material, a random salt, and a user-defined ID value which can safely distinguish streams with the same key material. This algorithm is forward secure because compromising a future key will not compromise past keys since these hashes are irreversibly constructed. It's also semi-future secure since having a past key doesn't allow you to compute future keys without also compromising the seed hash, and the first ratcheting ``hashlib`` object. Since those two states are never disclosed or used for encryption, the key material produced is future secure with respect to itself only. Full future-security would allow for the same property even if the seed & ratchet object's state were compromised. This feature can, however, be added to the algorithm since the generator itself can receive entropy externally from a user at any arbitrary point in its execution, say, after computing a shared diffie-hellman exchange key.


**Q: How fast is this implementation of the one-time pad cipher?**

A: Well, because it relies on ``hashlib.sha3_512`` hashing to build key material streams, it's rather efficient, encrypting & decrypting about 8 MB/s on a ~1.5 GHz core.


**Q: Why make a new cipher when AES is strong enough?**

A: Although primatives like AES are strong enough for now, there's no guarantee that future hardware or algorithms won't be developed that break them. In fact, AES's theoretical bit-strength has dropped over the years because of hardware and algorithmic developments. It's still considered a secure cipher, but the **one-time pad** isn't considered theoretically "strong enough", instead it's mathematically proven to be unbreakable. Such a cryptographic guarantee is too profound not to develop further into an efficient, accessible standard.


**Q: What size keys does this one-time pad cipher use?**

A: It's been designed to work with 512-bit hexidecimal keys. 


**Q: What's up with the ``AsyncDatabase`` / ``Database``?**

A: The idea is to create an intuitive, pythonic interface to a transparently encrypted and decrypted persistence tool that also cryptographically obscures metadata. It's designed to work with json serializable data, which gives it native support for some basic python datatypes. It needs improvement with regard to disk memory efficiency. So, it's still a work in progress, albeit a very nifty one.


**Q: Why are the modules transformed into ``Namespace`` objects?**

A: We overwrite our modules in this package to have a more fine-grained control over what part of the package's internal state is exposed to users and applications. The goal is make it more difficult for users to inadvertently jeopardize their security tools, and minimize the attack surface available to adversaries. The ``aiootp.Namespace`` class also makes it easier to coordinate and decide the library's UI/UX across the package.