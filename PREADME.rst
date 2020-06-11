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

    import aiootp
    
    
    # Make a new user key for encryption / decryption with a fast,
    
    # cryptographically secure pseudo-random number generator ->
    
    key = await aiootp.acsprng()
    
    
    # Create a database object ->
    
    db = await aiootp.AsyncDatabase(key)
    
    
    # Store protected data by a ``tag`` ->
    
    tag = "private_account"
    
    salt = await db.asalt()
    
    # This is a tunably memory & cpu hard function to protect passwords ->
    
    password = await db.apasscrypt("password012345", salt)
    
    db[tag] = {password: "secured data"}
    
    
    # Add to existing stored data ->
    
    db[tag].update({"salt": salt})
    
    
    # Read from the database with ``aquery`` ->
    
    (await db.aquery(tag))[password]
    
 >>>'secured data'
    
    
    # Or use bracketed lookup (it's an async-safe operation) ->
    
    salt = db[tag]["salt"]
    
    wrong_password = await db.apasscrypt("wrong password attempt", salt)
    
    db[tag][wrong_password]
    
 >>>KeyError: 
    
    
    # Or, pop the value out of the database ->
    
    account_data = await db.apop(tag)
    
    
    # Any type & amount of data can be verified with an hmac ->
    
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
    
    
    # Write database changes to disk with transparent encryption ->
    
    await db.asave()
    
    
    # Delete a child database from the filesystem ->
    
    await db.adelete_metatag("child")
    
    db.child["hobbies"]
    
 >>>AttributeError: 'AsyncDatabase' object has no attribute 'child'
    
    
    # If tags are also sensitive, they can be safely hashed ->
    
    clients = await db.ametatag("clients")
    
    email_uuids = await clients.auuids("emails", size=32)
    
    for email_address in ["brittany@email.com", "john.doe@email.net"]:
    
        hashed_tag = await email_uuids(email_address)
        
        clients[hashed_tag] = "client account data"
    
    clients["salt"] = await email_uuids.aresult(exit=True)
    
    
    # Automate the write to disk logic with a context manager ->
    
    async with (await aiootp.AsyncDatabase(key)) as db:
    
        db["tag"] = {"data": "can be any json serializable object"}
        
        db["bitcoin"] = "0bb6eee10d2f8f45f8a"
        
        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}
        
        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]
    
    
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
    
    
    # Databases, and the rest of the package, use special generators to 
    
    # process data. Here's a sneak peak at the low-level magic that enables 
    
    # easy processing of data streams ->
    
    import json
    
    datastream = aiootp.ajson_encode(clients)  # <- yields ``clients`` jsonified
    
    # Makes a hashmap of chunks of ciphertext ~256 bytes each ->
    
    async with db.aencrypt_stream(data_name, datastream) as encrypting:
        
        encrypted_hashmap = await encrypting.adict()
        
        # Returns the automatically generated random salt ->
        
        salt = await encrypting.aresult()
        
    
    # Users will need to correctly order the hashmap of ciphertext for
    
    # decryption ->
    
    stream = await db.aciphertext_stream(data_name, encrypted_hashmap, salt)
    
    # Then decryption of the stream is available ->
    
    async with db.adecrypt_stream(data_name, stream, salt) as decrypting:
    
        decrypted = json.loads(await decrypting.ajoin())
        
    assert decrypted == clients
    
    
    #




What other tools are available to users?:

.. code:: python

    import aiootp   
    
    
    # Async & synchronous versions of almost everything in the library ->
    
    assert await aiootp.asha_512("data") == aiootp.sha_512("data")
    
    key = aiootp.csprng()
    
    assert aiootp.Database(key).root_filename == (await aiootp.AsyncDatabase(key)).root_filename
    
    
    # Precomputed & organized values that can aid users, like:
    
    # A dictionary of prime numbers grouped by their bit-size ->
    
    aiootp.primes[512][0]    # <- The first prime greater than 512-bits
    
    aiootp.primes[2048][-1]    # <- The last prime less than 2049-bits
    
    
    # Symmetric one-time-pad encryption of json data ->
    
    plaintext = {"account": 3311149, "titles": ["queen b"]}
    
    encrypted = aiootp.json_encrypt(plaintext, key=key)
    
    decrypted = aiootp.json_decrypt(encrypted, key=key)
    
    assert decrypted == plaintext
    
    
    # Symmetric one-time-pad encryption of binary data ->
    
    binary_data = aiootp.randoms.urandom(256)
    
    encrypted = aiootp.bytes_encrypt(binary_data, key=key)
    
    decrypted = aiootp.bytes_decrypt(encrypted, key=key)
    
    assert decrypted == binary_data
    
    
    # Generators under-pin most procedures in the library ->
    
    from aiootp import json_encode   # <- A simple generator
    
    from aiootp.ciphers import cipher, decipher    # <- Also simple generators
    
    
    # Yields plaintext json string in chunks ->
    
    plaintext_generator = json_encode(plaintext)
    
    
    # An endless stream of forward + semi-future secure hashes ->
    
    keystream = aiootp.keys(key)
    
    
    # xor's the plaintext chunks with key chunks ->
    
    with aiootp.cipher(plaintext_generator, keystream) as encrypting:
    
        # ``list`` returns all generator results in a list
    
        ciphertext = encrypting.list()
        
    # Get the auto generated random salt back. It's needed for decryption ->
    
    ciphertext_seed_entropy = keystream.result(exit=True)
    
    
    # This example was a low-level look at the encryption algorithm. And it 

    # was seven lines of code. The Comprende class makes working with 

    # generators a breeze, & working with generators makes solving problems 

    # in bite-sized chunks a breeze. Here's the two-liner that also takes 

    # care of managing the random salt ->
    
    ciphertext = aiootp.json_encode(plaintext).encrypt(key).list()
    
    plaintext_json = aiootp.unpack(ciphertext).decrypt(key).join()
    
    
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
        "_agetitem",  # These getitem methods are accessible from an
        "_getitem",   # instance's ``__getitem__`` bracket lookup syntax.
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
    
    names = aiootp.akeys(key, salt)
    
    
    # Resize each output of ``names`` to 32 characters, tag each output with
    
    # an incrementing number, & stop the stream after 0.1 seconds ->
    
    async for index, name in names.aresize(32).atag().atimeout(0.1):
    
        ordered_entries[name] = f"{index} data organized by the stream of hashes"
    
    
    # Retrieving items in the correct order requires knowing both ``key`` & ``salt``
    
    async for index, name in aiootp.akeys(key, salt).aresize(32).atag():
    
        try:
        
            assert ordered_entries[name] == f"{index} data organized by the stream of hashes"
            
        except KeyError:
        
            print(f"There are no more entries after {index} iterations.")
            
            assert index == len(ordered_entries) + 1
            
            break
            
            
    # There's a prepackaged ``Comprende`` generator function that does
    
    # encryption / decryption of key ordered hash maps. First let's make an
    
    # actual encryption key stream that's different from ``names`` ->
    
    key_stream = aiootp.akeys(key, salt, pid=aiootp.sha_256(key, salt))
    
    
    # And example plaintext ->
    
    plaintext = 100 * "Some kinda message..."
    
    
    # And let's make sure to clean up after ourselves with a context manager ->
    
    data_stream = aiootp.adata(plaintext)
    
    async with data_stream.amap_encrypt(names, key_stream) as encrypting:
    
        # ``adata`` takes a sequence, & ``amap_encrypt`` takes two iterables,
        
        # a stream of names for the hash map, & the stream of key material.
        
        ciphertext_hashmap = await encrypting.adict()
        
        
    # Now we'll pick the chunks out in the order produced by ``names`` to 

    # decrypt them ->
    
    ciphertext_stream = aiootp.apick(names, ciphertext_hashmap)
    
    async with ciphertext_stream.amap_decrypt(key_stream) as decrypting:
    
        decrypted = await decrypting.ajoin()
        
    assert decrypted == plaintext
    
    
    # This is really neat, & makes sharding encrypted data incredibly easy.
    
    
    #




Let's take a deep dive into the low-level xor procedure used to implement the one-time-pad:

.. code:: python
    
    import aiootp
    
    # It is a ``Comprende`` generator ->
    
    @aiootp.comprehension()
    
    # ``datastreams`` are typically just a single iterable of integers that
    
    # are either plaintext or ciphertext. ``key`` is by default the ``keys``
    
    # generator. ``buffer_size`` is by default ``10**20``, which represents 
    
    # how many (20) of the most significant decimal digits in each integer 
    
    # key produced will be excluded from use for xoring. This is necessary 
    
    # because the first digits in a ``int(key, 16)`` converted key are less 
    
    # random than the least significant digits. 20 decimal digits is roughly 
    
    # 64-bits ->
    
    def xor(*datastreams, key=None, buffer_size=aiootp.power10[20], convert=True):
    
        # ``convert`` is an optional flag to allow users to pass a preconverted
        
        # interable of integer key material ->
        
        if convert:
        
            entropy = key.int(16)
            
        else:
            
            entropy = key
            
        # If more than one iterable of plaintext or ciphertext integers are 
        
        # passed, then they're processed one at a time here. Reversing the 
        
        # procedure when more than one data stream is used is not supported ->
        
        for items in zip(*datastreams):
        
            # Initialize the result. Anything xor'd by 0 returns itself ->
        
            result = 0
            
            for item in items:
            
                # For each element of each plaintext or ciphertext iterable,
                
                # a seed is cached to increase efficiency when growing the key ->
            
                seed = entropy() * entropy()
                
                # Each time ``entropy`` is called, it pulls 2 sha3_512 hashes
                
                # from the forward + semi-future secure key stream whose 
                
                # concatenated digests are integer converted & multiplied with
                
                # another pair of hashes from the stream. This creates keys of 
                
                # sizes that are multiples of 2048-bits. The new key is then 
                
                # xor'd with the 2048-bit seed to prevent any cryptanalysis 
                
                # involving factoring the multiplication ->
                
                current_key = seed ^ (entropy() * entropy())
                
                # The resulting key is then xor'd with the plaintext or 
                
                # ciphertext element ->
                
                tested = item ^ current_key
                
                # And the size of the item is increased by the buffer to account
                
                # for the less random most significant bits ->
                
                item_size = item * buffer_size
                
                # Next, the key is grown to be larger than the plaintext element
                
                # or, if the reverse operation is being done on ciphertext, then
                
                # the growth is stopped if a plaintext is revealed, since the
                
                # plaintext is always smaller than the key. Multiplying ``tested``
                
                # by 100 gets rid of rounding errors, as sometimes xor'ing two
                
                # integers can result in a number that's larger than both of them
                
                # by one significant digit.
                
                while tested * 100 > current_key and item_size > current_key:
                
                    # If the key needs to grow again, then the current key is
                    
                    # multiplied by another 2048-bit compund key & the result 
                    
                    # is xor'd with the seed to eliminate the potential of
                    
                    # factoring the result ->
                    
                    current_key = seed ^ (current_key * entropy() * entropy())
                    
                    # We then reset ``tested`` to test until plaintext is revealed
                    
                    # or, an appropriate ciphertext is made ->
                    
                    tested = item ^ current_key
                    
                # If the procedure succeeds in either case, the result is stored
                
                # or, yielded when there are no more elements in the zipped
                
                # datastream iteration ->
                
                result ^= tested
                
            yield result
            
    # This is a very space-efficient algorithm for a one-time-pad that adapts
    
    # dynamically to increased plaintext or ciphertext sizes. Both because 
    
    # it's built on generators, & because an infinite stream of key material
    
    # can efficiently be produced from a finite-sized key & an ephemeral salt.
    
    
    #




Here's a quick overview of this package's modules:

.. code:: python
    
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