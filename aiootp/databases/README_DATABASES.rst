This file is part of aiootp, an asynchronous pseudo-one-time-pad based crypto and anonymity library.

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html

Copyright

-  © 2019-2021 Gonzo Investigative Journalism Agency, LLC <gonzo.development@protonmail.ch>
-  © 2019-2021 Richard Machado <rmlibre@riseup.net>

All rights reserved.




Description
===========

This file is placed in the default directory for transparently encrypted / decrypted database files. It's a small guide for understanding how to use them properly & what they offer.




Table Of Contents
-----------------

- `Database`_
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

- `AsyncDatabase`_
-
  a) `(async) Ideal Initialization`_
  b) `(async) User Profiles`_
  c) `(async) Tags`_
  d) `(async) Metatags`_
  e) `(async) Basic Management`_
  f) `(async) Mirrors`_
  g) `(async) Namespaces`_
  h) `(async) Public Cryptographic Functions`_

     I. `(async) Encrypt / Decrypt`_
     II. `(async) HMACs`_
     III. `(async) UUIDs`_
     IV. `(async) Passcrypt`_




_`Database`
-----------

The package's ``AsyncDatabase`` & ``Database`` classes are very powerful data persistence utilities. They automatically handle encryption & decryption of user data & metadata, providing a pythonic interface for storing & retrieving any json serializable objects. They're designed to seamlessly bring encrypted bytes at rest, to dynamic objects in use.


_`Ideal Initialization`
^^^^^^^^^^^^^^^^^^^^^^^

Make a new user key with a fast, cryptographically secure pseudo-random number generator. Then this strong 512-bit key can be used to create a database object.

.. code-block:: python

    from aiootp import Keys, Database
    
    
    key = Keys.csprng()

    db = Database(key)
    

_`User Profiles`
^^^^^^^^^^^^^^^^

With User Profiles, passwords may be used instead to open a database. Often, passwords & passphrases contain very little entropy. So, they aren't recommended for that reason. However, profiles provide a succinct way to use passwords more safely. They do this by deriving strong keys from low entropy user input, the memory/cpu hard passcrypt algorithm, & a secret salt which is automatically generated & stored on the user's filesystem.

.. code-block:: python

    # Convert any available user credentials into cryptographic tokens ->

    tokens = Database.generate_profile_tokens(
    
        "server-url.com",     # An unlimited number of arguments can be passed
        
        "address@email.net",  # here as additional, optional credentials.
        
        username="username",
        
        password="password",
        
        salt="optional salt keyword argument",
        
    )


    # Finally, use those special tokens to open a database instance ->

    db = Database.generate_profile(tokens)


_`Tags`
^^^^^^^

Data within databases are primarily organized by Tags. Tags are simply json serializable labels, and the data stored under them can also be any json serializable objects.

.. code-block:: python

    # Open a context to automatically save data to disk when closed ->

    with db:
    
        db["tag"] = {"data": "can be any json serializable object"}
        
        db["hobby"] = db.base64_encode(b"fash smasher")
        
        db["bitcoin"] = "0bb6eee10d2f8f45f8a"
        
        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}
        
        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]


    # Instead of saving the entire database when a single new tag is 

    # added, a tag can be saved to disk individually ->

    db.save_tag("lawyer")


    # View an instance's tags ->

    db.tags
    >>> ['tag', 'hobby', 'bitcoin', 'lawyer', 'safehouses']


    # Set & query tags in the instance's cache with dedicated method ->

    db.set("pseudonym", "Free The People")

    db.query("pseudonym")
    >>> 'Free The People'

    assert "pseudonym" in db


    # Remove a tag from the cache & its associated data on the filesystem ->

    db.pop("pseudonym")
    >>> 'Free The People'

    assert "pseudonym" not in db

Access to data is open to the user, so care must be taken not to let external api calls touch the database without accounting for how that can go wrong.


_`Metatags`
^^^^^^^^^^^

Metatags are used to organize & create children of parent databases. They are fully-fledged databases all on their own, with their own distinct key material too. They're accessible from the parent through an attribute that's added to the parent instance with the same name as the metatag. When the parent is saved, or deleted, then their children are also.

.. code-block:: python

    # Create a metatag database ->

    molly = db.metatag("molly")


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

    db.delete_metatag("molly")
    
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
    
    db.save()


    # Entering the instance's context also saves data to disk ->

    with db:
    
        print("Saving to disk...")
    

    # Delete a database from the filesystem ->
    
    db.delete_database()
    
    
As databases grow in the number of tags, metatags & the size of data within, it may become desireable to load data from them as needed, instead of all at once during initialization. This can be done with the ``preload`` boolean keyword argument.

.. code-block:: python

    # Let's create some test values to show the impact preloading has ->

    with Database(key) as db:

        db["favorite_foods"] = ["justice", "community"]
    
        db.metatag("exercise_routines") 
    

    # This is how to toggle preloading off during initialization ->

    quick_db = Database(key, preload=False)
    
    
   # In synchronous databases, values can still be retrieved using

   # bracketed lookups since they're able to load from disk on demand ->

    with quick_db:
    
        quick_db["favorite_foods"]
        >>> ["justice", "community"]
    
    
        # Metatags need to be loaded manually, though ->
    
        quick_db.exercise_routines
        >>> AttributeError:
    
        quick_db.metatag("exercise_routines")
    
        assert type(quick_db.exercise_routines) == Database


_`Mirrors`
^^^^^^^^^^

Database mirrors allow users to make copies of all files within a database under new encryption keys. This is useful if users simply want to make backups, or if they'd like to update / change their database keys. 

.. code-block:: python

    # A unique login key / credentials are needed to create a new 

    # database ->
    
    new_key = Keys.csprng()
    
    new_db = Database(new_key)


    # Mirroring an existing database is done like this ->
    
    new_db.mirror_database(db)

    assert new_db["favorite_foods"] is db["favorite_foods"]


    # If the user is just updating their database keys, then the old

    # database should be deleted ->

    db.delete_database()


    # Now the new database can be saved to disk & given an appropriate 

    # name ->

    with new_db as db:

        pass


_`Namespaces`
^^^^^^^^^^^^^

Database Tags can be loaded into ``Namespace`` objects. This saves lots of time & cpu effort on lookups. This is because databases use cryptographic hashes of Tags to find their associtated data within themselves. This can be up to a couple thousand times slower than the dotted lookups on a ``Namespace`` object. This is a great way to load lots of encrypted values but then use them very efficiently in calculations.

.. code-block:: python

    # Loading a database's tags into a Namespace is done this way ->

    namespace = db.into_namespace()
    
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

    jciphertext = db.json_encrypt(json_plaintext)

    bciphertext = db.bytes_encrypt(bytes_plaintext)


    # Those values can just as easily be decrypted ->

    assert json_plaintext == db.json_decrypt(jciphertext)

    assert bytes_plaintext == db.bytes_decrypt(bciphertext)


    # Filenames may be added to classify ciphertexts. They also alter the 

    # key material used during encryption in such a way, that without the

    # correct filename, the data cannot be decrypted ->

    filename = "grocery list"

    groceries = ["carrots", "taytoes", "rice", "beans"]

    ciphertext = db.json_encrypt(groceries, filename=filename)

    assert groceries == db.json_decrypt(ciphertext, filename=filename)


    # Time-based expiration of ciphertexts is also available for all 

    # encrypted data this package produces ->

    from aiootp.asynchs import sleep


    sleep(6)

    db.json_decrypt(jciphertext, ttl=2)
    >>> TimeoutError: Timestamp expired by <4> seconds.

    db.bytes_decrypt(bciphertext, ttl=2)
    >>> TimeoutError: Timestamp expired by <4> seconds.


    # The number of seconds that are exceeded may be helpful to know. In

    # which case, this is how to retrieve that integer value ->

    try: 
    
        db.bytes_decrypt(bciphertext, ttl=2)

    except TimeoutError as error:

        seconds_expired_by = error.value


_`HMACs`
********

Besides encryption & decryption, databases can also be used to manually verify the authenticity of data with HMACs.

.. code-block:: python

    # Creating an HMAC of some data with a database is done this way ->

    data = "validate this data!"

    hmac = db.hmac(data)

    db.test_hmac(data, hmac=hmac)
    >>> True


    # Data that is not the same, or is altered, will be caught ->

    altered_data = "valiZate this data!"

    db.test_hmac(altered_data, hmac=hmac)
    >>> ValueError: "HMAC of the data stream isn't valid."
    

    # Any type of data can be run thorugh the function, it's the repr

    # of the data which is evaluated ->

    arbitrary_data = {"id": 1234, "payload": "message"}

    hmac = db.hmac(arbitrary_data)
    
    db.test_hmac(arbitrary_data, hmac=hmac)
    >>> True


    # Beware: Datatypes where order of values is not preserved may fail 

    # to validate even if they are functionally equivalent -> 

    order_swapped_data = {"payload": "message", "id": 1234}

    assert order_swapped_data == arbitrary_data
    
    db.test_hmac(order_swapped_data, hmac=hmac) 
    >>> ValueError: "HMAC of the data stream isn't valid."
    

_`UUIDs`
********

Instances can create special generator coroutines that are used to hash sensitive tags, or other data, into hexidecimal UUIDs of arbitrary size. These hashes are secured with the database instance's keys, & a salt value which is either passed in manually by the user, or if not, is automatically generated. The salt is available at the end of the coroutine's usage by calling for it to be returned & for the coroutine to be exited. 

.. code-block:: python

    # Organizing databases with metatags improves readability & safely 

    # isolates cryptographic domains, because metatags use their own

    # sets of keys. Their keys also can't be used to derive their 

    # parent's keys ->

    db.metatag("clients")


    # Choosing a category for the coroutine also separates domains ->
    
    email_uuids = db.clients.uuids("emails", size=24, salt=None)


    # Then a user can hash any values by sending them into the coroutine ->

    for email_address in ["brittany@email.com", "john.doe@email.net"]:
    
        hashed_tag = email_uuids(email_address)
        
        db.clients[hashed_tag] = "client account data"


    # Once finished hashing, the salt that was used can be retrieved ->
    
    db["clients salt"] = email_uuids.result(exit=True)


_`Passcrypt`
************

``Passcrypt`` is the package's Argon2id-like password-based key derivation function. It was designed to be resistant to time-memory tradeoffs & cache timing side-channel attacks. When passwords (or data in general) are processed through an instance's passcrypt method, then they're also protected by being hashed together with the database's keys.

.. code-block:: python

    # This is an example usage of the databases' passcrypt methods ->

    from getpass import getpass
    

    password = getpass("Enter password: ")

    salt = db.generate_salt()

    db.passcrypt(password, salt)
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

    password_hash = db.passcrypt(password, salt, **settings)


    #




_`AsyncDatabase`
----------------

The package's ``AsyncDatabase`` & ``Database`` classes are very powerful data persistence utilities. They automatically handle encryption & decryption of user data & metadata, providing a pythonic interface for storing & retrieving any json serializable objects. They're designed to seamlessly bring encrypted bytes at rest, to dynamic objects in use.


_`(async) Ideal Initialization`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Make a new user key with a fast, cryptographically secure pseudo-random number generator. Then this strong 512-bit key can be used to create a database object.

.. code-block:: python

    from aiootp import AsyncKeys, AsyncDatabase
    
    
    key = await AsyncKeys.acsprng()

    db = await AsyncDatabase(key)
    

_`(async) User Profiles`
^^^^^^^^^^^^^^^^^^^^^^^^

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


_`(async) Tags`
^^^^^^^^^^^^^^^

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


_`(async) Metatags`
^^^^^^^^^^^^^^^^^^^

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


_`(async) Basic Management`
^^^^^^^^^^^^^^^^^^^^^^^^^^^

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


_`(async) Mirrors`
^^^^^^^^^^^^^^^^^^

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


_`(async) Namespaces`
^^^^^^^^^^^^^^^^^^^^^

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


_`(async) Public Cryptographic Functions`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Although databases handle encryption & decryption automatically, users may want to utilize their databases' keys to do custom cryptographic procedures manually. There are a few public functions available to users if they should want such functionality.


_`(async) Encrypt / Decrypt`
****************************

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


_`(async) HMACs`
****************

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
    

_`(async) UUIDs`
****************

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


_`(async) Passcrypt`
********************

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
