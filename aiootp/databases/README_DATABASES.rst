This file is part of aiootp, an asynchronous one-time-pad based crypto and anonymity library.

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html

Copyright

-  © 2019-2021 Gonzo Investigatory Journalism Agency, LLC <gonzo.development@protonmail.ch>
-  © 2019-2021 Richard Machado <rmlibre@riseup.net>

All rights reserved.




Description
===========

- This file is placed in the default directory for transparently encrypted / decrypted database files.


``Database`` usage examples:

.. code:: python


    import aiootp


    # Make a new user key for encryption / decryption with a fast,

    # cryptographically secure pseudo-random number generator ->

    key = aiootp.csprng()


    # Create a database object with it ->

    db = aiootp.Database(key)


    # Users can also use passwords to open a database, if necessary.

    # Although it's not recommended, here's how to do it ->

    tokens = aiootp.Database.generate_profile_tokens(
        "server_url",     # An unlimited number of arguments can be passed
        "email_address",  # here as additional, optional credentials.
        username="username",
        password="password",
        salt="optional_salt_keyword_argument",
    )

    db = aiootp.Database.generate_profile(tokens)


    # Data within databases are organized by ``tag``s ->

    with db:    #  <---Context saves data to disk when closed

        db["tag"] = {"data": "can be any json serializable object"}

        db["bitcoin"] = "0bb6eee10d2f8f45f8a"

        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}

        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]


    # Access to data is open to the user, so care must be taken

    # not to let external api calls touch the database without

    # accounting for how that can go wrong.


    # Sensitive tags can be hashed into uuids of arbitrary size ->

    clients = db.metatag("clients")

    email_uuids = clients.uuids("emails", size=64)

    for email_address in ["brittany@email.com", "john.doe@email.net"]:

        hashed_tag = email_uuids(email_address)

        clients[hashed_tag] = "client account data"

    db["clients salt"] = email_uuids.result(exit=True)


    # Data of any type can be verified using an hmac ->

    hmac = db.hmac({"id": 1234, "payload": "message"})

    db.test_hmac({"id": 1234, "payload": "message"}, hmac=hmac)

 >>> True

    # Although, datatypes where order of values is not preserved may fail to

    # validate ->

    db.test_hmac({"payload": "message", "id": 1234}, hmac=hmac)

 >>> ValueError: "HMAC of ``data`` isn't valid."


    # Create child databases accessible from the parent by a ``metatag`` ->

    metatag = "child"

    molly = db.metatag(metatag)

    molly["hobbies"] = ["skipping", "punching"]

    molly["hobbies"].append("reading")

    molly["hobbies"] is db.child["hobbies"]

 >>> True

    assert isinstance(molly, aiootp.AsyncDatabase)


    # If the user no longer wants a piece of data, pop it out ->

    molly.pop("hobbies")

    "hobbies" in molly

 >>> False


    # Delete a child database from the filesystem ->

    db.delete_metatag("child")

    db.child["hobbies"]

 >>> AttributeError: 'AsyncDatabase' object has no attribute 'child'


    # Write database changes to disk with transparent encryption ->

    db.save()


    # Make mirrors of databases ->

    new_key = aiootp.csprng()

    new_db = aiootp.Database(new_key)

    new_db.mirror_database(db)

    assert new_db["lawyer"] is db["lawyer"]


    # Or make namespaces out of databases for very efficient lookups ->

    namespace = new_db.into_namespace()

    assert namespace.bitcoin == new_db["bitcoin"]

    assert namespace.lawyer is new_db["lawyer"]


    # Delete a database from the filesystem ->

    db.delete_database()


    # Initialization of a database object is more computationally expensive

    # than entering its context manager. So keeping a reference to a

    # preloaded database is a great idea, either call ``asave`` / ``save``

    # periodically, or open a context with the reference whenever wanting to

    # capture changes to the filesystem ->

    with new_db as db:

        print("Saving to disk...")


    # Transparent and automatic encryption makes persisting sensitive

    # information very simple. Though, if users do want to encrypt /

    # decrypt things manually, then databases allow that too ->

    data_name = "saturday clients"

    clients = ["Tony", "Maria"]

    encrypted = db.encrypt(filename=data_name, plaintext=clients)

    decrypted = db.decrypt(filename=data_name, ciphertext=encrypted)

    clients == decrypted

 >>> True


    # Encrypted messages have timestamps that can be used to enforce

    # limits on how old messages can be (in seconds) before they are

    # rejected ->

    decrypted = db.decrypt(data_name, encrypted, ttl=25)

 >>> TimeoutError: Timestamp expired by <10> seconds.


    #




``AsyncDatabase`` usage examples:

.. code:: python

    import aiootp


    # Make a new user key for encryption / decryption with a fast,

    # cryptographically secure pseudo-random number generator ->

    key = await aiootp.acsprng()


    # Create a database object with it ->

    db = await aiootp.AsyncDatabase(key)


    # Users can also use passwords to open a database, if necessary.

    # Although it's not recommended, here's how to do it ->

    tokens = await aiootp.AsyncDatabase.agenerate_profile_tokens(
        "server_url",     # An unlimited number of arguments can be passed
        "email_address",  # here as additional, optional credentials.
        username="username",
        password="password",
        salt="optional_salt_keyword_argument",
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

 >>> True

    # Although, datatypes where order of values is not preserved may fail to

    # validate ->

    await db.atest_hmac({"payload": "message", "id": 1234}, hmac=hmac)

 >>> ValueError: "HMAC of ``data`` isn't valid."


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


    # Transparent and automatic encryption makes persisting sensitive

    # information very simple. Though, if users do want to encrypt /

    # decrypt things manually, then databases allow that too ->

    data_name = "saturday clients"

    clients = ["Tony", "Maria"]

    encrypted = await db.aencrypt(filename=data_name, plaintext=clients)

    decrypted = await db.adecrypt(filename=data_name, ciphertext=encrypted)

    clients == decrypted

 >>> True


    # Encrypted messages have timestamps that can be used to enforce

    # limits on how old messages can be (in seconds) before they are

    # rejected ->

    decrypted = await db.adecrypt(data_name, encrypted, ttl=25)

 >>> TimeoutError: Timestamp expired by <10> seconds.


    #
