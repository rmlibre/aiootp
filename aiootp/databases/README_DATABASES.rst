This file is part of aiootp, an asynchronous one-time-pad based crypto and anonymity library.

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html

Copyright

-  © 2019-2020 Gonzo Investigatory Journalism Agency, LLC <gonzo.development@protonmail.ch>
-  © 2019-2020 Richard Machado <rmlibre@riseup.net>

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
    
    
    # Create a database object ->
    
    db = aiootp.Database(key)
    
    
    # Store protected data by a ``tag`` ->
    
    tag = "private_account"
    
    salt = db.salt()
    
    # This is a memory & cpu hard function to protect passwords ->
    
    password = db.passcrypt("password012345", salt)
    
    db[tag] = {password: "secured data"}
    
    
    # Add to existing stored data ->
    
    db[tag].update({"salt": salt})
    
    
    # Read from the database with ``aquery`` ->
    
    db.query(tag)[password]
    
 >>>'secured data'
    
    
    # Or use bracketed lookup (it's an async-safe operation) ->
    
    salt = db[tag]["salt"]
    
    wrong_password = db.passcrypt("wrong password attempt", salt)
    
    db[tag][wrong_password]
    
 >>>KeyError: 
    
    
    # Or, pop the value out of the database ->
    
    account_data = db.pop(tag)
    
    
    # Any type & amount of data can be verified with an hmac ->
    
    hmac = db.hmac({"id": 1234, "payload": "message"})
    
    db.test_hmac({"id": 1234, "payload": "message"}, hmac=hmac)
    
 >>>True
    
    # Although, datatypes where order of values is not preserved may fail to 
    
    # validate -> 
    
    db.test_hmac({"payload": "message", "id": 1234}, hmac=hmac) 
    
 >>>ValueError: "HMAC of ``data`` isn't valid." 
    
    
    # Create child databases accessible from the parent by a ``metatag`` ->
    
    metatag = "child"
    
    molly = db.metatag(metatag)
    
    molly["hobbies"] = ["skipping", "punching"]
    
    molly["hobbies"].append("reading")
    
    molly["hobbies"] is db.child["hobbies"]
    
 >>>True
    
    assert isinstance(molly, aiootp.Database)
    
    
    # Write database changes to disk ->
    
    db.save()
    
    
    # Delete a child database from the filesystem ->
    
    db.delete_metatag("child")
    
    db.child["hobbies"]
    
 >>>AttributeError: 'Database' object has no attribute 'child'
    
    
    # Automate the write to disk logic with a context manager ->
    
    with aiootp.Database(key) as db:
    
        db["tag"] = {"data": "can be any json serializable object"}
        
        db["bitcoin"] = "0bb6eee10d2f8f45f8a"
        
        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}
        
        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]
    
    
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
    
 >>>True
    
    
    #




``AsyncDatabase`` usage examples:

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
    
    # This is a memory & cpu hard function to protect passwords ->
    
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
    
    
    # Write database changes to disk ->
    
    await db.asave()
    
    
    # Delete a child database from the filesystem ->
    
    await db.adelete_metatag("child")
    
    db.child["hobbies"]
    
 >>>AttributeError: 'AsyncDatabase' object has no attribute 'child'
    
    
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