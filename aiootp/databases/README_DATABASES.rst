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


    # Make a new user key for encryption / decryption ->
    
    key = aiootp.csprng()    # <- A fast, cryptographically secure pseudo-random number generator


    # Create a database object ->
    
    db = aiootp.Database(key)


    # Store protected data by a ``tag`` ->
    
    tag = "private_account"
    
    salt = db.salt()
    
    hmac = db.hmac("password012345", salt)
    
    db[tag] = {hmac: "secured data"}
    
    
    # Add to existing stored data ->
    
    db[tag].update({"password_salt": salt})
    
    
    # Read from the database with ``query`` ->
    
    db.query(tag)[hmac]
    
 >>>'secured data'
    
    
    # Or use bracketed lookup (it's an async-safe operation) ->
    
    salt = db[tag]["password_salt"]
    
    wrong_hmac = db.hmac("wrong password attempt", salt)
    
    db[tag][wrong_hmac]
    
 >>>KeyError: 
    
    
    # Or, pop the value out of the database ->
    
    account_data = db.pop(tag)
    
    
    # Create child databases accessible from the parent by a ``metatag`` ->
    
    metatag = "child"
    
    molly = db.metatag(metatag)
    
    molly["hobbies"] = ["skipping", "punching"]
    
    molly["hobbies"].append("reading")
    
    molly["hobbies"] is db.child["hobbies"]
    
 >>>True
    
    
    # Write the database changes to disk ->
    
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
    
    
    # Delete a database from the filesystem ->
    
    await db.delete_database()
    
    
    # Initialization of a database object is more computationally expensive than entering its
    
    # context manager. So keeping a reference to a preloaded database is a great idea, either
    
    # call ``asave`` / ``save`` periodically, or open a context with the reference whenever
    
    # wanting to capture changes to the filesystem ->
    
    with new_db as db:
    
        print("Saving to disk...")
    
    
    #




``AsyncDatabase`` usage examples:

.. code:: python
    
    import aiootp


    # Make a new user key for encryption / decryption ->
    
    key = await aiootp.acsprng()    # <- A fast, cryptographically secure pseudo-random number generator


    # Create a database object ->
    
    db = await aiootp.AsyncDatabase(key)


    # Store protected data by a ``tag`` ->
    
    tag = "private_account"
    
    salt = await db.asalt()
    
    hmac = await db.ahmac("password012345", salt)
    
    db[tag] = {hmac: "secured data"}
    
    
    # Add to existing stored data ->
    
    db[tag].update({"password_salt": salt})
    
    
    # Read from the database with ``aquery`` ->
    
    (await db.aquery(tag))[hmac]
    
 >>>'secured data'
    
    
    # Or use bracketed lookup (it's an async-safe operation) ->
    
    salt = db[tag]["password_salt"]
    
    wrong_hmac = await db.ahmac("wrong password attempt", salt)
    
    db[tag][wrong_hmac]
    
 >>>KeyError: 
    
    
    # Or, pop the value out of the database ->
    
    account_data = await db.apop(tag)
    
    
    # Create child databases accessible from the parent by a ``metatag`` ->
    
    metatag = "child"
    
    molly = await db.ametatag(metatag)
    
    molly["hobbies"] = ["skipping", "punching"]
    
    molly["hobbies"].append("reading")
    
    molly["hobbies"] is db.child["hobbies"]
    
 >>>True
    
    
    # Write the database changes to disk ->
    
    await db.asave()
    
    
    # Delete a child database from the filesystem ->
    
    await db.adelete_metatag("child")
    
    db.child["hobbies"]
    
 >>>AttributeError: 'AsyncDatabase' object has no attribute 'child'
    
    
    # Automate the write to disk logic with a context manager ->
    
    async with aiootp.AsyncDatabase(key) as db:
    
        db["tag"] = {"data": "can be any json serializable object"}
        
        db["bitcoin"] = "0bb6eee10d2f8f45f8a"
        
        db["lawyer"] = {"#": "555-555-1000", "$": 13000.50}
        
        db["safehouses"] = ["Dublin Forgery", "NY Insurrection"]
    
    
    # Make mirrors of databases ->
    
    new_key = await aiootp.acsprng()
    
    new_db = await aiootp.AsyncDatabase(new_key)
    
    await new_db.amirror_database(db)
    
    assert new_db["lawyer"] is db["lawyer"]
    
    
    # Delete a database from the filesystem ->
    
    await db.adelete_database()
    
    
    # Initialization of a database object is more computationally expensive than entering its
    
    # context manager. So keeping a reference to a preloaded database is a great idea, either
    
    # call ``asave`` / ``save`` periodically, or open a context with the reference whenever
    
    # wanting to capture changes to the filesystem ->
    
    async with new_db as db:
    
        print("Saving to disk...")
    
    
    #