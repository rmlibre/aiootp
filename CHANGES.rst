``Known Issues``
=================

-  The test suite for this software is under construction, & what tests
   have been published are currently inadequate to the needs of
   cryptography software.
-  This package is currently in beta testing. Contributions are welcome.
   Send us a message if you spot a bug or security vulnerability:
   
   -  < gonzo.development@protonmail.ch >
   -  < 31FD CC4F 9961 AFAC 522A 9D41 AE2B 47FA 1EF4 4F0A >




``Changelog``
=============


Changes for version 0.15.0 
========================== 


Major Changes 
------------- 

-  Security Patch: The previous update left the default salt stored by
   the ``Ropake`` class on the user filesystem as an empty string  for
   new files that were created since the ``asalt`` & ``salt`` functions
   were switched to producing 256-bit values instead of 512-bits. This
   bug has now been fixed.
-  An 8 byte timestamp is now prepended to each plaintext during the
   padding step. The decryption functions now take a ``ttl`` kwarg which
   will measure & enforce a time-to-live for ciphertexts under threat of
   ``TimeoutError``.
-  Added new profile feature to the database classes. This standardizes
   & simplifies the process for users to open databases using only 
   low-entropy "profile" information such as ``username``, ``password``,
   ``*credentials`` & an optional ``salt`` a user may have access to. 
   The new ``agenerate_profile_tokens``, ``generate_profile_tokens``, 
   ``agenerate_profile``, ``generate_profile``, ``aprofile_exists``, 
   ``profile_exists``, ``aload_profile``, ``load_profile``, ``adelete_profile``
   & ``delete_profile`` functions are the public part of this new feature.
-  Some more database class attributes have been turned private to clean
   up the api.
-  Fixed typo in ``__exit__`` method of ``Database`` class which referenced 
   a method which had its name refactored, leading to a crash.
-  Shifted the values in the ``primes`` dictionary such that the key for
   each element in the dictionary is the exclusive maximum of each prime
   in that element. Ex: primes[512][-1].to_bytes(64, "big") is now valid.
   Whereas before, primes[512] was filled with primes that were 64 bytes
   and 1 bit long, making them 65 byte primes. This changes some of the
   values of constants in the package & therefore some values derived 
   from those constants.
-  Slimmed down the number of elements in the ``primes`` & ``bits`` 
   dictionaries, reducing the size of the package a great deal. ``primes``
   now contains two primes in each element, the first is the minimum 
   prime of that bit length, the latter the maximum.
-  Added ``URLSAFE_TABLE`` to the package.
-  Made ``salt`` & ``pid`` & ``ttl`` keyword only arguments in key


Minor Changes 
------------- 

-  Added ``this_second`` function to ``asynchs`` module for integer time.
-  Added ``apadding_key``, ``padding_key``, ``aplaintext_stream`` & 
   ``plaintext_stream`` functions to the ``ciphers`` module.
-  Added ``apadding_key``, ``padding_key`` to the ``keygens`` module &
   ``AsyncKeys`` & ``Keys`` classes.
-  Added ``axi_mix``, ``xi_mix``, ``acheck_timestamp``, ``check_timestamp``,
   to the ``generics`` module.
-  Added ``acsprbg``, ``csprbg``, ``asalt``, ``salt``, ``apadding_key``, 
   ``padding_key``, ``aplaintext_stream`` & ``plaintext_stream`` functions
   to OneTimePad class as ``staticmethod``s.
-  Added ``acheck_timestamp`` & ``check_timestamp`` functions to the 
   ``BytesIO`` class.
-  Added ``adeniable_filename`` & ``deniable_filename`` to the ``paths`` 
   module. 
-  Removed check for falsey data in encryption functions. Empty data is 
   & should be treated as valid plaintext.
-  Various refactorings, docstring fixes & efficiency improvements.
-  Added some new tests for database profiles.




Changes for version 0.14.0 
========================== 


Major Changes 
------------- 

-  Security patch: The ``apad_bytes``, ``pad_bytes``, ``adepad_bytes`` &
   ``depad_bytes`` functions were changed internally to execute in a
   more constant time. The variations were small for 256-byte buffers
   (the default), but can grow very wide with larger buffers. The salt
   in the package's encryption utilities is now used to derive the 
   plaintext's padding, making each padding unique. 
-  Unified the types of encodings the library's encryption functions
   utilize for producing ciphertext. This includes databases. They now
   all use the ``LIST_ENCODING``. This greatly increases the efficiency
   of the databases' encryption/decryption, save/load times. And this
   encoding is more space efficient. This change is backwards
   incompatible.
-  The ``LIST_ENCODING`` specification was also changed to produce
   smaller ciphertexts. The salt is no longer encrypted & included as
   the first 256 byte chunk of ciphertext. It is now packaged along with
   ciphertext in the clear & is restricted to being a 256-bit hex
   string.
-  The interfaces for the ``Database`` & ``AsyncDatabase`` were cleaned
   up. Many attributes & functions that were not intended as the public
   interface of the classes were made "private". Also, the no longer
   used utilities for encrypting & decrypting under the MAP_ENCODING
   were removed.
-  Updated the ``abytes_xor``, ``bytes_xor``, ``axor`` & ``xor`` generators 
   to shrink the size of the ``seed`` that's fed into the ``keystream``. This
   allows the one-time-pad cipher to be more cpu efficient.


Minor Changes 
------------- 

-  Fixed various typos, docstrings & tutorials that have no kept up
   with the pace of changes.
-  Various refactorings throughout.
-  The ``akeypair`` & ``keypair`` functions now produce a ``Namespace``
   populated with a 512-bit hex key & a 256-bit hex salt to be more
   consistent with their intended use-case with the one-time-pad cipher.
-  Removed ``aencode_salt``, ``encode_salt``, ``adecode_salt`` & 
   ``decode_salt`` functions since they are no longer used in conjunction
   with LIST_ENCODING ciphertexts.
-  Updated tests to recognize these changes.
-  Gave the ``OneTimePad`` class access to a ``BytesIO`` object under a
   new ``io`` attribute.




Changes for version 0.13.0 
========================== 


Major Changes 
------------- 

-  Security Patch: ``xor`` & ``axor`` functions that define the 
   one-time-pad cipher had a vulnerability fixed that can leak <1-bit of
   plaintext. The issue was in the way keys were built, where the
   multiplicative products of two key segments were xor'd together. This
   lead to keys being slightly more likely to be positive integers, 
   meaning the final bit had a greater than 1/2 probability of being a 
   ``0``. The fix is accompanied with an overhaul of the one-time-pad 
   cipher which is more efficient, faster, & designed with a better 
   understanding of the way bytes are processed & represented. The key
   chunks now do not, & must not, surpass 256 bytes & neither should 
   any chunk of plaintext output. Making each chunk deterministically 
   256 bytes allows for reversibly formatting ciphertext to & from 
   bytes-like strings. These changes are backwards incompatible with 
   prior versions of this package & are strongly recommended.
-  Added ``bytes_xor`` & ``abytes_xor`` functions which take in key 
   generators which produce key segments of type bytes instead of hex 
   strings.
-  ``AsyncDatabase`` & ``Database`` now save files in bytes format,
   making them much more efficient on disk space. They use the new
   ``BytesIO`` class in the ``generics`` module to transparently convert
   to & from json & bytes. This change is also not backwards compatible.
-  Removed ``acipher``, ``cipher``, ``adecipher``, ``decipher``,
   ``aorganize_encryption_streams``, ``organize_encryption_streams``,
   ``aorganize_decryption_streams``, ``organize_decryption_streams``,
   ``aencrypt``, ``encrypt``, ``adecrypt``, ``decrypt``, ``asubkeys`` &
   ``subkeys`` generators from the ``ciphers`` module & package to slim 
   down the code, remove repetition & focus on the cipher tools that 
   include hmac authentication.
-  Removed deprecated diffie-hellman methods in ``Ropake`` class. 
-  Removed the static ``power10`` dictionary from the package.
-  The default secret salt for the ``Ropake`` class is now derived from the 
   contents of a file that's in the databases directory which is chmod'd to 
   0o000 unless needed. 
-  Made ``aclient_message_key``, ``client_message_key``, ``aserver_message_key``, 
   & ``server_message_key`` ``Ropake`` class methods to help distinguish 
   client-to-server & server-to-client message keys which prevents replay 
   attacks on the one-message ROPAKE protocol. 
-  Added protocol coroutines to the ``Ropake`` class which allow for easily
   engaging in 2DH & 3DH elliptic curve exchanges for servers & clients.
-  Efficiency improvements to the ``aseeder`` & ``seeder`` generator functions
   in the ``randoms`` module. This affects the ``acsprng`` & ``csprng`` objects
   & all the areas in the library that utilize those objects.
-  Changed the repr behavior of ``Comprende`` instances to redact all args &
   kwargs by default to protect cryptographic material from unintentionally
   being displayed on user systems. The repr can display full contents by 
   calling the ``enable_debugging`` method of the ``DebugControl`` class.
-  All generator functions decorated with ``comprehension`` are now given
   a ``root`` attribute. This allows direct access to the function without
   needing to instantiate or run it as a ``Comprende`` object. This saves 
   a good deal of cpu & time in the overhead that would otherwise be 
   incurred by the class. This is specifically more helpful in tight &/or
   lower-level looping.


Minor Changes 
------------- 

-  Various refactorings across the library. 
-  Fixed various typos, bugs & inaccurate docstrings throughout the library.
-  Add ``chown`` & ``chmod`` functions to the ``asynchs.aos`` module. 
-  Now makes new ``multiprocessing.Manager`` objects in the ``asynchs.Processes`` 
   & ``asynchs.Threads`` classes to avoid errors that occur when using a stale 
   object whose socket connections are closed. 
-  Changed ``Ropake`` class' ``adb_login`` & ``db_login`` methods to 
   ``adatabase_login_key`` & ``database_login_key``. Also, fix a crash bug in 
   those methods. 
-  Changed ``Ropake`` class' ``aec25519_pub``, ``ec25519_pub``, ``aec25519_priv`` 
   & ``ec25519_priv`` methods to ``aec25519_public_bytes``, ``ec25519_public_bytes``, 
   ``aec25519_private_bytes`` & ``ec25519_private_bytes``. 
-  Added low-level private methods to ``Ropake`` class which do derivation 
   & querying of the default class key & salt. 
-  Behavior changes to the ``ainverse_int`` & ``inverse_int`` functions in the 
   ``generics`` module to allow handling bases represented in ``str`` or ``bytes`` 
   type strings. 
-  Behavior & name changes to the ``abinary_tree`` & ``binary_tree`` functions in the 
   ``generics`` module to ``abuild_tree`` & ``build_tree``. They now allow making 
   uniform trees of any width & depth, limited only by the memory in a 
   user's machine. 
-  Provided new ``acsprbg`` & ``csprbg`` objects to the library that return 512-bits 
   of cryptographically secure pseudo-random ``bytes`` type strings. They are 
   made by the new ``abytes_seeder`` & ``bytes_seeder`` generators. 
-  The ``csprng``, ``acsprng``, ``csprbg`` & ``acsprbg`` objects were 
   wrapped in functions that automatically restart the generators if they're
   stalled / interrupted during a call. This keeps the package from melting
   down if it can no longer call the CSPRNGs for new entropy.
-  Cleaned up & simplified ``table_key`` functions in the ``keygens`` module. 
-  Changed the output of ``asafe_symm_keypair`` & ``safe_symm_keypair`` functions 
   to contain bytes values not their hex-only representation. Also removed 
   these functions from the main imports of the package since they are slow 
   & their main contribution is calling ``arandom_number_generator`` & 
   ``random_number_generator`` to utilize a large entropy pool when starting
   CSPRNGs.
-  Added new values to the ``bits`` dictionary.
-  Added ``apad_bytes``, ``pad_bytes``, ``adepad_bytes`` & ``depad_bytes``
   functions which use ``shake_256`` to pad/depad plaintext bytes to & from
   multiples of 256 bytes. They take in a key to create the padding. 
   This method is intended to also aid in protecting against padding
   oracle attacks.




Changes for version 0.12.0 
========================== 


Major Changes 
------------- 

-  The OPAKE protocol was renamed to ROPAKE, an acronym for Ratcheting 
   Opaque Password Authenticated Key Exchange. This change was necessary 
   since OPAKE is already a name for an existing PAKE protocol. This change 
   also means the ``Opake`` class name was changed to ``Ropake``. 
-  The ``Ropake`` class' registration algorithm was slightly modified to 
   use the generated Curve25519 ``shared_key`` an extra time in the key 
   derivation process. This shouldn't break any currently authenticated 
   sessions. 
-  The ``asyncio_contextmanager`` package is no longer a listed dependency 
   in ``setup.py``. The main file from that package was copied over into the 
   ``/aiootp`` directory in order to remove the piece of code that caused 
   warnings to crop up when return values were retrieved from async 
   generators. This change will put an end to this whack-a-mole process of 
   trying to stop the warnings with try blocks scattered about the codebase. 
-  Added ``asave_tag``, ``save_tag``, ``asave_file`` & ``save_file`` methods 
   to the database classes so that specific entries can be saved to disk 
   without having to save the entire database which is much more costly. The 
   manifest file isn't saved to disk when these methods are used, so if a 
   tag file isn't already saved in the database, then the saved files will 
   not be present in the manifest or in the cache upon subsequent loads of 
   the database. The saved file will still however be saved on the 
   filesystem, though unbeknownst to the database instance.
-  The ``Namespace`` class now redacts all obvious key material in instance 
   repr's, which is any 64+ hex character string, or any number with 64+ 
   decimal digits. 
-  Removed the experimental recursive value retrieval within ``Comprende``'s 
   ``__aexamine_sent_exceptions`` & ``__examine_sent_exceptions`` methods. 
   This change leads to more reliable & faster code, in exchange for an 
   unnecessary feature being removed. 
-  Bug fix of the ``auuids`` & ``uuids`` methods by editing the code in 
   the ``asyncio_contextmanager`` dependency & using the patched package 
   instead of the ``comprehension`` decorator for the ``arelay`` & ``relay`` 
   methods of ``Comprende``. Their internal algorithms was also updated to 
   be simpler, but are incompatible with the outputs of past versions of 
   these methods. 


Minor Changes 
------------- 

-  Various refactorings & documentation additions / modifications throughout 
   the library. 
-  Various small bug fixes.
-  The shared keys derived from the ``Ropake`` protocol are now returned in 
   a ``Namespace`` object instead of a raw dictionary, which allows the 
   values to be retrieved by dotted &/or bracketed lookup. 
-  The ``atest_hmac`` & ``test_hmac`` algorithms / methods were made more 
   efficient & were refactored. Now they call ``atime_safe_equality`` &
   ``time_safe_equality`` internally, which are new methods that can apply
   the non-constant time but randomized timing comparisons on any pairs of
   values.




Changes for version 0.11.0 
========================== 


Major Changes 
------------- 

-  The Opake protocol was made greatly more efficient. This was done by 
   replacing the diffie-hellman verifiers with a hash & xor commit & reveal
   system. Most hashing was made more efficient my using quicker & smaller
   ``sha_512`` function instead of ``nc_512``, & streamlining the protocol.
-  The ``Opake.client`` & ``Opake.client_registration`` methods now take
   an instantiated client database instead of client credentials which 
   improves security, efficiency & usability. This change reduces the amount
   of exposure received by user passwords & other credentials. It also 
   simplifies usage of the protocol by only needing to carry around a 
   database instead of a slew of credentials, which is also faster, since
   the credentials are passed through the cpu & memory hard ``passcrypt``
   function everytime to open the database.


Minor Changes 
------------- 

-  Heavy refactorings & documentation additions / modifications of the 
   ``Opake`` class. Removed the ``Opake.ainit_database`` & ``Opake.init_database``
   methods, & made the ``salt`` default argument parameter in 
   ``Opake.aclient_database``, ``Opake.client_database``, ``Opake.adb_login`` &
   ``Opake.db_login`` into a keyword only argument so any extra user defined
   ``credentials`` are able to be passed without specifying a salt.
-  The decorators for the ``Comprende.arelay`` & ``Comprende.relay`` methods 
   were changed from ``@asyncio_contextmanager.async_contextmanager`` to
   ``@comprehension()`` to stop that package from raising exceptions when
   we retrieve return values from async generators.




Changes for version 0.10.1 
========================== 


Major Changes 
------------- 

-  Added ``Processes`` & ``Threads`` classes to ``asynchs.py`` which abstract 
   spawning & getting return values from async & sync functions intended to 
   be run in threads, processes or pools of the former types. This simplifies 
   & adds time control to usages of processes & threads throughout the 
   library. 
-  Reduced the effectiveness of timing analysis of the modular exponentiation 
   in the ``Opake`` class' verifiers by making the process return values 
   only after discrete intervals of time. Timing attacks on that part of the 
   protocol may still be viable, but should be significantly reduced. 
-  Bug fix in ``Comprende`` which should take care of warnings raised from 
   the ``aiocontext`` package when retrieving async generator values by 
   raising ``UserWarning`` within them. 


Minor Changes 
------------- 

-  Heavy refactorings of the ``Opake`` class. 
-  Various refactorings & cleanups around the package. 
-  Further add ``return_exceptions=True`` flag to gather calls in ``ciphers.py``. 
-  Added ``is_registration`` & ``is_authentication`` which take a client 
   hello message that begin the ``Opake`` protocol, & return ``False`` if 
   the message is not either a registration or authentication message, 
   respectively, & return ``"Maybe"`` otherwise, since these functions can't 
   determine without running the protocol whether or not the message is 
   valid. 




Changes for version 0.10.0 
========================== 


Major Changes 
------------- 

-  Added a new oblivious, one-message, password authenticated key exchange 
   protocol class in ``aiootp.ciphers.Opake``. It is a first attempt at the 
   protocol, which works rather well, but may be changed or cleaned up in a 
   future update. 
-  Added the ``cryptography`` package as a dependency for elliptic curve 
   25519 diffie-hellman key exchange in the ``Opake`` protocol. 
-  Fix buggy data processing functions in ``generics.py`` module. 
-  Added ``silent`` flag to ``AsyncDatabase`` & ``Database`` methods, which 
   allows their instances to finish initializing even if a file is missing 
   from the filesystem, normally causing a ``FileNotFoundError``. This makes 
   trouble-shooting corrupted databases easier. 
-  Added new ``aiootp.paths.SecurePath`` function which returns the path to 
   a unique directory within the database's default directory. The name of 
   the returned directory is a cryptographic value used to create & open the 
   default database used by the ``Opake`` class to store the cryptographic 
   salt that secures the class' client passwords. It's highly recommended 
   to override this default database by instantiating the Opake class with 
   a custom user-defined key. The instance doesn't need to be saved, since 
   all the class' methods are either class or static methods. The ``__init__`` 
   method only changes the class' default database to one opened with the 
   user-defined ``key`` &/or ``directory`` kwargs, & should really only be 
   done once at the beginning of an application. 


Minor Changes 
------------- 

-  Various refactorings & cleanups around the package. 
-  Added ``Comprende`` class feature to return the values from even the 
   generators within an instance's arguments. This change better returns 
   values to the caller from chains of ``Comprende`` generators. 
-  Fixed ``commons.BYTES_TABLE`` missing values. 
-  Added ``commons.DH_PRIME_4096_BIT_GROUP_16`` & ``commons.DH_GENERATOR_4096_BIT_GROUP_16`` 
   constants for use in the ``Opake`` protocol's public key verifiers. 
-  Added other values to the ``commons.py`` module. 
-  Added new very large no-collision hash functions to the ``generics.py`` 
   module used to xor with diffie-hellman public keys in the ``Opake`` class. 
-  Added new ``wait_on`` & ``await_on`` ``Comprende`` generators to ``generics.py`` 
   which waits for a queue or container to be populated & yields it whenever 
   it isn't empty. 




Changes for version 0.9.3 
========================= 


Major Changes 
------------- 

-  Speed & efficiency improvements in the ``Comprende`` class & ``azip``. 


Minor Changes 
------------- 

-  Various refactorings & code cleanups.
-  Added ``apop`` & ``pop`` ``Comprende`` generators to the library.
-  Switched the default character table in the ``ato_base``, ``to_base``, 
   ``afrom_base``, & ``from_base`` chainable generator methods from the 62
   character ``ASCII_ALPHANUMERIC`` table, to the 95 character ``ASCII_TABLE``.
-  Made the digits generators in ``randoms.py`` automatically create a new
   cryptographically secure key if a key isn't passed by a user.
-  Some extra data processing functions added to ``generics.py``.




Changes for version 0.9.2 
========================= 


Major Changes 
------------- 

-  Added ``passcrypt`` & ``apasscrypt`` instance methods to ``OneTimePad``,
   ``Keys``, & ``AsyncKeys`` classes. They produce password hashes that are
   not just secured by the salt & passcrypt algorithm settings, but also by
   their main symmetric instance keys. This makes passwords infeasible to
   crack without also compromising the instance's 512-bit key.


Minor Changes 
------------- 

-  Further improvements to the random number generator in ``randoms.py``.
   Made its internals less sequential thereby raising the bar of work needed
   by an attacker to successfully carry out an order prediction attack.
-  Added checks in the ``Passcrypt`` class to make sure both a salt & 
   password were passed into the algorithm.
-  Switched ``PermissionError`` exceptions in ``Passcrypt._validate_args``
   to ``ValueError`` to be more consistent with the rest of the class.
-  Documentation updates / fixes.




Changes for version 0.9.1 
========================= 


Minor Changes 
------------- 

-  Now any falsey values for the ``salt`` keyword argument in the library's 
   ``keys``, ``akeys``, ``bytes_keys``, ``abytes_keys``, ``subkeys``, & 
   ``asubkeys`` infinite keystream generators, & other functions around the 
   library, will cause them to generate a new cryptographically secure 
   pseudo-random value for the salt. It formerly only did this when ``salt`` 
   was ``None``. 
-  The ``seeder`` & ``aseeder`` generators have been updated to introduce 
   512 new bits of entropy from ``secrets.token_bytes`` on every iteration 
   to ensure that the CSPRNG will produce secure outputs even if its 
   internal state is somehow discovered. This also allows for simply calling 
   the CSPRNG is enough, there's no longer a strong reason to pass new 
   entropy into it manually, except to add even more entropy as desired.
-  Made ``size`` the last keywordCHECKSUMS.txt argument in ``encrypt`` & 
   ``aencrypt`` to better mirror the signatures for rest of the library. 
-  Added ``token_bits`` & ``atoken_bits`` functions to ``randoms.py`` which 
   are renamings of ``secrets.randbits``. 
-  Refactored & improved the security og ``randoms.py``'s random number 
   generator. 




Changes for version 0.9.0 
========================= 


Major Changes 
------------- 

-  Added hmac codes to ciphertext for the following functions: ``json_encrypt``, 
   ``ajson_encrypt``, ``bytes_encrypt``, ``abytes_encrypt``, 
   ``Database.encrypt`` & ``AsyncDatabase.aencrypt``. This change greatly 
   increases the security of ciphertext by ensuring it hasn't been modified 
   or tampered with maliciously. One-time pad ciphertext is maleable, so 
   without hmac validation it can be changed to successfully allow 
   decryption but return the wrong plaintext. These functions are the 
   highest level abstractions of the library for encryption/decryption, 
   which made them excellent targets for this important security update. 
   As well, it isn't easily possible for the library to provide hmac codes 
   for generators that produce ciphertext, because the end of a stream of 
   ciphertext isn't known until after the results have left the scope 
   of library code. So users will need to produce their own hmac codes for 
   generator ciphertext unless we find an elegant solution to this issue. 
   These functions now all return dictionaries with the associated hmac 
   stored in the ``"hmac"`` entry. The bytes functions formerly returned 
   lists, now their ciphertext is available from the ``"ciphertext"`` entry. 
   And, all database files will have an hmac attached to them now. These 
   changes were designed to still be compatible with old ciphertexts but 
   they'll likely be made incompatible by the v0.11.x major release. 
-  Only truthy values are now valid ``key`` keyword arguments in the 
   library's ``keys``, ``akeys``, ``bytes_keys``, ``abytes_keys``, ``subkeys``, 
   & ``asubkeys`` infinite keystream generators. Also now seeding extra entropy 
   into ``csprng`` & ``acsprng`` when ``salt`` is falsey within them. 
-  Only truthy values are now valid for ``password`` & ``salt`` arguments in 
   ``apasscrypt``, ``passcrypt`` & their variants. 


Minor Changes 
------------- 

-  Updates to documentation & ``README.rst`` tutorials.
-  The ``kb``, ``cpu``, & ``hardness`` arguments in ``sum_passcrypt`` &
   ``asum_passcrypt`` chainable generator methods were switched to keyword
   only arguments.




Changes for version 0.8.1 
========================= 


Major Changes 
------------- 

-  Added ``sum_passcrypt`` & ``asum_passcrypt`` chainable generator methods 
   to ``Comprende`` class. They cumulatively apply the passcrypt algorithm 
   to each yielded value from an underlying generator with the passcrypt'd 
   prior yielded result used as a salt. This allows making proofs of work, 
   memory & space-time out of iterations of the passcrypt algorithm very 
   simple. 


Minor Changes 
------------- 

-  Various inaccurate docstrings fixed. 
-  Various refactorings of the codebase. 
-  Made ``kb``, ``cpu``, & ``hardness`` arguments into keyword only arguments 
   in ``AsyncDatabase`` & ``Database`` classes. 
-  The ``length`` keyword argument in functions around the library was 
   changed to ``size`` to be consistent across the whole package. Reducing 
   the cognitive burden of memorizing more than one name for the same concept. 
-  Various efficiency boosts. 
-  Edits to ``README.rst``. 
-  Added ``encode_salt``, ``aencode_salt``, ``decode_salt`` & ``adecode_salt`` 
   functions to the library, which gives access to the procedure used to 
   encrypt & decrypt the random salt which is often the first element 
   produced in one-time pad ciphertexts. 
-  Added cryptographically secure pseudo-random values as default keys in 
   encryption functions to safeguard against users accidentally encrypting 
   data without specifying a key. This way, such mistakes will produce 
   ciphertext with an unrecoverable key, instead of without a key at all. 




Changes for version 0.8.0
=========================


Major Changes
-------------

-  Fix ``test_hmac``, ``atest_hmac`` functions in the keys & database 
   classes. The new non-constant-time algorithm needs a random salt to be 
   added before doing the secondary hmac to prevent some potential exotic 
   forms of chosen plaintext/ciphertext attacks on the algorithm. The last 
   version of the algorithm should not be used. 
-  The ``Keys`` & ``AsyncKeys`` interfaces were overhauled to remove the 
   persistance of instance salts. They were intended to be updated by users 
   with the ``reset`` & ``areset`` methods, but that cannot be guaranteed 
   easily through the class, so it is an inappropriate interface since 
   reusing salts for encryption is completely insecure. The instances do
   still maintain state of their main encryption key, & new stateful methods
   for key generation, like ``mnemonic`` & ``table_key``, have been added.
   The ``state`` & ``astate`` methods have been removed.
-  Gave ``OneTimePad`` instances new stateful methods from the ``ciphers.py`` 
   module & ``keygens.py`` keys classes. Its instances now remember the main 
   symmetric key behind the ``key`` property & automatically passes it as a 
   keyword argument to the methods in ``OneTimePad.instance_methods``.


Minor Changes
-------------

-  Update ``CHANGES.rst`` file with the updates that were not logged for
   v0.7.1.
-  ``BYTES_TABLE`` was turned into a list so that the byte characters can 
   be retrieved instead of their ordinal numbers.




Changes for version 0.7.1
=========================


Major Changes
-------------

-  Fix a mistake in the signatures of ``passcrypt`` & ``apasscrypt. The args
   ``kb``, ``cpu`` & ``hardness`` were changed into keyword only arguments
   to mitigate user mistakes, but the internal calls to those functions were
   still using positional function calls, which broke the api. This issue
   is now fixed.




Changes for version 0.7.0
=========================


Major Changes
-------------

-  Replaced usage of bare ``random`` module functions, to usage of an 
   instance of ``random.Random`` to keep from messing with user's settings 
   on that module. 
-  Finalized the algorithm for the ``passcrypt`` & ``apasscrypt`` functions. 
   The algorithm is now provably memory & cpu hard with a wide security 
   margin with adequate settings. The algorithm isn't likely change with 
   upcoming versions unless a major flaw is found. 
-  The default value for the ``cpu`` argument in ``passcrypt`` & ``apasscrypt`` 
   is now ``3`` & now directly determines how many hash iterations are done 
   for each element in the memory cache. This provides much more 
   responsiveness to users & increases the capacity to impact resource cost
   with less tinkering. 
-  Switched the ``AsyncKeys.atest_hmac`` & ``Keys.test_hmac`` methods to a 
   scheme which is not constant time, but which instead does not leak useful 
   information. It does this by not comparing the hmacs of the data, but of 
   a pair of secondary hmacs. The timing analysis itself is now dependant 
   on knowledge of the key, since any conclusions of such an analysis would 
   be unable correlate its findings with any supplied hmac without it. 
-  Added  ``test_hmac`` & ``atest_hmac`` to the database classes, & changed 
   their hmac algorithm from ``sha3_512`` to ``sha3_256``. 


Minor Changes
-------------

-  Various code cleanups, refactorings & speedups.
-  Several fixes to inaccurate documentation.
-  Several fixes to inaccurate function signatures.
-  Added ``mnemonic`` & ``amnemonic`` key generators to ``keygens.py`` with
   a wordlist 2048 entries long. A custom wordlist can also be passed in.
-  Minor changes in ``Comprende`` to track down a bug in the functions that 
   use the asyncio_contextmanager package. It causes a warning when asking
   async generators to return (not yield) values.
-  Some refactoring of ``random_number_generator`` & ``arandom_number_generator``.




Changes for version 0.6.0
=========================


Major Changes
-------------

-  Replaced the usage of ``os.urandom`` within the package with 
   ``secrets.token_bytes`` to be more reliable across platforms. 
-  Replaced several usages of ``random.randrange`` within ``randoms.py`` to 
   calls to ``secrets.token_bytes`` which is faster & more secure. It
   now also seeds ``random`` module periodically prior to usage.
-  Changed the internal cache sorting algorithm of ``passcrypt`` & 
   ``apasscrypt`` functions. The key function passed to ``list.sort(key=key)`` 
   now not only updates the ``hashlib.sha3_512`` proof object with 
   each element in the cache, but with it's own current output. This change 
   is incompatible with previous versions of the functions. The key function 
   is also trimmed down of unnecessary value checking. 
-  The default value for the ``cpu`` argument in ``passcrypt`` & ``apasscrypt``
   is now ``40_000``. This is right at the edge of when the argument begins
   impacting the cpu work needed to comptute the password hash when the ``kb``
   argument is the default of ``1024``.
-  Switched the ``AsyncKeys.atest_hmac`` & ``Keys.test_hmac`` methods to a 
   constant time algorithm.


Minor Changes
-------------

-  Various code cleanups, refactorings & speedups.
-  Added a ``concurrent.futures.ThreadPoolExecutor`` instance to the ``asynchs``
   module for easily spinning off threads. It's available under 
   ``asynchs.thread_pool``.
-  Added ``sort`` & ``asort`` chainable generator method to the ``Comprende`` 
   class. They support sorting by a ``key`` sorting function as well.
-  Changed the name of ``asynchs.executor_wrapper`` to ``asynchs.wrap_in_executor``.
-  Changed the name of ``randoms.non0_digit_stream``, ``randoms.anon0_digit_stream``,
   ``randoms.digit_stream`` & ``randoms.adigit_stream`` to ``randoms.non_0_digits``,
   ``randoms.anon_0_digits``, ``randoms.digits`` & ``randoms.adigits``.
-  Several fixes to inaccurate documentation.
-  ``apasscrypt`` & ``Passcrypt.anew`` now use the synchronous version of the 
   algorithm internally because it's faster & it doesn't change the 
   parallelization properties of the function since it's already run 
   automatically in another process.
-  Added ``shuffle``, ``ashuffle``, ``unshuffle``, & ``aunshuffle`` functions
   to ``randoms.py`` that reorder sequences pseudo-randomly based on their
   ``key`` & ``salt`` keyword arguments.
-  Fixed bugs in ``AsyncKeys`` & ``debuggers.py``.
-  Added ``debugger`` & ``adebugger`` chainable generator methods to the
   ``Comprende`` class which benchmarks & inspects running generators with
   an inline syntax.




Changes for version 0.5.1
=========================


Major Changes
-------------

-  Fixed a bug in the methods ``auuids`` & ``uuids`` of the database classes 
   that assigned to a variable within a closure that was nonlocal but which 
   wasn't declared non-local. This caused an error which made the methods 
   unusable. 
-  Added ``passcrypt`` & ``apasscrypt`` functions which are designed to be 
   tunably memory & cpu hard password-based key derivation function. It was 
   inspired by the scrypt protocol but internally uses the library's tools. 
   It is a first attempt at the protocol, it's internal details will likely 
   change in future updates. 
-  Added ``bytes_keys`` & ``abytes_keys`` generators, which are just like 
   the library's ``keys`` generator, except they yield the concatenated 
   ``sha3_512.digest`` instead of the ``sha3_512.hexdigest``. 
-  Added new chainable generator methods to the ``Comprende`` class for 
   processing bytes, integers, & hex strings into one another. 


Minor Changes
-------------

-  Various code cleanups.
-  New tests added to the test suite for ``passcrypt`` & ``apasscrypt``.
-  The ``Comprende`` class' ``alist`` & ``list`` methods can now be passed
   a boolean argument to return either a ``mutable`` list directly from the 
   lru_cache, or a copy of the cached list. This list is used by the 
   generator itself to yield its values, so wilely magic can be done on the
   list to mutate the underlying generator's results. 




Changes for version 0.5.0
=========================


Major Changes
-------------

-  Added interfaces in ``Database`` & ``AsyncDatabase`` to handle encrypting
   & decrypting streams (``Comprende`` generators) instead of just raw json 
   data. They're methods called ``encrypt_stream``, ``decrypt_stream``,
   ``aencrypt_stream``, & ``adecrypt_stream``.
-  Changed the attribute ``_METATAG`` used by ``Database`` & ``AsyncDatabase`` 
   to name the metatags entry in the database. This name is smaller, cleaner 
   & is used to prevent naming collisions between user entered values & the 
   metadata the classes need to organize themselves internally. This change 
   will break databases from older versions keeping them from accessing their 
   metatag child databases.
-  Added the methods ``auuids`` & ``uuids`` to ``AsyncDatabase`` & ``Database``
   which return coroutines that accept potentially sensitive identifiers &
   turns them into salted ``size`` length hashes distinguished by a ``salt``
   & a ``category``.


Minor Changes
-------------

-  Various code & logic cleanups / speedups.
-  Refactorings of the ``Database`` & ``AsyncDatabase`` classes.
-  Various inaccurate docstrings fixed.




Changes for version 0.4.0
=========================


Major Changes
-------------

-  Fixed bug in ``aiootp.abytes_encrypt`` function which inaccurately called
   a synchronous ``Comprende`` end-point method on the underlying async
   generator, causing an exception and failure to function.
-  Changed the procedures in ``akeys`` & ``keys`` that generate their internal
   key derivation functions. They're now slightly faster to initialize &
   more theoretically secure since each internal state is fed by a seed
   which isn't returned to the user. This encryption algorithm change is 
   incompatible with the encryption algorithms of past versions.


Minor Changes
-------------

-  Various code cleanups.
-  Various inaccurate docstrings fixed.
-  Keyword arguments in ``Keys().test_hmac`` & ``AsyncKeys().atest_hmac``
   had their order switched to be slightly more friendly to use.
-  Added documentation to ``README.rst`` on the inner workings of the
   one-time-pad algorithm's implementation.
-  Made ``Compende.arandom_sleep`` & ``Compende.random_sleep`` chainable
   generator methods.
-  Changed the ``Compende.adelimit_resize`` & ``Compende.delimit_resize``
   algorithms to not yield inbetween two joined delimiters in a sequence
   being resized.




Changes for version 0.3.1
=========================


Minor Changes
-------------

-  Fixed bug where a static method in ``AsyncDatabase`` & ``Database`` was 
   wrongly labelled a class method causing a failure to initialize.




Changes for version 0.3.0
=========================


Major Changes
-------------

-  The ``AsyncDatabase`` & ``Database`` now use the more secure ``afilename`` 
   & ``filename`` methods to derive the hashmap name and encryption streams
   from a user-defined tag internal to their ``aencrypt`` / ``adecrypt`` / 
   ``encrypt`` / ``decrypt`` methods, as well as, prior to them getting called. 
   This will break past versions of databases' ability to open their files.
-  The package now has built-in functions for using the one-time-pad 
   algorithm to encrypt & decrypt binary data instead of just strings
   or integers. They are available in ``aiootp.abytes_encrypt``, 
   ``aiootp.abytes_decrypt``, ``aiootp.bytes_encrypt`` & ``aiootp.bytes_decrypt``.
-  The ``Comprende`` class now has generators that do encryption & decryption 
   of binary data as well. They are available from any ``Comprende`` generator
   by the ``abytes_encrypt``, ``abytes_decrypt``, ``bytes_encrypt`` & ``bytes_decrypt`` 
   chainable method calls.
   
   
Minor Changes
-------------

-  Fixed typos and inaccuracies in various docstrings.
-  Added a ``__ui_coordination.py`` module to handle inserting functionality 
   from higher-level to lower-level modules and classes.
-  Various code clean ups and redundancy eliminations.
-  ``AsyncKeys`` & ``Keys`` classes now only update their ``self.salt`` key
   by default when their ``areset`` & ``reset`` methods are called. This
   aligns more closely with their intended use.
-  Added ``arandom_sleep`` & ``random_sleep`` chainable methods to the
   ``Comprende`` class which yields outputs of generators after a random 
   sleep for each iteration.
-  Added several other chainable methods to the ``Comprende`` class for
   string & bytes data processing. They're viewable in ``Comprende.lazy_generators``.
-  Added new, initial tests to the test suite.




Changes for version 0.2.0
=========================


Major Changes
-------------

-  Added ephemeral salts to the ``AsyncDatabase`` & ``Database`` file 
   encryption procedures. This is a major security fix, as re-encryption 
   of files with the same tag in a database with the same open key would 
   use the same streams of key material each time, breaking encryption if 
   two different versions of a tag file's ciphertext stored to disk were 
   available to an adversary. The database methods ``encrypt``, ``decrypt``, 
   ``aencrypt`` & ``adecrypt`` will now produce and decipher true one-time 
   pad ciphertext with these ephemeral salts. 
-  The ``aiootp.subkeys`` & ``aiootp.asubkeys`` generators were revamped 
   to use the ``keys`` & ``akeys`` generators internally instead of using 
   their own, slower algorithm. 
-  ``AsyncDatabase`` file deletion is now asynchronous by running the 
   ``builtins.os.remove`` function in an async thread executor. The 
   decorator which does the magic is available at ``aiootp.asynchs.executor_wrapper``. 


Minor Changes
-------------

-  Fix typos in ``__root_salt`` & ``__aroot_salt`` docstrings. Also replaced 
   the ``hash(self)`` argument for their ``lru_cache``  & ``alru_cache`` 
   with a secure hmac instead. 
-  add ``gi_frame``, ``gi_running``, ``gi_code``, ``gi_yieldfrom``, 
   ``ag_frame``, ``ag_running``, ``ag_code`` & ``ag_await`` properties to 
   ``Comprende`` class to mirror async/sync generators more closely. 
-  Remove ``ajson_encrypt``, ``ajson_decrypt``, ``json_encrypt``, 
   ``json_decrypt`` functions' internal creation of dicts to contain the 
   plaintext. It was unnecessary & therefore wasteful. 
-  Fix docstrings in ``OneTimePad`` methods mentioning ``parent`` kwarg which 
   is a reference to deleted, refactored code. 
-  Fix incorrect docstrings in databases ``namestream`` & ``anamestream`` 
   methods. 
-  Added ``ASYNC_GEN_THROWN`` constant to ``Comprende`` class to try to stop 
   an infrequent & difficult to debug ``RuntimeError`` when async generators 
   do not stop after receiving an ``athrow``. 
-  Database tags are now fully loaded when they're copied using the methods 
   ``into_namespace`` & ``ainto_namespace``. 
-  Updated inaccurate docstrings in ``map_encrypt``, ``amap_encrypt``, 
   ``map_decrypt`` & ``amap_decrypt`` ``OneTimePad`` methods. 
-  Added ``acustomize_parameters`` async function to ``aiootp.generics`` 
   module. 
-  Various code clean ups.




Changes for version 0.1.0 
========================= 

Minor Changes 
------------- 

-  Initial version. 


Major Changes 
------------- 

-  Initial version. 

