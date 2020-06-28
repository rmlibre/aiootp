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

