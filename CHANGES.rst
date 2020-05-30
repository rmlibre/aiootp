
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
   turns them into salted ``length`` sized hashes distinguished by a ``salt``
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

