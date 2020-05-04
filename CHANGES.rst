
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
   to use the ``keys`` generator internally instead of using their own, 
   slower algorithm. 
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
-  an infrequent & difficult to debug ``RuntimeError`` when async generators 
   do not stop after receiving an ``athrow``. 
-  Database tags are now fully loaded when they're copied using the methods 
   ``into_namespace`` & ``ainto_namespace``. 
-  Updated inaccurate docstrings in ``map_encrypt``, ``amap_encrypt``, 
   ``map_decrypt`` & ``amap_decrypt`` ``OneTimePad`` methods. 
-  Added ``acustomize_parameters`` async function to ``aiootp.generics``
   modules.
-  Various code clean ups.




Changes for version 0.1.0 
========================= 

Minor Changes 
------------- 

-  Initial version. 


Major Changes 
------------- 

-  Initial version. 

