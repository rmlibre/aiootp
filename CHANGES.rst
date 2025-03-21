
`Changelog`
===========




Changes for version 0.23.17
---------------------------


Major Changes
^^^^^^^^^^^^^

- fix(test): collect names once if pytest runs w/o module specified


Minor Changes
^^^^^^^^^^^^^

- build(package): allow but warn of non-standard HEAD names
- build(package): prompt for desired branch if non-standard
- docs(exc): specify return type hint for Ignore callable arg
- docs(test): switch Targets to type-hintable NamedTuple type
- docs(readme): display example returns of None consistently
- docs(readme): describe cipher key sizes as inclusive of 64-bytes
- docs(typing): describe queue param correctly as a deque
- test(paths): exempt Windows of need to deny salt file reads
- test(paths): parametrize & stabilize 'test_paths.py' methods
- test(paths): ensure reads return expected salt value
- test(paths): add new tests to 'test_paths.py' after refactor
- test(signer): avoid false negatives if example file is empty
- test(signer): add cases of wrong signing keys for verification
- refactor(perm): use args & concentrate steps in key encoder
- refactor(test): extract base class from common runner logic
- refactor(test): remove extra salt file tests during refactor
- refactor(test): prepare for consolidation & parametrization 1/x
- refactor(test): prepare for consolidation & parametrization 2/x
- refactor(test): prepare for consolidation & parametrization 3/x
- refactor(test): consolidate & parametrize to simplify new tests
- refactor(test): prepare to categorize tests into smaller modules
- refactor(test): remove unneeded aggregator 'conftest.py' imports
- style(ciphers): merge loop conditional with inner guard clause




Changes for version 0.23.16
---------------------------


Major Changes
^^^^^^^^^^^^^

- fix: avoid deprecated 'fork', switch to queues & 'spawn'
- build: remove no longer needed 'setup.py' file
- build: add missing wheel dependency to dev installs
- build: add missing setuptools dependency to dev installs
- build: send build data over sockets to a local signing service
- test: add full coverage for '_paths.py'
- test: use new, custom, more efficient hypothesis strategies
- perf: store PackageSigner files as hexdigests to ease transmission
- refactor: update '_paths.py' style, names & logic structure


Minor Changes
^^^^^^^^^^^^^

- feat: add trial ciphertext<-->phrase steganographic tool
- feat: add a size argument to ByteIO (a)read methods
- build: bump dependencies versions & apply new ruff rules
- build: automate 'MANIFEST.in' & follow setuptools guide
- build: add ipython to dev installs to standardize & simplify environment setup
- docs: specify bool or None as ``__(a)exit__`` return type
- docs: fix inaccurate changelog message under v0.23.15
- docs(readme): include ``Slick256`` in online cipher description
- docs(readme): clean intro instructions & make test/dev section
- docs: fix incomplete docstring in 'cipher_interface.py'
- docs: fix docstring typos
- docs: improve docstring clarity
- docs: correct return type hint on test methods
- docs: add function name in not implemented warning message
- docs: reword salt misuse resistance docstrings & add citation
- docs: add return type hint on test fixtures
- docs: bump AGPLv3 license date range
- docs: correct 'test_paths.py' error messages
- docs: correct outdated '_paths.py' docstrings
- test: cover placeholder method in 'aos.py' module
- test: remove leftover usage of 'fork' processes
- refactor: fix concurrency type hints & unnecessary coupling
- refactor: bundle like-context exceptions into named constants
- refactor: extract names defined in function to file's config section
- refactor: use constants for static filenames instead of literals
- refactor: extract server socket init into a context manager
- refactor: call new functions for default inputs to cipher configs
- refactor: move test vectors into their own modules
- style: replace simple ternary ops with short-circuits




Changes for version 0.23.15
---------------------------


Major Changes
^^^^^^^^^^^^^

- ci: add ``hypothesis`` to GH actions workflow dependencies
- build: update dependencies & add coverage to dev & test installs
- build: add ``hypothesis`` dependency to dev & test installs
- build: bump ``ruff`` version & fix new lint rule changes
- build: add ``build`` dependency to dev installs
- build: update metadata to show Python 3.13 support


Minor Changes
^^^^^^^^^^^^^

- fix: capture ``KeyError`` & raise ``AttributeError`` instead [#8]
- fix: use size instead of config_id to determine GUID key_size
- feat: add 48-byte default permutation config objects
- feat: add decisecond & centisecond clock configurations
- ci: add Python '3.13.x' to GH actions
- build: use dynamic table to specify the package readme
- build: specify the coverage htmlcov directory
- build: remove 'command_line' so coverage can run specific files
- build: fix deprecation of unset pytest_asyncio fixture loop scope
- build: add verify package flow to signing ceremony
- docs: fix wrong typing annotation
- docs: fix docstring typo & grammar
- docs: fix grammar of error message
- docs: fix (a)canonical_pack docstring format diagram
- docs(readme): clean-up install instructions
- test: prepare fixtures to refactor 'test_PackageSigner.py'
- test: refactor 'test_PackageSigner.py' & cover all branches
- test: cover input combinations for ``(a)test_timestamp``
- test: import ``hypothesis`` in 'conftest.py'
- test: parametrize & fuzz 'test_gentools.py' to cover branches
- test: continue refactor & coverage in 'test_PackageSigner.py'
- test: configure pytest to display or error on warnings
- refactor: remove unnecessary variable alias
- refactor: specify input types as positive integers
- refactor: unify, parametrize, & simplify PackageSigner test values
- refactor: remove redundant step in test initialization
- refactor: terminate 'pyproject.toml' container lines with commas




Changes for version 0.23.14
---------------------------


Major Changes
^^^^^^^^^^^^^

- build: fix improperly packaged directory structure for wheel


Minor Changes
^^^^^^^^^^^^^

- build: use standard SPDX string name for project license
- build: move links to 'project.urls' table in 'pyproject.toml'




Changes for version 0.23.13
---------------------------


Major Changes
^^^^^^^^^^^^^

- build: improve package signing with better logic & git file tree


Minor Changes
^^^^^^^^^^^^^

- ci: attempt bash shell for Windows GH actions tarball tests
- ci: attempt tar command for Windows GH actions tarball tests
- build(package): swap author order for display purposes
- build: attempt specifying python versions in wheel file




Changes for version 0.23.12
---------------------------


Major Changes
^^^^^^^^^^^^^

- fix(concurrency): use constant-time 'is done' logic for cipher streams
- build: start transition to the new standard ``pyproject.toml``
- build: continue ``pyproject.toml`` updates for Ruff & manifest
- style: apply Ruff rule A001 for module doctring placement


Minor Changes
^^^^^^^^^^^^^

- ci: run PyPI tarball package tests in new GitHub actions
- test: wait longer for concurrent thread to start running
- refactor: make custom ``CipherStreamIsClosed`` exception
- style: apply Ruff rule B008 exception only to ``rng.py`` module
- style: remove Ruff rule UP015 exception since using pathlib
- style: clean & sort ``MANIFEST.in`` with git ls-tree
- refactor: prepare for ``pyproject.toml`` with new signing ceremony file




Changes for version 0.23.11
---------------------------


Major Changes
^^^^^^^^^^^^^

- fix(concurrency): block multiple calls to cipher stream finalization [#19]
- fix(concurrency): complete all buffers before (a)finalize runs [#19]
- style(lint): apply Ruff lint & format with more rules [#12]


Minor Changes
^^^^^^^^^^^^^

- docs(ruff): improve grammar & structure of rule annotations
- build(ignore): extend & alphabetize with explicit dirs
- refactor: rename test init file to the standard 'conftest.py'
- refactor(tests): use more descriptive names




Changes for version 0.23.10
---------------------------


Major Changes
^^^^^^^^^^^^^

- fix(commons): deduplicate logic to keep behavior consistent [#14][#15]
- feat(commons): support tuples of types in ``typed_slots`` classes


Minor Changes
^^^^^^^^^^^^^

- fix(concurrency): use timing-safe token comparisons & mask repr
- fix(concurrency): rely on context manager boolean control flow
- docs(coc): fix typos & rename first section
- docs(perm): add missing operator in doc string examples
- docs(cipher): fix misuse resistance calculations [#16]
- docs(concurrency): fix typos & grammar in doc strings
- perf(commons): separate & order inclusion checks
- style(lint): turn on "ARG" flag & fix associated warnings




Changes for version 0.23.9
--------------------------


Major Changes
^^^^^^^^^^^^^

- fix(commons): avoid silent add of ``__slots__`` attrs to ``__dict__`` [#11]
- fix(concurrency): prevent simultaneous data buffering [#12]
- build(lint): require Ruff for test installation [#12]
- test(lint): perform Ruff lint & format suggestions [#12]


Minor Changes
^^^^^^^^^^^^^

- fix: allow ``str`` build numbers in signing ceremony
- fix(db): raise intended error by loading missing import [#12]
- fix(commons): remove duplicates prior to update
- fix(commons): accept pair-iterable mapping in init
- fix(commons): remove ``__all__`` method causing recursion bugs
- fix(concurrency): import missing name in guard clause line [#12]
- ci(perf): run workflows on push & pull, but not on same event
- docs: fix wrong or incomplete doc strings
- docs: add links for bug & security issue reporting
- docs(lint): incorporate Ruff demo & update badges [#12]
- docs(bugfix): demonstrate avoiding slots/dict conflicts [#11]
- docs(bugfix): clarify tests to show problematic assignments [#11]
- docs(commons): add distinguishing facets of classes to doc strings
- docs(typing): fix & add type hints
- build(lint): add ``ruff.toml`` config file [#12]
- test(cipher): demonstrate proper stream authentication
- test(commons): ensure proper use avoids bug from PR [#11]
- test(concurrency): add module for ``ConcurrencyGuard`` tests [#12]
- perf(init): cache slots as sets for membership tests [#11]
- revert: scrap discouraged quick-fix in favor of f1060ce221 [#11]
- refactor(exc): rely on common invalid length exception
- style(lint): remove unused imports [#12]
- style(lint): prevent reformat of problem statement [#12]
- style(lint): prefer non-lambda function definitions [#12]
- style(commons): add missing ``__slots__`` declarations




Changes for version 0.23.8
--------------------------


Major Changes
^^^^^^^^^^^^^

- feat(api): support compliant public keys in KEX protocols [#7]
- feat(typing): generalize ``Config`` type-checking as superclass [#9]


Minor Changes
^^^^^^^^^^^^^

- fix(package): delete option likely breaking piwheels
- fix(exc): stabilize exceptions & error-raising properties [#8]
- fix(typing): ensure ``Protocol`` subclasses runtime checkable [#8]
- ci(pypi): import & run on GH release
- docs(cipher): describe a ``salt`` consistently
- build(github): add bug report issue template
- refactor(api): enforce positional or keyword only arguments
- refactor(api): default ttl as None & update method signatures
- refactor(commons): delegate (del/get)attr to (del/get)item




Changes for version 0.23.7
--------------------------


Major Changes
^^^^^^^^^^^^^

- fix(behavior): fix inconsistent ``Slots`` subclass frozen & mapping functionality
- fix(api): resolve type unsafety of redundant params in KEX protocol inits [#5]


Minor Changes
^^^^^^^^^^^^^

- chore(release): mark completed ``v0.23.x`` series versions with git tags
- refactor(package): move ``FrozenInstance`` class to its own module
- refactor(algorithm): remove hard-coded KDF in ``X25519`` protocol methods [#4]
- docs(database): provide more concurrency-safe & elegant usage examples
- docs: fix & improve misc
- test: fix & improve misc
- style: fix & improve misc




Changes for version 0.23.6
--------------------------


Major Changes
^^^^^^^^^^^^^

- Standardize on mapping functionality for ``Slots`` sub classes.
- Automate saving database to disk after ``PackageSigner`` signs package.


Minor Changes
^^^^^^^^^^^^^

- Add GitHub actions for live testing installs from PyPI.
- Improvements & fixes to type hints.
- Improvements & fixes to doc strings.
- Improvements & fixes to package tests.
- Improvements & fixes to package documentation.
- Improvements & fixes to code formatting & style.




Changes for version 0.23.5
--------------------------


Major Changes
^^^^^^^^^^^^^

- Refactor internal ``_typing.py`` module into a subpackage.
- Remove inefficient internal code related to the ``keygens/curve_25519/adapter.py`` module.


Minor Changes
^^^^^^^^^^^^^

- Reach 100% testing line coverage on Linux.
- Simplify & update internal functionality that also removes a vanishingly unlikely infinite loop condition.
- Utilize unused package seed during package initialization.
- Improve the derivation algorithm for the ``AffinePermutation`` 's  multiplicative key.
- Refactor & add tests into a new ``test_online_cipher_interfaces.py`` testing module.
- Add ``test_event_loops.py`` test module.
- Improvements & fixes to type hints.
- Improvements & fixes to doc strings.
- Improvements & fixes to package tests.
- Improvements & fixes to package documentation.
- Improvements & fixes to code formatting & style.




Changes for version 0.23.4
--------------------------


Major Changes
^^^^^^^^^^^^^

- Provide ``Clock`` interface for determining relative time resolution adequacy, & add warning about system time resolution inadequacy harming ``GUID`` uniqueness.


Minor Changes
^^^^^^^^^^^^^

- Add ``(a)canonical_unpack`` references to ``generics``, communicating their higher-level usefulness.
- Rename ``test_passcrypt_apasscrypt.py`` to ``test_Passcrypt.py``.
- Improvements & fixes to type hints.
- Improvements & fixes to doc strings.
- Improvements & fixes to package tests.
- Improvements & fixes to package documentation.
- Improvements & fixes to code formatting & style.




Changes for version 0.23.3
--------------------------


Minor Changes
^^^^^^^^^^^^^

- Move ``wrap_in_executor`` from ``asynchs.aos`` to ``asynchs.loops``.
- Remove ``asynchs.loops.stop``, add ``asynchs.loops.set_event_loop``.
- Improvements & fixes to type hints.
- Improvements & fixes to doc strings.
- Improvements & fixes to package tests.
- Improvements & fixes to package documentation.
- Improvements & fixes to code formatting & style.




Changes for version 0.23.2
--------------------------


Major Changes
^^^^^^^^^^^^^

- Dispersed ``keygens/package_signing.py`` module into separate ``keygens/package_signer.py`` & ``keygens/package_verifier.py`` modules.
- Apply preliminary quick fixes to cross-platform errors in `asynchs` subpackage.


Minor Changes
^^^^^^^^^^^^^

- Code formatting fixes.
- Remove deprecated code.
- Add preemptive validity checks for SIV algorithm measurements.
- Fixes to the correctness & completeness of doc strings.
- Fixes to the correctness & completeness of package tests.
- Fixes to the correctness & completeness of package documentation.




Changes for version 0.23.1
--------------------------


Minor Changes
^^^^^^^^^^^^^

- Bump declared compatible Python versions in packaging metadata to 3.8 - 3.12.
- Fix tests that were fragile to edge cases.




Changes for version 0.23.0
--------------------------


**(Major Rewrite: Backwards Incompatible)**


Major Changes
^^^^^^^^^^^^^

- Refined the ``Chunky2048`` algorithm & implementation, increasing its efficiency.
- Implemented a new cipher we're calling ``Slick256``. It utilizes the session randomized, non-linearity, & diffusion of a keyed permutation to improve robustness, RUP-security, & salt misuse-reuse resistance. This design is relatively simple, with desirable security properties, a smaller state size & 32-byte blocks, but runs slower than ``Chunky2048``.
- Removed the expansive & difficult to maintain ``Comprende`` class & its associated functionalities.
- Extensive refactoring & reimplementations of code throughout the package. Many modules were renamed & dispersed into subpackages for better organization, smaller & much clearer source files. Coding style & quality has been greatly improved.
- Efficiency improvements to ``(Async)Database`` classes.
- Implementation of keyed-permutations based on modified affine cipher arithmetic.


Minor Changes
^^^^^^^^^^^^^

- Fixes to the correctness & completeness of type hints.
- Fixes to the correctness & completeness of doc strings.
- Fixes to the correctness & completeness of package documentation.
- Expansion & cleaning of test suite, reaching 99% line coverage.




Changes for version 0.22.2
--------------------------


Minor Changes
^^^^^^^^^^^^^

- Update the package description.
- Fix documentation typos & formatting.




Changes for version 0.22.1
--------------------------


Major Changes
^^^^^^^^^^^^^

-  The top-level ``DomainKDF`` class' hashing methods can now accept an arbitrary amount of additional data arguments which do not change the internal state of its objects.
-  Switch the order of the internal raw guids with the ``node_number`` in the ``GUID`` class. This is intended to induce the most variability possible in output guids by interpreting the variable raw guids as more significant bits.


Minor Changes
^^^^^^^^^^^^^

-  The default ``cpu`` cost for ``Passcrypt`` was lowered from 2 to 1.
-  Ensured raw guid byte values used by ``GUID`` class are interpreted as big-endian integers.
-  The top-level ``(a)csprng`` functions now don't bother to convert a falsey, non-``bytes``, user-supplied ``entropy`` argument to ``bytes``. Instead they just use a value from an internal entropy pool as additional entropy for that invocation of the function.
-  Code clean-ups.
-  Documentation fixes.
-  Added tests for ``DomainKDF``, ``GUID`` & ``SyntheticIV``, & improved clarity of some existing tests.
-  Packaging changes to create coherent wheel files.
-  Explicitly declare use of big-endian encoding throughout the package.
-  Conduct a more comprehensive addition of the package's types to the ``Typing`` class.




Changes for version 0.22.0
---------------------------


**(Major Rewrite: Backwards Incompatible)**


Security Advisory:
^^^^^^^^^^^^^^^^^^

-  The top-level ``(a)csprng`` functions were found to be unsafe in concurrent code, leading to the possibilty of producing identical outputs from distinct calls if run in quick succession from concurrently running threads & coroutines. The classification of this vulnerability is severe because: 1) users should be able to expect the output of a 64-byte cryptographically secure pseudo-random number generator to always produce unique outputs; and, 2) much of the package utilizes them to produce cryptographic material. This vulnerability does not effect users of the library which are not running it in multiple concurrent threads or coroutines. The vulnerability has been patched & all users are **highly encouraged** to upgrade to v0.22.0+.


Major Changes
^^^^^^^^^^^^^

-  Support for python 3.6 was dropped. The package now supports python versions 3.7+.
-  **Chunky2048**: A new version of the cipher has been developed which
   implements algorithms & interfaces that offer improvements in multiple
   regards: smaller size overhead of ciphertexts, faster execution time
   for large messages & large keys, more robust salt reuse/misue resistance,
   fewer aspects harming deniability & better domain separation.
   Many of the changes are described here:

   -  The ``(a)bytes_keys`` generators were updated to use ``shake_128``-based KDF objects instead of ``sha3_512``, yielding 256-bytes on each iteration instead of 128, now requiring only a single iteration to produce a keystream key for each block, instead of two. This choice was made during the process of analyzing the use of the user's encryption `key` to seed the `seed_kdf` on each iteration. We wanted to stop doing that essentially, because it slowed down the cipher too much when used with large keys. And because it seems like a bad idea to use the same key repeatedly while also not incorporating the uniqueness or entropy from the message's `salt`, `siv` or `aad`.

      But still, we somehow wanted to come up with an idea which could efficiently & continually extract entropy from the user `key` if it did happen to be large. An answer came in the form of expanding on an earlier implemented idea which used the key multiple times to create unique seeds during initialization. In this case, however, instead of creating unique seeds with the single `seed_kdf`, each of the three KDFs & the MAC object used by the cipher will be given the whole `key` once at initialization, with proper domain separation, & including the message `salt` & `aad` (The `siv` can't be used because its creation happens after initialization during encryption). This gives each of their (SHA3) 200-byte internal states independent access to the full entropy of the `key`.

      Then, the problem was that, by using ``sha3_512`` internally, a maximum of 64-bytes of entropy could be communicated between KDFs at each round (and only 32-bytes from the ``StreamHMAC`` (`shmac`) object's ``sha3_256`` MAC). But the blocksize of each round is 256-bytes. So, the idea became to attempt to *communicate* more entropy between the KDFs & MAC each round than there exists possible messages in the message space of each round. It seems plausible, that by only assuming the independence of each of the KDFs / MAC & that they can indeed `efficiently pass entropy` to one another, that for large keys we could argue the relevant key space is that of the 800-byte internal state of the cipher at each round (which happens to be more than three times the size of the message space of each round). This is to say, we conjecture, that by `efficiently communicating more entropy` from *independent sources* than there exists *possible messages*, & in fact incorporating the entropy of *each message block* into the cipher's state at the start of *each round*, that the entropy of the internal keyspace is continually being refreshed in a way which is negligibly distinguishable from using a fresh random key each round the length of the blocksize. This seems like at least a feasible way to begin the argument that it is possible to meaningfully relate the information theoretic security of the one-time pad to a pseudo one-time pad in a measurable way.

      `Efficiently Pass Entropy`: By this we mean, the rate of bits extracted from one state object, to the rate of bits of actual entropy absorbed by a receiveing state object, up to its XORable state size, being different by only a negligible amount. Here, we can conservatively assume the limit of this efficiency is the XORable state size, since we know that in the ideal setting, XORing `n` uniform random bits with an unknown message of <= `n` bits is perfectly hiding, which implies perfectly efficient conveyance of entropy. By using ``shake_128`` as each of the cipher's state objects, & its larger rate of 168-bytes, more than twice the number of bytes can be passed to & extracted from each, per round & per call to their internal `f` permutation, as compared with ``sha3_512``. `If they can efficiently pass entropy`, then any secret state exposed by the `left_kdf` or `right_kdf` in the creation of ciphertext, can then be efficiently displaced by the introduction of new entropy from the other state objects. This follows from the theory that a finite sized pool of entropy which is already maximally filled with entropy, cannot incorporate more entropy without fundamentally erasing internal information. From this we arrived at the new design for ``Chunky2048``. In this new design, the `shmac` feeds 168-bytes to the `seed_kdf`, the `seed_kdf` creates 336-bytes to feed 168-bytes each to the `left_kdf` & `right_kdf`, the `left_kdf` & `right_kdf` each produce 128-byte keys which XOR the 256-byte plaintext, then this ciphertext feeds the `shmac` & the cycle repeats.

      More work needs to be done to formalize these definitions & analyze their properties. We would be grateful for any help from those with expertise in formal proofs of security in tearing apart this design as we move closer to the first stable release of the package.

   -  The ``SyntheticIV`` class' algorithm has been updated as a result of analyzing how we could improve the salt misuse-reuse resistance of the cipher without attesting to plaintext contents in the form of an `siv` attached to ciphertexts. This plaintext attestation worked counter to our goal of wanting to be able to say something non-trivial about the key-deniability of the cipher. It was noticed that the plaintext padding already incorporated an 8-byte timestamp (now reduced to 4-bytes) & 16-bytes of ephemeral randomness as part of the prepended inner-header, & that these values were not at all used to seed the cipher's state during decryption. Instead a keyed-hash was calculated over the first block of plaintext during encryption to create the 24-byte `siv`. But, this is actually `less effective` at producing salt misuse-reuse resistance than using the timestamp & ephemeral randomness directly in seeding the `seed_kdf`, because the timestamp is a unique & global counter that does not suffer from collisions. This understanding came while also trying to find a good use for the initial `primer_key` generated by the keystream generator when sending in the first obligatory `None` value. In the previous version it was used to initialize the `shmac`, but now that the `shmac` would be initialized directly with the user `key`, it was searching for a use. So the idea was to pair them.

      The new 256-byte `primer_key` would be XORed with the 256-byte first block of plaintext to mask the inner-header. The unmasked inner-header & 148-bytes of the `shmac`'s digest will seed the keystream, & the freshly seeded keystream output would be truncated to XOR the part of the masked plaintext which doesn't include the inner-header. There's no need now to attach the `siv` to the ciphertext. Instead, during decryption, the decipher algorithm has access to the inner-header, because it has access to the `primer_key` & the masked inner-header. The actual plaintext contents of the first block are only accessible after unmasking the inner-header & seeding the keystream. This combination alone of protection from a timestamp & 16-bytes of randomness should give a salt misuse-reuse resistance of at least `~2 ^ 64 messages` **per second**!

      However, even with this new scheme, it would still be problematic to repeat a combination of `key`, `salt` & `aad`, since it would leak the XORs of timestamp information. With all of this in mind, the new formulation would include a 16-byte `salt` & a newly introduced 16-byte `iv`, both of which are attached to ciphertexts. This is a header size reduction of 16-bytes, since prior `salt` & `siv` sizes were 24-bytes each. The difference between the `salt` & `iv` is that the `salt` is available for the user to choose, but the `iv` is **always** generated randomly. Since the `iv` isn't dependent on message data the way that the `siv` was, it too can now be incorporated into all of the state objects during initialization. The `iv` ensures that even if a `key`, `salt` & `aad` tuple repeats, the timestamp is still protected. Below is a diagram of the procedure:


      .. code-block:: python

        #
         _____________________________________
        |                                     |
        |    Algorithm Diagram: Encryption    |
        |_____________________________________|
         ------------------------------------------------------------------     #
        |      inner-header      |        first block of plaintext         |    #
        | timestamp |  siv-key   |                                         |    #
        |  4-bytes  |  16-bytes  |               236-bytes                 |    #
         ------------------------------------------------------------------     #
        |---------------------- entire first block ------------------------|    #
                                         |                                      #
                                         |                                      #
        first 256-byte keystream key ----⊕                                      #
                                         |                                      #
                                         |                                      #
                                         V                                      #
                              masked plaintext block                            #
         ------------------------------------------------------------------     #
        |  masked inner-header   |     first block of masked plaintext     |    #
         ------------------------------------------------------------------     #
                                 |----- the 236-byte masked plaintext -----|    #
                                                      |                         #
                                                      |                         #
        siv = inner-header + shmac.digest(148)        |                         #
        keystream(siv)[10:246] -----------------------⊕                         #
                                                      |                         #
                                                      |                         #
                                                      V                         #
         ------------------------------------------------------------------     #
        |  masked inner-header   |       first block of ciphertext         |    #
         ------------------------------------------------------------------     #


         _____________________________________
        |                                     |
        |    Algorithm Diagram: Decryption    |
        |_____________________________________|
         ------------------------------------------------------------------     #
        |  masked inner-header   |        first block of ciphertext        |    #
         ------------------------------------------------------------------     #
        |---------------------- entire first block ------------------------|    #
                                         |                                      #
                                         |                                      #
        first 256-byte keystream key ----⊕                                      #
                                         |                                      #
                                         |                                      #
                                         V                                      #
                            unmasked ciphertext block                           #
         ------------------------------------------------------------------     #
        |      inner-header      |   first block of unmasked ciphertext    |    #
         ------------------------------------------------------------------     #
                                 |--- the 236-byte unmasked ciphertext ----|    #
                                                      |                         #
                                                      |                         #
        siv = inner-header + shmac.digest(148)        |                         #
        keystream(siv)[10:246] -----------------------⊕                         #
                                                      |                         #
                                                      |                         #
                                                      V                         #
         ------------------------------------------------------------------     #
        |      inner-header      |         first block of plaintext        |    #
        | timestamp |  siv-key   |                                         |    #
        |  4-bytes  |  16-bytes  |               236-bytes                 |    #
         ------------------------------------------------------------------     #

        #

   -  The ``Padding`` class has seen some changes. Firstly, the 8-byte timestamp in the inner-header was reduced to 4-bytes. Furthermore, to get the full 136 years out of the 4-byte timestamps, the epoch used to calculate them was changed to unix timestamp `1672531200` (Sun, 01 Jan 2023 00:00:00 UTC). This is the new default `0` date for the package's timestamps. This saves some space & aims to provided fewer bits of confirmable attestation & correlation in proof games which simulate attacks on the key-deniability of the cipher. To explain: the plaintext padding includes random padding. That padding is intended to leave an adversary which attempts to brute force a ciphertext's encryption `key`, even with unbounded computational resources, in a state where it cannot decide with better accuracy than random chance between the exponentially large number of keys which create the same `shmac` tag (the variable `keyspace` is much larger than the 32-byte tag) with their accompanying exponentially large number of `plausible` plaintexts (any `reasonable` plaintext with any variable length random padding between 16 & 272 bytes), & the actual user `key` & plaintext.

      We also got rid of the use of a `padding_key` to indicate the end of a plaintext message. It used to be sliced off the `primer_key`, but the `primer_key` has a new use now. Also, the `padding_key` was another form of plaintext / key attestation harming deniability that we wanted to get rid of. Instead, a simpler method is now employed: The final byte of the final block of padded plaintext is a number which tells the decryptor exactly how many bytes of random padding were added to the plaintext to fill the block. This saves a lot of space, is simpler, minimizes unnecessary key attestation, & eliminates the need for the ``Padding`` class to know anything about user secrets in order to do the padding, which is an improvement all around.

-  New ``(Async)CipherStream`` & ``(Async)DecipherStream`` classes were introduced which allow users to utilize the online nature of the ``Chunky2048`` cipher, ciphering & deciphering data in bufferable chunks, without needing to know about or instantiate all of the low-level classes. They automatically handle the required plaintext padding, ciphertext authentication, & detection of out-of-order message blocks. This greatly simplifies the safe usage of ``Chunky2048`` in online mode, provides robustness, & gets rid of the need for users to worry about the dangers of release of unverified plaintexts.

-  The ``Passcrypt`` algorithm was redesigned to be data-independent, more efficiently acheive its security goals, & allow for more compact hashes which include its difficulty settings metadata. The `kb` parameter was changed to `mb`, & now measures Mebibytes (MiB). A new `cores` parallelization parameter was added, which indicates the number of parallel processes to use to complete the procedure. And the `cpu` parameter now measures the number of iterations over the memory cache that are done, as well as the computational complexity of the algorithm. ``Passcrypt`` now uses ``shake_128`` instead of ``sha3_512`` internally. This also allows for users to specify a ``tag_size`` number of bytes to produce as an output tag. A ``salt_size`` parameter can now also be supplied to the ``(a)hash_passphrase`` methods. The ``(a)hash_passphrase`` methods now produce raw-bytes outputs & the ``(a)hash_passphrase_raw`` & ``(a)verify_raw`` methods were removed. ``(a)verify`` methods now also accept ``range``-type objects as ``mb_allowed``, ``cpu_allowed``, & ``cores_allowed`` keyword argument inputs. These range objects can be used to specify the exact amount of resources which the user allows for difficulty settings, which can mitigate adversarial (or unintentional) DOS attacks on machines doing hash verification.

-  Type annotations were added to most of the library, including return types, which were completely neglected in prior versions. They are still not functioning with mypy, & are serving right now as documentation & auto-complete helpers.

-  Many unnecesssary, low-level or badly designed features, functions & classes were either deleted or pulled into private namespaces, along with major reorganization & cleanup of the codebase. The tangled mess of internal module imports was also cleaned up. The goal is to provide access to only the highest level, simplest, & safest by default interfaces which can actually help users in their data processing & cryptographic tasks. These changes aim to improve maintainability, readability, correctness & safety.

-  New top-level ``(a)hash_bytes`` functions were added to the package, which accept an unlimited number bytes-type inputs as positional arguments & automatically canonically encode all inputs before being hashed (which aims to prevent canonicalization attacks & length-extension attacks). A ``key`` keyword-only argument can also be supplied to optionally produce keyed hashes.

-  A new top-level ``GUID`` class was added. It creates objects which produce variable length, obfuscated, pseudo-random bytes-type globally unique identifiers based on a user-defined integer `node_number`, a user-defined uniform bytes `salt`, a nanosecond `timestamp`, random `entropy` bytes & a 1-byte `counter`. The benefits of its novel design explained: **1)** the namespace separation of user-defined salts (like name-based uuids); **2)** guaranteed output uniqueness for all instances using the same `salt` & `node_number` which occur on a different nanosecond (like time-based uuids, but with higher precision); **3)** guaranteed output uniqueness between all instances which use the same `salt` but a different `node_number`, even if produced on the same nanosecond; **4)** guaranteed output uniqueness for any unique instance using the same `salt` & `node_number` if it produces 256 or fewer outputs every nanosecond; **5)** probabilistic output uniqueness for any unique instance using the same `salt` & `node_number` if it produces >256 outputs per-nanosecond, exponentially proportional to the number of random `entropy` bytes (which in turn are proportional to the output size of the GUIDs); **6)** output invertability, meaning outputs can be unmasked & sorted according to `timestamp`, `node_number` & `counter`; **7)** random-appearing outputs, with the marginal amount of privacy which can be afforded by obfuscated affine-group operations. Admittedly, point **7)** still *leaves much room for improvement*, as the privacy of the design could instead be ensured by strong hardness assumptions given by other types of invertible permutations or group operations. The goal was to create something efficient (below 3µs per guid), which met the above criterion, & that produced output bit sequences which passed basic randomness tests. We'd be excited to accept pull requests which use strong invertable permutations or group operations that are also about as efficient, & that for `n`-byte declared output sizes, outputs do not repeat for fewer than ~256 ** `n` sequential input values.

-  The top-level ``DomainKDF`` class now also creates KDF objects which automatically canonically encode all inputs.

-  The ``X25519`` protocols now return ``DomainKDF`` results instead of plain ``sha3_512`` objects.

-  The ``(Base)Comprende`` classes were greatly simplified, & the caching & ``messages`` features were removed.

-  The top-level ``(a)mnemonic`` functions now return lists of bytes-type words, instead of str-type, & can now be used to quickly generate lists of randomly selected words without providing a (now optional) passphrase.

-  The ``(Async)Database`` classes' ``(a)generate_profile`` methods no longer require tokens to first be created by the user. That is now handled internally, & the external API accepts raw bytes inputs for credentials from the user.

-  The ``PackageSigner`` & ``PackageVerifier`` now use ``sha384`` for digests instead of ``sha512``. The verifier now by default recomputes & verifies the digests of files from the filesystem using the ``path`` keyword argument to the constructor as the root directory for the relative filepaths declared in the "checksums" entry of the signature summary.




Minor Changes
^^^^^^^^^^^^^

-  A new ``Clock`` class was added to the ``generics.py`` module which provides a very intuitive API for handling time & timestamp functionalities for various time units.

-  The test suite was reorganized, cleaned up & extended significantly, & now also utilizes ``pytest-asyncio`` to run async tests. This led to many found & fixed bugs in code that was not being tested. There's still a substantial amount of tests that need to be written. We would greatly appreciate contributions which extend our test coverage.

-  Many improvements to the correctness, completeness & aesthetic beauty of the code documentation with the addition of visual aides, diagrams & usage examples.

-  A top-level ``report_security_issue`` function was added, which provides a terminal application for users to automatically encrypt security reports to us using our new X25519 public key.

-  We lost access to our signing keys in encrypted drives which were damaged in flooding. So we decided to shred them & start fresh. Our new Ed25519 signing key is "70d1740f2a439da98243c43a4d7ef1cf993b87a75f3bb0851ae79de675af5b3b". Contact us via email or twitter if you'd like to confirm that the key you are seeing is really ours.




Changes for version 0.21.1
--------------------------


Minor Changes
^^^^^^^^^^^^^

-  Fix usage of the wrong package signing key.




Changes for version 0.21.0
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Non-backwards compatible changes:
-  Altered the ``Chunky2048`` cipher's key derivation to continuously extract
   entropy from users' main encryption key. The design goal of the cipher
   is to be as close as possible to a one-time pad, but because we use
   key derivations to mix together all the relevant values used by the
   cipher, there's a limited amount of entropy that can be extracted
   from the main key no matter how large it is. The changes feed the
   main key into the internal seed KDF multiple times when creating the
   cipher's initial seeds, & once on every iteration of the ``(a)bytes_keys``
   generators.
-  Merged two internal KDFs used by the cipher into the one seed KDF. This
   also now means that using the ``(a)update_key`` methods of the ``StreamHMAC``
   class updates the KDF used to ratchet the encryption keystream.
-  Use ``sha3_512`` instead of ``sha3_256`` for the ``StreamHMAC`` final HMAC
   & slice the first bytes designated by the package's ``commons.py`` module.
   This allows the HMAC length to be specified & changed easily. It's
   **highly discouraged** to use anything less than 32-bytes.


Minor Changes
^^^^^^^^^^^^^

-  Internal refactorings.
-  Updates to tests.




Changes for version 0.20.7
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Changed the way the ``Padding.(a)end_padding`` methods calculate the
   required padding length. The change causes the methods to now assume
   that the plaintext has already been prepended with the start padding.
-  The various ``test_*`` & ``verify_*`` functions/methods throughout the
   package have been changed to return ``None`` on successful validation
   instead of ``True``, which more closely matches the convention for
   exception-raising validators.
-  The default ``block_id`` length was changed from 16-bytes to 24-bytes.


Minor Changes
^^^^^^^^^^^^^

-  Make the ``(a)end_padding`` methods of the ``Padding`` class assume the
   supplied data has already been prepended with the start padding. This
   better integrates with streams of plaintext (online usage).
-  Small internal refactorings.
-  Documentation fixes.




Changes for version 0.20.6
--------------------------


Major Changes
^^^^^^^^^^^^^

-  The ``(Async)Database`` classes now support storing raw ``bytes`` type
   tag entries! This is a huge boon to time/space efficiency when needing
   to store large binary files, since they don't need to be converted to
   & from base64. This feature was made possible with only very minor
   changes to the classes, & they're fully backwards-compatible! Older
   versions will not be able handle raw ``bytes`` entries, but old JSON
   serializable entries work the same way they did.


Minor Changes
^^^^^^^^^^^^^

-  Docfixes.
-  Small refactorings.
-  Add new tests & make existing tests complete faster.
-  Support empty strings to be passed to the ``(Async)Database`` constructors'
   ``directory`` kwarg, signifying the current directory. Now ``None`` is
   the only falsey value which triggers the constructors to use the default
   database directory.
-  Fixed a bug in the ``AsyncDatabase`` class' ``aset_tag`` method, which
   would throw an attribute error when passed the ``cache=False`` flag.
-  Add Windows support to the CI tests.




Changes for version 0.20.5
--------------------------


Minor Changes
^^^^^^^^^^^^^

-  Include the missing changelog entries for ``v0.20.4``.




Changes for version 0.20.4
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Add ``python3.10`` support by copying the ``async_lru`` package's main module
   from their more up-to-date github repository instead of from PyPI.


Minor Changes
^^^^^^^^^^^^^

-  Small refactorings & code cleanups.
-  Documentation updates.
-  Type-hinting updates.
-  Cleanups to the package's module API.
-  Improve CI & extend to ``python3.10``.




Changes for version 0.20.3
--------------------------


Minor Changes
^^^^^^^^^^^^^

-  Small refactorings.
-  Documentation updates.
-  Type-hinting updates.
-  Additional tests.




Changes for version 0.20.2
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Changed the ``Padding`` class' ``(a)check_timestamp`` methods to
   ``(a)test_timestamp``, to better match the naming convention in the
   rest of the package.
-  Removed the ``(a)sum_sha3__(256/512)`` chainable generator methods from
   the ``Comprende`` class.
-  Removed the ``os.urandom`` based functions in the ``randoms.py`` module.


Minor Changes
^^^^^^^^^^^^^

-  Fixes & improvements to out of date documentation.
-  Small fixes to type-hints.
-  Small refactorings.
-  Add ``(a)generate_key`` functions to the package & ``(Async)Keys`` classes.
-  Fix some exception messages.




Changes for version 0.20.1
--------------------------


Minor Changes
^^^^^^^^^^^^^

-  Small fixes & improvements to documentation.
-  Small fixes & improvements to tests.
-  Small fixes to type-hints.
-  Small re-organization of source file contents.
-  Small bug fixes.




Changes for version 0.20.0 (Backwards incompatible updates)
-----------------------------------------------------------


Major Changes
^^^^^^^^^^^^^

-  The ``(a)json_(en/de)crypt`` & ``(a)bytes_(en/de)crypt`` functions &
   methods now only expect to work with ``bytes`` type ciphertext. And,
   the low-level cipher generators expect iterables of bytes where they
   used to expect iterables of integers.
-  The ``pid`` keyword-only argument throughout the package was changed
   to ``aad`` to more clearly communicate its purpose as authenticated
   additional data.
-  The ``key``, ``salt`` & ``aad`` values throughout the package are now
   expected to be ``bytes`` type values.
-  The ``key`` must now be at least 32-bytes for use within the ``Chunky2048``
   cipher & its interfaces.
-  The ``salt``, for use in the ``Chunky2048`` cipher & its interfaces,
   was decreased from needing to be 32-bytes to 24-bytes.
-  The ``siv``, for use in the ``Chunky2048`` cipher & its interfaces, was
   increased from needing to be 16-bytes to 24-bytes.
-  The new ``KeyAADBundle`` class was created as the primary interface
   for consuming ``key``, ``salt``, ``aad`` & ``siv`` values. This class'
   objects are the only ones that are used to pass around these values
   in low-level ``Chunky2048`` cipher functionalities. The higher-level
   cipher functions are the only public interfaces that still receive
   these ``key``, ``salt``, & ``aad`` values.
-  The ``KeyAADBundle`` now manages the new initial key derivation of the
   ``Chunky2048`` cipher. This new algorithm is much more efficient,
   utilizing the output of the keystream's first priming call instead of
   throwing it away, removing the need for several other previously used
   hashing calls.
-  The ``bytes_keys`` & ``abytes_keys`` keystream generator algorithms
   were improved & made more efficient. They also now only receive ``bytes``
   type coroutine values or ``None``.
-  The ``StreamHMAC`` algorithms were improved & made more efficient.
-  The ``Chunky2048`` class now creates instance's that initialize, & who's
   methods are callable, much more efficiently by reducing its previously
   dynamic structure. Its now reasonable to use these instances in code
   that has strict performance requirements.
-  The ``Keys`` & ``AsyncKeys`` classes were trimmed of all instance
   behaviour. They are now strictly namespaces which contain static or
   class methods.
-  All instance's of the word `password` throughout the package have been
   replaced with the word `passphrase`. The ``Passcrypt`` class now only
   accepts ``bytes`` type ``passphrase`` & ``salt`` values. The returned
   hashes are also now always ``bytes``.
-  The ``Padding`` & ``BytesIO`` classes' functionalities were made more
   efficient & cleaned up their implementations.
-  New ``PackageSigner`` & ``PackageVerifier`` classes were added to the
   ``keygens.py`` module to provide an intuituve API for users to sign their
   own packages. This package now also uses these classes to sign itself.
-  The new ``gentools.py`` module was created to organize the generator
   utilities that were previously scattered throughout the package's
   top-level namespaces.
-  The new ``_exceptions.py`` module was created to help organize the
   exceptions raised throughout the package, improving readability
   & maintainability.
-  The new ``_typing.py`` module was added to assist in the long process
   of adding functional type-hinting throughout the package. For now,
   the type hints that have been added primarily function as documentation.
-  A new ``Slots`` base class was added to the ``commons.py`` module to
   simplify the creation of more memory efficient & performant container
   classes. The new ``_containers.py`` module was made for such classes
   for use throughout the package. And, most classes throughout the
   package were given ``__slots__`` attributes.
-  A new ``OpenNamespace`` class was added, which is a subclass of ``Namespace``,
   with the only difference being that instances do not omit attributes
   from their repr's.
-  The new ``(a)bytes_are_equal`` functions, which are pointers to
   ``hmac.compare_digest`` from the standard library, have replaced the
   ``(a)time_safe_equality`` functions.
-  The ``(a)sha_256(_hmac)`` & ``(a)sha_512(_hmac)`` functions have had
   their names changed to ``(a)sha3__256(_hmac)`` & ``(a)sha3__512(_hmac)``.
   This was done to communicate that they are actually SHA3 functions,
   but the double underscore is to keep them differentiable from the
   standard library's ``hashlib`` objects. They can now also return
   ``bytes`` instead of hex strings if their ``hex`` keyword argument is truthy.
-  The base functionality of the ``Comprende`` class was refactored out into a
   ``BaseComprende`` class. The chainable data processor generator methods
   remain in the ``Comprende`` class. Their endpoint methods (such as ``(a)list``
   & ``(a)join``) have also been changed so they don't cache results by default.
-  The ``Passcrypt`` class' ``kb`` & ``hardness`` can now be set to values
   independently from one another. The algorithm runs on the new
   ``(a)bytes_keys`` coroutines, & a slightly more effective cache building
   procedure.
-  The databases classes now don't preload their values by default. And,
   various methods which work with tags & metatags have been given a
   ``cache`` keyword-only argument to toggle on/off the control of using
   the cache for each operation.
-  New method additions/changes to the database classes:

   -  ``(a)rollback_tag``, ``(a)clear_cache``, & a ``filenames`` property
      were added.
   -  ``(a)hmac`` was changed to ``(a)make_hmac``, & now returns ``bytes`` hashes.
   -  ``(a)save`` was changed to ``(a)save_database``.
   -  ``(a)query`` was changed to ``(a)query_tag``.
   -  ``(a)set`` was changed to ``(a)set_tag``.
   -  ``(a)pop`` was changed to ``(a)pop_tag``.
   -  The ``tags``, ``metatags`` & ``filenames`` properties now return sets
      instead of lists.

-  The ``Ropake`` class has been removed from the package pending changes to
   the protocol & its implementation.
-  The ``(a)generate_salt`` function now returns ``bytes`` type values,
   & takes a ``size`` keyword-only argument, with no default, that determines
   the number of bytes returned between [8, 64].
-  The ``(a)random_512`` & ``(a)random_256`` public functions can now cause
   their underlying random number generators to fill their entropy pools
   when either the ``rounds`` or ``refresh`` keyword arguments are specified.
-  The following variables were removed from the package:

   -  ``(a)keys``, ``(a)passcrypt``, ``(a)seeder``, ``(a)time_safe_equality``,
      ``Datastream``, ``bits``, ``(a)seedrange``, ``(a)build_tree``,
      ``(a)customize_parameters``, ``convert_class_method_to_member``,
      ``convert_static_method_to_member``, ``(a)xor``, ``(a)padding_key``,
      ``(a)prime_table``, ``(a)unique_range_gen``, ``(a)non_0_digits``,
      ``(a)bytes_digits``, ``(a)digits``, ``(a)permute``, ``(a)shuffle``,
      ``(a)unshuffle``, ``(a)create_namespace``,
      (``(a)depad_plaintext``, ``(a)pad_plaintext`` & their generator forms.
      Only the non-generator forms remain in the ``Padding`` class), (The
      ``(a)passcrypt``, ``(a)uuids``, ``(a)into_namespace`` methods from the
      database classes), (The ``(a)csprbg`` functions were removed & instead
      the ``(a)csprng`` functions produce ``bytes`` type values.)

-  Thorough & deep refactorings of modules, classes & methods. Many methods
   & functions were made private, cleaning up the APIs of the package,
   focusing on bringing the highest-level functionalities to top level
   namespaces accessible to users. Some purely private functionalities
   were entirely moved to private namespaces not readily accessible to
   users.
-  Most of the constants which determine the functionalities throughout
   the package were refactored out into ``commons.py``. This allows
   for easy changes to protocols & data formats.


Minor Changes
^^^^^^^^^^^^^

-  Many documentation improvements, fixes, trimmings & updates.
-  Added a ``WeakEntropy`` class to the ``randoms.py`` module.




Changes for version 0.19.4
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Created a private ``EntropyDaemon`` class to run a thread in the
   background which feeds into & extracts entropy from some of the
   package's entropy pools. Also moved the separate private ``_cache``
   entropy pools from the parameters to the random number generators.
   They're now a single private ``_pool`` shared global that's
   asynchronously & continuously updated by the background daemon thread.
-  Switched the ``random`` portion of function names in the ``randoms.py``
   module to read ``unique`` instead. This was done to the functions which
   are actually pseudo-random. This should give users a better idea of
   which functions do what. The exception is that the ``random_sleep`` &
   ``arandom_sleep`` functions have kept their names even though they
   sleep a pseudo-randomly variable amount of time. Their names may
   cause more confusion if they were either ``(a)unique_sleep`` or
   ``(a)urandom_sleep``. Because they don't use ``os.urandom`` & what
   is a ``unique_sleep``? When / if a better name is found these
   function names will be updated as well.


Minor Changes
^^^^^^^^^^^^^

-  Various docstring / documentation fixes & refactorings.




Changes for version 0.19.3
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Removed ``ascii_encipher``, ``ascii_decipher``, ``aascii_encipher`` &
   ``aascii_decipher`` generators from the ``Chunky2048`` & ``Comprende``
   classes, & the package. It was unnecessary, didn't fit well with the
   intended use of the ``Padding`` class, & users would be much better
   served by converting their ascii to bytes to use the ``bytes_``
   generators instead.
-  Removed the ``map_encipher``, ``map_decipher``, ``amap_encipher`` &
   ``amap_decipher`` generators from the ``Chunky2048`` & ``Comprende``
   classes, & the package. They were not being used internally to the
   package anymore, & their functionality, security & efficiency could
   not be guaranteed to track well with the changes in the rest of the
   library.
-  Added domain specificity to the ``X25519`` protocols' key derivations.
-  Renamed the database classes' ``(a)encrypt`` & ``(a)decrypt`` methods
   to ``(a)json_encrypt`` & ``(a)json_decrypt`` for clarity & consistency
   with the rest of the package. Their signatures, as well as those in
   ``(a)bytes_encrypt`` & ``(a)bytes_decrypt``, were also altered to
   receive plaintext & ciphertext as their only positional arguments.
   The ``filename`` argument is now a keyword-only argument with a default
   ``None`` value. This allows databases to be used more succinctly for
   manual encryption & decryption by making the filename tweak optional.
-  The ``runs`` keyword argument for the functions in ``randoms.py`` was
   renamed to ``rounds``. It seems more clear that it is controlling the
   number of rounds are internally run within the ``(a)random_number_generator``
   functions when deriving new entropy.


Minor Changes
^^^^^^^^^^^^^

-  Fixes to docstrings & tutorials. Rewrite & reorganization of the
   ``PREADME.rst`` & ``README.rst``. More updates to the readme's are still
   on the way.
-  Slight fix to the Passcrypt docstring's algorithm diagram.
-  Moved the default passcrypt settings to variables in the ``Passcrypt``
   class.
-  Added the ability to send passcrypt settings into the ``mnemonic`` &
   ``amnemonic`` coroutines, which call the algorithm internally but
   previously could only use the default settings.
-  Some code cleanups & refactorings.




Changes for version 0.19.2
--------------------------


Minor Changes
^^^^^^^^^^^^^

-  Made the output lengths of the ``Padding`` class' generator functions
   uniform. When the footer padding on a stream of plaintext needs to
   exceed the 256-byte blocksize (i.e. when the last unpadded plaintext
   block's length ``L`` is ``232 < L < 256``), then another full block of
   padding is produced. The generators now yield 256-byte blocks
   consistently (except during depadding when the last block of plaintext
   may be smaller than the blocksize), instead of sometimes producing a
   final padded block which is 512 bytes.




Changes for version 0.19.1
--------------------------


Minor Changes
^^^^^^^^^^^^^

-  Fixed a bug where database classes were evaluating as falsey when they
   didn't have any tags saved in them. They should be considered truthy
   if they're instantiated & ready to store data, even if they're
   currently empty & not saved to disk. This was reflected in their
   ``__bool__`` methods. The bug caused empty metatags not to be loaded
   when an instance loads, even when ``preload`` is toggled ``True``.
-  Removed the coroutine-receiving logic from the ``Padding`` class'
   ``Comprende`` generators. Since they buffer data, the received values
   aren't ever going to coincide with the correct iteration & will be
   susceptible to bugs
-  Fixed a bug in the ``Padding`` class' ``Comprende`` generators which
   cut iteration short because not enough data was available from the
   underlying generators upfront. Now, if used correctly to pad/depad
   chunks of plaintext 256 bytes at a time, then they work as expected.
-  The ``update``, ``aupdate``, ``update_key`` & ``aupdate_key`` methods
   in both the ``StreamHMAC`` & ``DomainKDF`` classes now return ``self``
   to allow inline updates.
-  Added ``acsprng`` & ``csprng`` function pointers to the ``Chunky2048``
   class.
-  Updates to docstrings which didn't get updated with info on the new
   *synthetic IV* feature.
-  Some other docstring fixes.
-  Some small code cleanups & refactorings.




Changes for version 0.19.0
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Security Upgrade: The package's cipher was changed to an online,
   authenticated scheme with salt misuse-reuse resistance. This was
   acheived through a few backwards incompatible techniques:

   1. A synthetic IV (SIV) is calculated from the keyed-hash of the first
      256-byte block of plaintext. The SIV is then used to seed the
      keystream generator, & is used to update the validator object. This
      ensures that if the first block is unique, then the whole ciphertext
      will be unique.
   2. A 16-byte ephemeral & random SIV-key is also prepended to the
      first block of plaintext during message padding. Since this value
      is also hashed to derive the SIV, this key gives a strong
      guarantee that a given message will produce a globally unique
      ciphertext.
   3. An 8-byte timestamp is prepended to the first block of plaintext
      during padding. Timestamps are inherently sequential, they can be
      verified by a user within some bounds, & can also be used to
      mitigate replay attacks. Since it's hashed to make the SIV, then
      it helps make the entire ciphertext unique.
   4. After being updated with each block of ciphertext, the validator's
      current state is again fed into the keystream generator as a new
      rotating seed. This mitigation is limited to ensuring only that
      every following block of ciphertext to a block which is unique
      will also be unique. More specifically this means that: **if**
      *all* **other mitigations fail to be unique**, or are missing, then
      the first block which is unique **will appear the same**, except
      for the bits which have changed, **but, all following blocks will
      be randomized.** This limitation could be avoided with a linear
      expansion in the ciphertext size by generating an SIV for each
      block of plaintext. This linear expansion is prohibitive as a
      default setting, but the block level secrecy, even when all other
      mitigations fail, is enticing. This option may be added in the
      future as a type of padding mode on the plaintext.

   The SIV-key is by far the most important mitigation, as it isn't
   feasibly forgeable by an adversary, & therefore also protects against
   attacks using encryption oracles. These changes can be found in the
   ``SyntheticIV`` class, the (en/de)cipher & xor generators, & the
   ``StreamHMAC`` class in the ``ciphers.py`` module. The padding
   changes can also be found in the new ``Padding`` class in the ``generics.py``
   module. The SIV is attached in the clear with ciphertexts & was
   designed to function with minimal user interaction. It needs only to
   be passed into the ``StreamHMAC`` class during decryption -- during
   encryption it's automatically generated & stored in the ``StreamHMAC``
   validator object's ``siv`` property attribute.
-  Security Patch: The internal ``sha3_512`` kdf's to the  ``akeys``, ``keys``,
   ``abytes_keys`` & ``bytes_keys`` keystream generators are now updated
   with 72 bytes of (64 key material + 8 padding), instead of just 64
   bytes of key material. 72 bytes is the *bitrate* of the ``sha3_512``
   object. This change causes the internal state of the object to be permuted
   for each iteration update & before releasing a chunk of key material.
   Frequency analysis of ciphertext bytes didn't smooth out to the
   cumulative distribution expected for all large ciphertexts prior to
   this change. But after the change the distribution does normalize as
   expected. This indicates that the key material streams were biased
   away from random in a small but measurable way. Although, no
   particular byte values seem to have been preferred by this bias, this
   is a huge shortcoming with unknown potential impact on the strength
   of the package's cipher. This update is strongly recommended & is
   backwards incompatible.
-  This update gives a name to the package's pseudo-one-time-pad cipher
   implementation. It's now called ``Chunky2048``! The ``OneTimePad``
   class' name was updated to ``Chunky2048`` to match the change.
-  The ``PreemptiveHMACValidation`` class & its related logic in the
   ``StreamHMAC`` class was removed. The chaining of validator output
   into the keystream makes running the validator over the ciphertext
   separately or prior to the decryption process very costly. It would
   either mean recalculating the full hash of the ciphertext a second
   time to reproduce the correct outputs during each block, or a large
   linear memory increase to hold all of its digests to be fed in some
   time after preemtive validation. It's much simpler to remove that
   functionality & potentially replace it with something else that fits
   the user's applications better. For instance, the ``current_digest``
   & ``acurrent_digest`` methods can produce secure, 32-byte authentication
   tags at any arbitrary blocks throughout the cipher's runtime, which
   validate the cipehrtext up to that point. Or, the ``next_block_id``
   & ``anext_block_id`` methods, which are a more robust option because
   each id they produce validates the next ciphertext block before
   updating the internal state of the validator. This acts as an
   automatic message ordering algorithm, & leaves the deciphering
   party's state unharmed by dropped packets or manipulated ciphertext.
-  The ``update_key`` & ``aupdate_key`` methods were also added to the
   ``StreamHMAC`` class. They allow the user to update the validators'
   internal key with new entropy or context information during its
   runtime.
-  The ``Comprende`` class now takes a ``chained`` keyword-only argument
   which flags an instance as a chained generator. This flag allows
   instances to communicate up & down their generator chain using the
   shared ``Namespace`` object accessible by their ``messages`` attribute.
-  The chainable ``Comprende`` generator functions had their internals
   altered to allow them to receive, & pass down their chain, values
   sent from a user using the standard coroutine ``send`` & ``asend``
   method syntax.
-  ``Comprende`` instances no longer automatically reset themselves every
   time they enter their context managers or when they are iterated over.
   This makes their interface more closely immitate the behavior of
   async/sync generator objects. To get them to reset, the ``areset`` or
   ``reset`` methods must be used. The message chaining introduced in
   this update allows chains of ``Comprende`` async/sync generators to
   inform each other when the user instructs one of them to reset.
-  The standard library's ``hmac`` module is now used internally to the
   ``generics.py`` module's ``sha_512_hmac``, ``sha_256_hmac``, ``asha_512_hmac``
   & ``asha_256_hmac`` functions. They still allow any type of data to be
   hashed, but also now default to hashing ``bytes`` type objects as
   they are given.
-  The new ``Domains`` class, found in ``generics.py``, is now used to
   encode constants into deterministic pseudo-random 8-byte values for
   helping turn hash function outputs into domain-specific hashes. Its
   use was included throughout the library. This method has an added
   benefit with respect to this package's usage of SHA-3. That being, the
   *bitrate* for both ``sha3_512`` & ``sha3_256`` are ``(2 * 32 * k) + 8``
   bytes, where ``k = 1`` for ``sha3_512`` & ``k = 2`` for ``sha3_256``.
   This means that prepending an 8-byte domain string to their inputs
   also makes it more efficient to add some multiple of key material
   to make the input data precisely equal the *bitrate*. More info on
   domain-specific hashing can be found here_.

.. _here: https://eprint.iacr.org/2020/241.pdf

-  A new ``DomainsKDF`` class in ``cipehrs.py`` was added to create a
   more standard & secure method of key derivation to the library which
   also incorporates domain separation. Its use was integrated thoughout
   the ``AsyncDatabase`` & ``Database`` classes to mitigate any further
   vulnerabilities of their internal key-derivation functions. The
   database classes now also use bytes-type keys internally, instead
   of hex strings.
-  The ``Passcrypt`` class now contains methods which create & validate
   passcrypt hashes which have their settings & salt attached to them.
   Instances can now also be created with persistent settings that are
   automatically sent into instance methods.


Minor Changes
^^^^^^^^^^^^^

-  Many fixes of docstrings, typos & tutorials.
-  Many refactorings: name changes, extracted classes / functions,
   reorderings & moves.
-  Various code clean-ups, efficiency & usability improvements.
-  Many constants used throughout the library were given names defined
   in the ``commons.py`` module.
-  Removed extraneous functions throughout the library.
-  The asymmetric key generation & exchange functions/protocols were
   moved from the ``ciphers.py`` module to ``keygens.py``.
-  Add missing modules to the MANIFEST.rst file.
-  Added a ``UniformPrimes`` class to the ``__datasets`` module for efficient
   access to primes that aren't either mostly 1 or 0 bits, as is the case for
   the ``primes`` helper table. These primes are now used in the ``Hasher``
   class' ``amask_byte_order`` & ``mask_byte_order`` methods.
-  The ``time_safe_equality`` & ``atime_safe_equality`` methods are now
   standalone functions available from the ``generics.py`` module.
-  Added ``reset_pool`` to the ``Processes`` & ``Threads`` classes. Also
   fixed a missing piece of logic in their ``submit`` method.
-  Added various conversion values & timing functions to the ``asynchs.py``
   module.
-  The ``make_uuid`` & ``amake_uuid`` coroutines had their names changed to
   ``make_uuids`` & ``amake_uuids``.
-  Created a new ``Datastream`` class in ``generics.py`` to handle buffering
   & resizing iterable streams of data. It enables simplifying logic that
   must happen some number of iterations before the end of a stream. It's
   utilized in the ``Padding`` class' generator functions available as
   chainable ``Comprende`` methods.
-  The ``data`` & ``adata`` generators can now produce a precise number of
   ``size``-length ``blocks`` as specified by a user. This gets rid of the
   confusing usage of the old ``stop`` keyword-only argument, which stopped
   a stream after *approximately* ``size`` number of elements.
-  Improved the efficiency & safety of entropy production in the
   ``randoms.py`` module.



Changes for version 0.18.1
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Security Patch: Deprecated & replaced an internal kdf for saving
   database tags due to a vulnerability. If an adversary can get a user
   to reveal the value returned by the ``hmac`` method when fed the tag
   file's filename & the salt used for that encrypted tag, then they
   could deduce the decryption key for the tag. A version check was
   added only for backwards compatibility & will be removed on the next
   update. All databases should continue functioning as normal, though
   all users are advised to **re-save their databases** after upgrading
   so the new kdf can be used. This will not overwrite the old files,
   so they'll need to be deleted manually.
-  Replaced usage of the async ``switch`` coroutine with ``asyncio.sleep``
   because it was not allowing tasks to switch as it was designed to.
   Many improvements were made related to this change to make the
   package behave better in async contexts.
-  Removed the private method in the database classes which held a
   reference to the root salt. It's now held in a private attribute.
   This change simplifies the code a bit & allows instances to be
   pickleable.
-  The ``atimeout`` & ``timeout`` chainable ``Comprende`` generator
   methods can now stop the generators' executions mid-iteration. They
   run them in separate async tasks or thread pools, respectively, to
   acheive this.
-  The ``await_on`` & ``wait_on`` generators now restart their timeout
   counters after every successful iteration that detected a new value
   in their ``queue``. The ``delay`` keyword argument was changed to
   ``probe_frequency``, a keyword-only argument.
-  Removed the package's dependency on the ``aioitertools`` package.
-  Made the ``sympy`` package an optional import. If any of its
   functionalities are used by the user, the package is only then
   imported & this is done automatically.
-  Various streamlining efforts were made to the imports & entropy
   initialization to reduce the package's import & startup time.


Minor Changes
^^^^^^^^^^^^^

-  Fixes of various typos, docstrings & tutorials.
-  Various cleanups, refactorings & efficiency improvements.
-  Added new tests for detecting malformed or modified ciphertexts.
-  Removed extraneous functions in ``generics.py``.
-  Add a ``UNIFORM_PRIME_512`` value to ``__datasets.py`` for use in the
   ``Hasher.mask_byte_order`` & ``Hasher.amask_byte_order`` methods.
   Those methods were also altered to produce more uniform looking
   results. The returned masked values are now also 64 bytes by default.
-  Added an ``automate_key_use`` keyword-only boolean argument to the init
   for the ``OneTimePad``, ``Keys`` & ``AsyncKeys`` classes. It can be toggled to
   stop the classes from overwriting class methods so they
   automatically read the instance's key attribute. This optionally
   speeds up instantiation by an order of magnitude at the cost of
   convenience.
-  Fixed ``asynchs.Threads`` class' wrongful use of a ``multiprocessing``
   ``Manager.list`` object instead of a regular list.
-  Changed the ``_delay`` keyword-only argument in ``Processes`` & ``Threads``
   classes' methods to ``probe_freqeuncy`` so users can specify how often
   results will be checked for after firing off a process, thread, or
   associated pool submission.
-  Now the ``asubmit`` & ``submit`` methods in ``Processes`` & ``Threads``
   can accept keyword arguments.
-  Added ``agather`` & ``gather`` methods to the ``Threads`` & ``Processes``
   classes. They receive any number of functions, & ``args`` &/or ``kwargs`` to
   pass to those functions when submitting them to their associated
   pools.
-  Changed the ``runsum`` instance IDs from hex strings to bytes & cleaned
   up the instance caching & cleaning logic.
-  Altered & made private the ``asalted_multiply`` & ``salted_multiply``
   functions in the ``randoms.py`` module.
-  Started a new event loop specific to the ``randoms.py`` module which
   should prevent the ``RuntimeError`` when ``random_number_generator``
   is called from within the user's running event loop.
-  Added a ``ValueError`` check to the ``(a)cspr(b/n)g`` functions in
   ``randoms.py``. This will allow simultaneously running tasks to
   request entropy from the function by returning a result from a
   newly instantiated generator object.
-  Added checks in the ``*_encipher`` & ``*_decipher`` generators to
   help assure users correctly declare the mode for their StreamHMAC
   validator instances.
-  Fixed the ``__len__`` function in the database classes to count the
   number of tags in the database & exclude their internal maintenaince
   files.
-  The ``TimeoutError`` raised after decrypting a ciphertext with an
   expired timestamp now contains the seconds it has exceeded the ``ttl``
   in a ``value`` attribute.
-  The timestamp used to sign the package now displays the day of
   signing instead of the second of signing.
-  The ``(a)sum_sha_*`` & ``(a)sum_passcrypt`` generators were altered to
   reapply the supplied ``salt`` on every iteration.
-  Stabilized the usability of the ``stop`` keyword-only argument in the
   ``adata`` & ``data`` generators. It now directly decides the total
   number of elements in a ``sequence`` allowed to be yielded.




Changes for version 0.18.0
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Security Patch: Rewrote the HMAC-like creation & authentication
   process for all of the package's ciphers. Now, the ``*_encipher``
   & ``*_decipher`` ``Comprende`` generators must be passed a validator
   object to hash the ciphertext as it's being created / decrypted.
   The ``StreamHMAC`` class was created for this purpose. It's initalized
   with the user's long-term key, the ephemeral salt & the pid value.
   The pid value can now effectively be used to validate additional data.
   These changes force the package's cipher to be used as an AEAD cipher.
-  Security Patch: The package's ``*_hmac`` hash functions & the ``Comprende``
   class' hash generators were rewritten to prepend salts & keys to data
   prior to hashing instead of appending. This is better for several
   important reasons, such as: reducing the amortizability of costs in
   trying to brute-force hashes, & more closely following the reasoning
   behind the HMAC spec even though sha3 has a different security profile.
-  Algorithm Patch: The ``akeys``, ``keys``, ``abytes_keys``, & ``bytes_keys``
   algorithms have been patched to differentiate each iteration's two
   sha3_512 hashes from one another in perpetuity. They contained a design
   flaw which would, if both sha3_512 objects landed upon the same
   1600-bit internal state, then they would produce the same keystreams
   from then on. This change in backwards incompatible. This flaw is
   infeasible to exploit in practice, but since the package's hashes &
   ciphertext validations were already channging this release, there was
   no reason to not fix this flaw so that it's self-healing if they ever
   do land on the same internal states.
-  The ``Passcrypt`` class & its algorithm were made more efficient to
   better equalize the cost for users & adversaries & simplifies the
   algorithm. Any inefficiencies in an implementation would likely cause
   the adversary to be able to construct optimized implementations to
   put users at an even greater disadvantage at protecting their inputs
   to the passcrypt algorithm. It used the ``sum_sha_256`` hash function
   internally, & since it was also changing in a non-backwards
   compatible way with this update, it was the best time to clean up
   the implementation.
-  Updated the package's description & its docstrings that refer to
   the package's cipher as an implementation of the one-time-pad. It's
   not accurate since the package uses pseudo-random hash functions to
   produce key material. Instead, the package's goal is to create a
   pseudo-one-time-pad that's indistinguishable from a one-time-pad.
   The ``OneTimePad`` class will keep its name for succinctness.
-  New ``amake_token``, ``make_token``, ``aread_token`` & ``read_token``
   class & instance methods added to the ``OneTimePad`` class. These
   tokens are urlsafe base64 encoded, are encrypted, authenticated &
   contain timestamps that can enforce a time-to-live for each token.
-  Non-backwards compatible changes to the database classes' filenames,
   encryption keys & HMACs. The ``*_hmac`` hash functions that the
   databases rely on were changing with this update, so additionally the
   filenames table used to encode the filenames was switched from the
   ``BASE_36_TABLE`` to the ``BASE_38_TABLE``. Both tables are safe for
   uri's across all platforms, but the new table can encode information
   slightly more efficiently.
-  Major refactorings & signature changes across the package to make
   passing keys & salts to ``*_hmac`` functions & the ``Comprende``
   class' hash generators explicit.
-  Removed the ``of`` keyword argument from all of the ``Comprende``
   class' generators. It was overly complicating the code, & was not
   entirely clear or useful for settings outside of the ``tags`` &
   ``atags`` generators.
-  Removed ``pybase64`` from the package & its dependencies list. The
   built-in python ``base64`` module works just fine.
-  Sorted the ``WORDS_LIST``, ``ASCII_ALPHANUMERIC``, & ``BASE_64_TABLE``
   datasets.
-  The ``salt`` & ``asalt`` functions have been renamed to ``generate_salt``
   & ``agenerate_salt`` for clarity's sake, & to reduce naming
   collisions.
-  Added another redundancy to the ``arandom_number_generator`` &
   ``random_number_generator`` functions. Now the async tasks it prepares
   into a list are pseudo-randomly shuffled before being passed into
   ``asyncio.gather``.


Minor Changes
^^^^^^^^^^^^^

-  Added a logo image to the package.
-  Separated the FAQ section from ``PREADME.rst``.
-  The ``primes`` & ``bits`` datasets are now represented in hex in the
   source code.
-  Added a ``BASE_38_TABLE`` dataset to the package.
-  The database classes now fill an ephemeral dictionary of filenames
   that couldn't be used to successfully load a tag file, available from
   within the ``_corrupted_files`` attribute.
-  The ``Comprende`` class' ``acache_check`` & ``cache_check`` context
   manager methods are now called ``aauto_cache`` & ``auto_cache``.
-  Added new ``bytes_count`` & ``abytes_count`` generators to ``generics.py``
   module which increment each iteration & yield the results as bytes.
-  Removed the ``akeypair`` & ``keypair`` functions from the package.
   Their successors are the ``asingle_use_key`` & ``single_use_key`` methods
   in the ``AsyncKeys`` & ``Keys`` classes. The attempt is to clarify &
   put constraints on the interface for creating a bundle of key
   material that has a single-use-only salt attached, as well as the pid
   value.
-  Moved ciphertext encoding functions into the ``BytesIO`` class from
   the global ``generics.py`` module.
-  Split ``PrimeGroups`` into two classes, one higher-level class by the
   same name & a ``BasePrimeGroups`` class. The former also has some
   added functionality for masking the order of bytes in a sequence
   using an modular exponentiation.
-  The ``Hasher`` class now has functionality added to mask the order
   of a bytes sequence with a modular multiplication.
-  Fixed the name of the project in the attribution lines in several
   source files.
-  Reconciled tests with the major changes in this release.
-  The old identity key for the package that was signed by the gnupg
   identity key was shredded & replaced with a new signed key.
-  Several bug fixes to the ``setup.py`` automated code signing.




Changes for version 0.17.0
--------------------------


Major Changes
^^^^^^^^^^^^^

-  Security Patch: The HMAC verifiers on ciphertexts did not include
   the ``salt`` or ``pid`` values when deriving the HMAC. This
   associated data can therefore be changed to cause a party to
   decrypt a past ciphertext with a salt or pid of an attacker's
   choosing. This is a critical vulnerability & it is highly recommended
   all users update. The fix is to hash the ciphertext, ``salt``
   & ``pid`` together & sending that hash into the validator to have
   the HMAC created / tested. This change will cause all prior
   ciphertexts to be marked invalid by the validator.
-  Refactored the names of the Comprende cipher methods to better
   communicate their intended use as lower level tools that cannot be
   used on their own to obtain authenticated, CCA or CPA secure
   encryption.
-  Added more comprehensive tests for ``X25519`` & ``Ed25519`` classes,
   as well as the protocols that utilize the ``X25519`` ecdh exchange.
   Fixed some bugs in the process.
-  ``X25519`` instances that contain a secret key now have access to
   protocol methods which automatically pass their key in as a keyword
   argument. This simplifies their usage further.
-  Incorporated the new ``Hasher`` class into the package's random
   number generator to improve its entropy production.


Minor Changes
^^^^^^^^^^^^^

-  Various fixes to typos, docstrings & tutorials.
-  New tutorials & docs added.
-  Changed the default table in ``ByteIO`` 's ``json_to_ascii``, ``ajson_to_ascii``,
   ``ascii_to_json`` & ``aascii_to_json`` to the ``URL_SAFE_TABLE`` to
   facilitate the creation of urlsafe_tokens.
-  Removed all code in the ``Ropake`` class that was used to create a default
   database to store a default salt for users. All of that functionality
   is expected to be handled by the database classes' token & profile
   creation tools.
-  Fixed bug in package signing script that called hex from a string.
-  Updated the package signing script to include these metadata in the
   signatures of the ephemeral keys: name of the package, version, the
   date in seconds.
-  Added metadata to the ``setup.cfg`` file.
-  Make passcrypt objects available from the ``keygens`` module.
-  Add more consistent ability within ``Ropake`` class to specify a
   time-to-live for protocol messages.
-  Added check to make sure instances of ``X25519`` & ``Ed25519`` are
   not trying to import a new secret key once they already have one.
   This won't be allowed in favor of creating a new object for a new
   secret key.
-  Fixed bug in database classes' bytes ciphers which called themselves
   recursively instead of calling the global functions of the same name.




Changes for version 0.16.0
--------------------------


Major Changes
^^^^^^^^^^^^^

-  All ``Database`` & ``AsyncDatabase`` filenames have been converted to
   base36 to aid in making the manifest files & the databases as a whole
   more space efficient. These changes are not backwards compatible.
-  More work was done to clean up the databases & make them more
   efficient, as well as equalize the sizes of the database files to
   mitigate leaking metadata about what they might contain.
-  Added new ``X25519`` & ``Ed25519`` classes that greatly simplify the
   usage of the cryptography module's 25519 based tools. They also help
   organize the codebase better -- where ``Ropake`` was holding onto
   all of the asymmetric tooling even though those tools were not part
   of the Ropake protocol.
-  New base & helper ``Asymmetric25519`` & ``BaseEllipticCurve`` classes
   were added as well to facilitate the reorganization.
-  Many methods in ``Ropake`` were turned private to simplify & clean up
   the interface so its intended use as a protocol is more clear for users.
-  Added the time-to-live functionality to ``Ropake`` decryption functions.
   The ``TIMEOUT`` attribute on the class can also be changed to import
   a global time-to-live for all ``Ropake`` ciphertexts.
-  Removed all ``nc_`` hash functions from the package/generics.py module.
-  The ``Namespace`` class now has a ``keys`` method so that namespaces
   can be unpacked using star-star syntax.
-  Because of the ongoing failures of gnupg, we are moving away from
   signing our packages with gnupg. Our new Ed25519 keys will be from
   the cryptography package, & we'll sign those with our gnupg key as a
   secondary form of attestation. Our package signing will be automated
   in the setup.py file & the methods we use will be transparent in the
   code. The new signatures for each package version will be placed in
   the file ``SIGNATURES.txt``.


Minor Changes
^^^^^^^^^^^^^

-  Many fixes & additions to docstrings & tutorials.
-  Massive refactorings, cleanups & typo fixes across the library,
   especially in the database classes, ``Ropake`` & the ``ciphers`` module.
-  Added comprehensive functional tests for the Ropake class.
-  Added ``BASE_36_TABLE`` to the ``commons`` module.
-  Fixed metadata issues in setup.py that caused upload issues to pypi.
-  The ``generate_profile``, ``load_profile``, ``agenerate_profile`` &
   ``aload_profile`` database methods now accept arbitrary keyword arguments
   that get passed into the database's __init__ constructor.
-  ``username`` & ``password`` are now required keyword-only arguments
   to the ``agenerate_profile_tokens`` & ``generate_profile_tokens``
   classmethods.
-  The ``aload`` & ``load`` database methods now take a ``manifest`` kwarg
   that when toggled ``True`` will also refresh the manifest file from
   disk.
-  Now when a database object is ordered to delete itself, the entirety
   of the instance's caches & attribute values are cleared & deleted.
-  Filled out the references to strong key generators & protocols in the
   ``keygens`` module.




Changes for version 0.15.0
--------------------------


Major Changes
^^^^^^^^^^^^^

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
   generators & encryption / decryption functions, further tighening up
   the api.


Minor Changes
^^^^^^^^^^^^^

-  Added ``this_second`` function to ``asynchs`` module for integer time.
-  Added ``apadding_key``, ``padding_key``, ``aplaintext_stream`` &
   ``plaintext_stream`` functions to the ``ciphers`` module.
-  Added ``apadding_key``, ``padding_key`` to the ``keygens`` module &
   ``AsyncKeys`` & ``Keys`` classes.
-  Added ``axi_mix``, ``xi_mix``, ``acheck_timestamp``, ``check_timestamp``,
   to the ``generics`` module.
-  Added ``acsprbg``, ``csprbg``, ``asalt``, ``salt``, ``apadding_key``,
   ``padding_key``, ``aplaintext_stream`` & ``plaintext_stream`` functions
   to OneTimePad class as ``staticmethod`` & instance methods.
-  Added ``acheck_timestamp`` & ``check_timestamp`` functions to the
   ``BytesIO`` class.
-  Added ``adeniable_filename`` & ``deniable_filename`` to the ``paths``
   module.
-  Removed check for falsey data in encryption functions. Empty data is
   & should be treated as valid plaintext.
-  Various refactorings, docstring fixes & efficiency improvements.
-  Added some new tests for database profiles.




Changes for version 0.14.0
--------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
--------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
--------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
--------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
--------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
--------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
-------------------------


Major Changes
^^^^^^^^^^^^^

-  Speed & efficiency improvements in the ``Comprende`` class & ``azip``.


Minor Changes
^^^^^^^^^^^^^

-  Various refactorings & code cleanups.
-  Added ``apop`` & ``pop`` ``Comprende`` generators to the library.
-  Switched the default character table in the ``ato_base``, ``to_base``,
   ``afrom_base``, & ``from_base`` chainable generator methods from the 62
   character ``ASCII_ALPHANUMERIC`` table, to the 95 character ``ASCII_TABLE``.
-  Made the digits generators in ``randoms.py`` automatically create a new
   cryptographically secure key if a key isn't passed by a user.
-  Some extra data processing functions added to ``generics.py``.




Changes for version 0.9.2
-------------------------


Major Changes
^^^^^^^^^^^^^

-  Added ``passcrypt`` & ``apasscrypt`` instance methods to ``OneTimePad``,
   ``Keys``, & ``AsyncKeys`` classes. They produce password hashes that are
   not just secured by the salt & passcrypt algorithm settings, but also by
   their main symmetric instance keys. This makes passwords infeasible to
   crack without also compromising the instance's 512-bit key.


Minor Changes
^^^^^^^^^^^^^

-  Further improvements to the random number generator in ``randoms.py``.
   Made its internals less sequential thereby raising the bar of work needed
   by an attacker to successfully carry out an order prediction attack.
-  Added checks in the ``Passcrypt`` class to make sure both a salt &
   password were passed into the algorithm.
-  Switched ``PermissionError`` exceptions in ``Passcrypt._validate_args``
   to ``ValueError`` to be more consistent with the rest of the class.
-  Documentation updates / fixes.




Changes for version 0.9.1
-------------------------


Minor Changes
^^^^^^^^^^^^^

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
-------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

-  Updates to documentation & ``README.rst`` tutorials.
-  The ``kb``, ``cpu``, & ``hardness`` arguments in ``sum_passcrypt`` &
   ``asum_passcrypt`` chainable generator methods were switched to keyword
   only arguments.




Changes for version 0.8.1
-------------------------


Major Changes
^^^^^^^^^^^^^

-  Added ``sum_passcrypt`` & ``asum_passcrypt`` chainable generator methods
   to ``Comprende`` class. They cumulatively apply the passcrypt algorithm
   to each yielded value from an underlying generator with the passcrypt'd
   prior yielded result used as a salt. This allows making proofs of work,
   memory & space-time out of iterations of the passcrypt algorithm very
   simple.


Minor Changes
^^^^^^^^^^^^^

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
-------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

-  Update ``CHANGES.rst`` file with the updates that were not logged for
   v0.7.1.
-  ``BYTES_TABLE`` was turned into a list so that the byte characters can
   be retrieved instead of their ordinal numbers.




Changes for version 0.7.1
-------------------------


Major Changes
^^^^^^^^^^^^^

-  Fix a mistake in the signatures of ``passcrypt`` & ``apasscrypt. The args
   ``kb``, ``cpu`` & ``hardness`` were changed into keyword only arguments
   to mitigate user mistakes, but the internal calls to those functions were
   still using positional function calls, which broke the api. This issue
   is now fixed.




Changes for version 0.7.0
-------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
-------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
-------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

-  Various code cleanups.
-  New tests added to the test suite for ``passcrypt`` & ``apasscrypt``.
-  The ``Comprende`` class' ``alist`` & ``list`` methods can now be passed
   a boolean argument to return either a ``mutable`` list directly from the
   lru_cache, or a copy of the cached list. This list is used by the
   generator itself to yield its values, so wilely magic can be done on the
   list to mutate the underlying generator's results.




Changes for version 0.5.0
-------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

-  Various code & logic cleanups / speedups.
-  Refactorings of the ``Database`` & ``AsyncDatabase`` classes.
-  Various inaccurate docstrings fixed.




Changes for version 0.4.0
-------------------------


Major Changes
^^^^^^^^^^^^^

-  Fixed bug in ``aiootp.abytes_encrypt`` function which inaccurately called
   a synchronous ``Comprende`` end-point method on the underlying async
   generator, causing an exception and failure to function.
-  Changed the procedures in ``akeys`` & ``keys`` that generate their internal
   key derivation functions. They're now slightly faster to initialize &
   more theoretically secure since each internal state is fed by a seed
   which isn't returned to the user. This encryption algorithm change is
   incompatible with the encryption algorithms of past versions.


Minor Changes
^^^^^^^^^^^^^

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
-------------------------


Minor Changes
^^^^^^^^^^^^^

-  Fixed bug where a static method in ``AsyncDatabase`` & ``Database`` was
   wrongly labelled a class method causing a failure to initialize.




Changes for version 0.3.0
-------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
-------------------------


Major Changes
^^^^^^^^^^^^^

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
^^^^^^^^^^^^^

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
-------------------------


Minor Changes
^^^^^^^^^^^^^

-  Initial version.


Major Changes
^^^^^^^^^^^^^

-  Initial version.



