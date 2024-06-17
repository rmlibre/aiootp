
`FAQ`
=====


Q: What is the one-time pad?
----------------------------

A: It's an inconvenient cipher which provides an information theoretic guarantee of confidentiality. Our goal is to design ciphers which achieve modern security notions, while minimizing inconveniences & still being able to make non-trivial statements, & information theoretic guarantees, against even computationally unbounded adversaries. In this effort, we've built what we hope to be a family of such candidate ciphers. Two concrete implementations being the ``Chunky2048`` & ``Slick256`` ciphers.




Q: How fast is this ``Chunky2048`` cipher?
------------------------------------------

A: Well, because it relies on ``hashlib.shake_128`` hashing to build key material streams, it's rather efficient. It can process about 40 MiB/s on a single ~1.5 GHz core for both encrypting & decrypting. This is still slow relative to other stream ciphers, but this package is written in pure Python & without hardware optimizations. Using SHA3 ASICs, specific chipset instructions, or a lower-level language implementation, could make this algorithm competitively fast.




Q: What size keys does the ``Chunky2048`` cipher use?
-----------------------------------------------------

A: It's been designed to work with any size of key >= 64 bytes.




Q: What's up with the ``AsyncDatabase`` / ``Database``?
-------------------------------------------------------

A: The idea is to create an intuitive, Pythonic interface to a transparently encrypted & decrypted key-value persistence tool that also cryptographically obscures metadata. They natively support raw bytes & JSON serializable data. They're also very well suited for async, concurrent, & distributed use-cases, since they organize collections of independent files for all of their data & administrative subdivisions. They're still works in progress, albeit very nifty ones.




Q: Why are the modules transformed into ``FrozenNamespace`` objects?
--------------------------------------------------------------------

A: We overwrite our modules in this package to have a more fine-grained control over what part of the package's internal state is exposed to users & applications. The goal is make it more difficult for users to inadvertently jeopardize their security tools, & minimize the attack surface available to adversaries. The ``FrozenNamespace`` class also makes it easier to coordinate & decide the library's UI/UX across the package.




`Known Issues`
==============

-  This package is currently in beta testing & active development,
   meaning major changes are still possible when there are really good
   reasons to do so. Contributions are welcome. Send us a message if
   you spot a bug or security vulnerability:

   -  gonzo.development@protonmail.ch
   -  rmlibre@riseup.net
   -  ed25519-key: 70d1740f2a439da98243c43a4d7ef1cf993b87a75f3bb0851ae79de675af5b3b
   -  x25519-key: 4457276dbcae91cc5b69f1aed4384b9eb6f933343bb44d9ed8a80e2ce438a450



