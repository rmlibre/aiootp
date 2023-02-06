_`FAQ` ............................................ `Table Of Contents`_
========================================================================


**Q: What is the one-time pad?**

A: It's a cipher which provides an information theoretic guarantee of confidentiality. It's typically thought to be too cumbersome a cipher for generalized application because it conveys strict, and well, cumbersome, requirements onto its users. The need for its keys to be at least as large as all the messages it's ever used to encrypt is one such requirement. Our goal is to design a cipher which immitates the one-time pad through clever algorithms, in such a way as to minimize its inconveniences & still provide some form of information theoretic confidentiality guarantees or, at a minimum, be able to make non-trivial statements about its security against even computationally unbounded adversaries. In this effort, we've built what we hope to be a candidate cipher, which we've called ``Chunky2048``.


**Q: How fast is this ``Chunky2048`` cipher?** 

A: Well, because it relies on ``hashlib.shake_128`` hashing to build key material streams, it's rather efficient. It can process about 24 MB/s on a ~1.5 GHz core for both encrypting & decrypting. This is still slow relative to other stream ciphers, but this package is written in pure Python & without hardware optimizations. Using SHA3 ASICs, specific chipset instructions, or a lower-level language implementation, could make this algorithm competitively fast.


**Q: What size keys does the ``Chunky2048`` cipher use?** 

A: It's been designed to work with any size of key >= 64 bytes. 


**Q: What's up with the ``AsyncDatabase`` / ``Database``?**

A: The idea is to create an intuitive, pythonic interface to a transparently encrypted and decrypted persistence tool that also cryptographically obscures metadata. It's designed to persist raw bytes or JSON serializable data, which gives it native support for some of the most important basic python datatypes. It's still a work in progress, albeit a very nifty one.


**Q: Why are the modules transformed into ``Namespace`` objects?**

A: We overwrite our modules in this package to have a more fine-grained control over what part of the package's internal state is exposed to users & applications. The goal is make it more difficult for users to inadvertently jeopardize their security tools, & minimize the attack surface available to adversaries. The ``Namespace`` class also makes it easier to coordinate and decide the library's UI/UX across the package.




