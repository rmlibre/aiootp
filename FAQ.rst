_`FAQ` ............................................ `Table Of Contents`_
========================================================================


**Q: What is the one-time pad?**

A: It's a provably unbreakable cipher. It's typically thought to be too cumbersome a cipher because it has strict requirements. Key size is one such requirement, since keys must be at least as large as the plaintext in order to ensure this unbreakability. We've tried to relax this requirement, by getting as close as possible with a pseudo one-time pad that's indistinguishable from a one-time pad. We attempt to not only make decryption computationally infeasible without the correct key, but also attempt to force an adversary, even with unbounded computational power, to distinguish between an exponentially large number of possible plaintexts. We've built a candidate cipher, which we've called ``Chunk2048``, by using a forward secret and semi-future secret double-ratchet key algorithm from arbitrarily large >=64-byte keys whose entropy are continuously extracted on each block, ephemeral salts, purposefully randomized synthetic IVs, large 256-byte block sizes, and deniability properties from plaintext padding randomization. Our view is that we can learn more from what makes the one-time pad unbreakable than just using large truly random keys, such as leaving an adversary in a state of undecidability when considering exponentially many equally likely options. This algorithmic approach also lends itself to great optimizations, since hash processing hardware / software is continually pushed to the edges of efficiency.


**Q: Isn't this technically a stream cipher?**

A: For sure, one-time pads are stream ciphers. Though, if we trust that pseudo-random functions **(PRFs)** exist, then by definition, their outputs are indistinguishable from truly random bits. Because of this, it's proven that pseudo one-time pads are computationally secure if they use secure PRFs. We conjecture that the sha3_512 hash function is either a PRF, or is close with negligible difference. In our view, it's an ideal candidate for the role of mimicking a PRF because: 
 -  it utilizes large >1024-bit hidden internal states 
 -  its cryptographic permutations are of high quality & are extensively reviewed
 -  it's irreversible & non-simulatable without knowing the internal states
 -  when updated with new key material, the exposed state is xor'd with the new key material then mixed & permuted with the hidden state, which is essentially one-time pad encryption of the exposed state with additional secret-dependent diffusion
 -  loss of information occurs, from the point of view of output digests, as data is processed
 -  it's continually reseedable with constant memory overhead
 -  it's a standardized cryptographic hash function designed with wide security margins 

True random advocates should note that even something as complicated, & seemingly unpredictable, as quantum mechanical events_, can in theory be the result of rather simple_ & predictable processes. We in no way claim to be quantum physicists. It, however, seems fitting in a discussion on the existence of randomness, & when challenging the conventional notion that the natural world is quintessential randomness, when none of that is proven (or provable) mathematically. This problem is related to several impossibility proofs [1_][2_][3_].

.. _1: https://en.wikipedia.org/wiki/Turing%27s_proof
.. _2: https://www.scientificamerican.com/article/are-we-living-in-a-computer-simulation/
.. _3: https://en.wikipedia.org/wiki/Kolmogorov_complexity#Chaitin's_incompleteness_theorem
.. _events : https://dailygalaxy.com/2019/06/the-unknown-question-the-end-of-spacetime/
.. _simple: https://writings.stephenwolfram.com/2020/04/finally-we-may-have-a-path-to-the-fundamental-theory-of-physics-and-its-beautiful/
.. _pseudo: https://www.youtube.com/watch?v=QlrPPG5H7lg&list=PL2jykFOD1AWb07OLBdFI2QIHvPo3aTTeu&index=16


**Q: What do you mean the ``aiootp.bytes_keys`` generator produces forward & semi-future secure key material?**

A: The infinite stream of key material produced by that generator has amazing properties. Under the hood it's a ``hashlib.sha3_512`` key ratchet algorithm. It's internal state consists of the user key, & three ``hashlib.sha3_512`` objects ratcheted iteratively with different KDF outputs computed on the key, salt, authenticated associated data, various other random & pseudo-random values, & plaintext message content. This algorithm is forward secure because compromising a future key will not compromise past keys since these hashes are irreversibly constructed. It's also semi-future secure since having a past key doesn't allow you to compute future keys without also compromising the values used to initialize & continuously seed entropy into the generator. Since those internal states are never disclosed or used directly for encryption, the key material produced is future secure with respect to itself only. Full future-security would allow for the same property even if these internal states were compromised. This feature can, however, be added to the algorithm since the generator itself can receive entropy externally from a user at any arbitrary point in its execution, say, after computing a shared diffie-hellman exchange key.


**Q: Why make a new cipher when AES is strong enough?** 

A: Although primatives like AES are strong enough for now, there's no guarantee that future hardware or algorithms won't be developed which break them. In fact, AES's theoretical bit-strength has dropped over the years because of new developments_. Many popular AES modes don't provide authentication, salt reuse/misuse resistance, post-quantum resistance, or beyond-birthday-bound security. And the most common authenticated AES mode (GCM) involves some complex maths & has large pits implementers & users can easily fall into. AES's efficiency is important, even though it falls short in defending against these weaknesses. We wanted to build a cipher which focuses on security & simplicity for developers, even at the cost of some efficiency. AES is still considered a secure cipher, but the **pseudo one-time pad** isn't considered "strong enough". Instead, it's mathematically proven to be computationally secure if the keystream is produced from a large enough key & a secure pseudo-random function. Such a cryptographic guarantee is too profound not to develop further into an accessible standard. The ``Chunky2048`` cipher is an attempt to do just that.

.. _developments: https://www.schneier.com/blog/archives/2009/07/another_new_aes.html


**Q: How fast is this ``Chunky2048`` cipher?** 

A: Well, because it relies on ``hashlib.sha3_512`` hashing to build key material streams, it's rather efficient. It can process about 23 MB/s on a ~1.5 GHz core for both encrypting & decrypting. This is slower than other stream ciphers, but this package is written in pure Python & without hardware optimizations. Using sha3_512 ASICs, specific chipset instructions, or a lower-level language implementation, could make this algorithm competitively fast.


**Q: What size keys does this pseudo one-time pad cipher use?** 

A: It's been designed to work with >=64-byte keys. 


**Q: What's up with the ``AsyncDatabase`` / ``Database``?**

A: The idea is to create an intuitive, pythonic interface to a transparently encrypted and decrypted persistence tool that also cryptographically obscures metadata. It's designed to persist raw bytes or JSON serializable data, which gives it native support for some of the most important basic python datatypes. It's still a work in progress, albeit a very nifty one.


**Q: Why are the modules transformed into ``OpenNamespace`` objects?**

A: We overwrite our modules in this package to have a more fine-grained control over what part of the package's internal state is exposed to users and applications. The goal is make it more difficult for users to inadvertently jeopardize their security tools, and minimize the attack surface available to adversaries. The ``aiootp.OpenNamespace`` class also makes it easier to coordinate and decide the library's UI/UX across the package.




