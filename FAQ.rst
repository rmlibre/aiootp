FAQ
---

**Q: What is the one-time-pad?**

A: It's a provably unbreakable cipher. It's typically thought to be too cumbersome a cipher because it has strict requirements. Key size is one requirement, since keys must be at least as large as the plaintext in order to ensure this unbreakability. We've simplified this requirement in an attempt to create a pseudo-one-time-pad that's indistinguishable from a one-time-pad using a forward secret and semi-future secret key ratchet algorithm, with ephemeral salts for each stream, allowing users to securely produce endless streams of key material as needed from a single finite size 512-bit long-term key. This algorithmic approach lends itself to great optimizations, since hash processing hardware/sorftware is continually pushed to the edges of efficiency.


**Q: Isn't this technically a stream cipher?** 

A: For sure, one-time pads are stream ciphers. Though, if we trust that pseudo-random functions **(PRFs)** exist, then by definition, their outputs are indistinguishable from truly random bits. Because of this, it's proven that pseudo_-one-time-pads are computationally secure if they use secure PRFs. We conjecture that the sha3 hash functions are either PRFs, or are close with negligible difference. In our view, they're ideal candidates for the role of mimicking PRFs because: 
 -  they utilize large >512-bit internal hidden states 
 -  their cryptographic permutations are of high quality 
 -  they're irreversible & non-simulatable without knowing thier internal states
 -  loss of information occurs as they process data & produce digests 
 -  they're standardized cryptographic hash functions designed with wide security margins 

True random advocates should note that even something as complicated, & seemingly unpredictable, as quantum mechanical events_, can in theory be the result of rather simple_ & predictable processes. We in no way claim to be quantum physicists. It, however, seems fitting in a discussion on the existence of randomness, & when challenging the conventional notion that the natural world is quintessential randomness, when none of that is proven (or provable) mathematically. This problem is related to several impossibility proofs [1_][2_][3_].

.. _1: https://en.wikipedia.org/wiki/Turing%27s_proof
.. _2: https://www.scientificamerican.com/article/are-we-living-in-a-computer-simulation/
.. _3: https://en.wikipedia.org/wiki/Kolmogorov_complexity#Chaitin's_incompleteness_theorem
.. _events : https://dailygalaxy.com/2019/06/the-unknown-question-the-end-of-spacetime/
.. _simple: https://writings.stephenwolfram.com/2020/04/finally-we-may-have-a-path-to-the-fundamental-theory-of-physics-and-its-beautiful/
.. _pseudo: https://www.youtube.com/watch?v=QlrPPG5H7lg&list=PL2jykFOD1AWb07OLBdFI2QIHvPo3aTTeu&index=16


**Q: What do you mean the ``aiootp.keys`` generator produces forward & semi-future secure key material?**

A: The infinite stream of key material produced by that generator has amazing properties. Under the hood it's a ``hashlib.sha3_512`` key ratchet algorithm. It's internal state consists of a seed hash, & three ``hashlib.sha3_512`` objects primed iteratively with the one prior and the seed hash's seed. The first object is updated with the seed hash, its prior output, and the entropy that may be sent into the generator as a coroutine. This first object's digest is then used to update the last two objects before yielding the last two's concatenated results. The seed to the seed hash is itself the hash of the input key material, a random salt, and a user-defined ID value which can safely differentiate streams with the same key material. This algorithm is forward secure because compromising a future key will not compromise past keys since these hashes are irreversibly constructed. It's also semi-future secure since having a past key doesn't allow you to compute future keys without also compromising the seed hash, and the first ratcheting ``hashlib`` object. Since those two states are never disclosed or used for encryption, the key material produced is future secure with respect to itself only. Full future-security would allow for the same property even if the seed & ratchet object's states were compromised. This feature can, however, be added to the algorithm since the generator itself can receive entropy externally from a user at any arbitrary point in its execution, say, after computing a shared diffie-hellman exchange key.


**Q: Why make a new cipher when AES is strong enough?** 

A: Although primatives like AES are strong enough for now, there's no guarantee that future hardware or algorithms won't be developed which break them. In fact, AES's theoretical bit-strength has dropped over the years because of new developments_. Many popular AES modes don't provide authenication, salt reuse/misuse resistance, post-quantum resistance, or beyond-birthday-bound security. And the most common authenticated AES mode (GCM) involves some complex maths & has large pits implementers can easily fall into. AES's efficiency is important, even though it falls short in defending against these vulnerabilities. We wanted to build a cipher which focuses on security & simplicity for developers, even at the cost of some efficiency. AES is still considered a secure cipher, but the **pseudo-one-time pad** isn't considered theoretically "strong enough". Instead, it's mathematically proven to be computationally secure if the keystream is produced from a large enough key & a secure pseudo-random function. Such a cryptographic guarantee is too profound not to develop further into an accessible standard. This cipher is an attempt to do just that.

.. _developments: https://www.schneier.com/blog/archives/2009/07/another_new_aes.html


**Q: How fast is this implementation of the pseudo one-time pad cipher?** 

A: Well, because it relies on ``hashlib.sha3_512`` hashing to build key material streams, it's rather efficient. It can process about 20 MB/s on a ~1.5 GHz core for both encrypting & decrypting. This is slower than other stream ciphers, but this package is written in pure Python & without hardware optimizations. Using sha3_512 ASICs, or specific chipset instructions, or a lower-level language implementation, could make this algorithm competitively fast.


**Q: What size keys does this pseudo one-time pad cipher use?** 

A: It's been designed to work with 512-bit hexidecimal keys. 


**Q: What's up with the ``AsyncDatabase`` / ``Database``?**

A: The idea is to create an intuitive, pythonic interface to a transparently encrypted and decrypted persistence tool that also cryptographically obscures metadata. It's designed to work with json serializable data, which gives it native support for some basic python datatypes. It needs improvement with regard to disk memory efficiency. So, it's still a work in progress, albeit a very nifty one.


**Q: Why are the modules transformed into ``Namespace`` objects?**

A: We overwrite our modules in this package to have a more fine-grained control over what part of the package's internal state is exposed to users and applications. The goal is make it more difficult for users to inadvertently jeopardize their security tools, and minimize the attack surface available to adversaries. The ``aiootp.Namespace`` class also makes it easier to coordinate and decide the library's UI/UX across the package.



