# This file is part of aiootp, an asynchronous pseudo one-time pad based
# crypto and anonymity library.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2023 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from test_initialization import *


async def test_acsprng():
    entropy = await randoms.arandom_number_generator(entropy=test_data, freshness=1)
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    entropy = await randoms.arandom_number_generator(128, freshness=0)
    assert len(entropy) == 128
    assert entropy.__class__ is bytes

    entropy = await acsprng(b"")
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    entropy = await acsprng("test")
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    key = await agenerate_key(freshness=0)
    assert len(key) == KEY_BYTES
    assert key.__class__ is bytes

    context = f"Allowed to generate a key less than {MIN_KEY_BYTES}"
    async with aignore(ValueError, if_else=aviolation(context)):
        key = await agenerate_key(size=MIN_KEY_BYTES - 1, freshness=0)

    async def try_to_make_duplicate_readouts():
        """
        The async csprng doesn't produce duplicate outputs when run in
        a multithreaded environment.
        """
        for i in range(32):
            await arandom_sleep(0.00001)
            entropy = await acsprng()

            assert entropy not in entropy_pool

            entropy_pool.add(entropy)

    entropy_pool = set()
    await Threads.agather(
        *[try_to_make_duplicate_readouts for _ in range(32)]
    )


def test_csprng():
    entropy = randoms.random_number_generator(entropy=test_data, freshness=1)
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    entropy = randoms.random_number_generator(128, freshness=0)
    assert len(entropy) == 128
    assert entropy.__class__ is bytes

    entropy = csprng(b"")
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    entropy = csprng("test")
    assert len(entropy) == 64
    assert entropy.__class__ is bytes

    key = generate_key(freshness=0)
    assert len(key) == KEY_BYTES
    assert key.__class__ is bytes

    context = f"Allowed to generate a key less than {MIN_KEY_BYTES} bytes."
    with ignore(ValueError, if_else=violation(context)):
        key = generate_key(size=MIN_KEY_BYTES - 1, freshness=0)

    def try_to_make_duplicate_readouts():
        """
        The async csprng doesn't produce duplicate outputs when run in
        a multithreaded environment.
        """
        for i in range(32):
            random_sleep(0.00001)
            entropy = csprng()

            assert entropy not in entropy_pool

            entropy_pool.add(entropy)

    entropy_pool = set()
    Threads.gather(
        *[try_to_make_duplicate_readouts for _ in range(32)]
    )


async def test_guids():
    assert 16 == len(GUID().new())
    assert 16 == len(await GUID().anew())

    # simulate the monotonic nature of a timestamp to test the uniqueness
    # of the algorithm outputs for all inputs between two multiples of
    # the prime used for that size category

    def raw_guid_simulator():
        nonlocal i

        i += 1
        return i

    # lowering the default minimum size to be able to efficiently do a
    # complete search of a salt space & the impacts of each possible
    # change in salt on uniqueness of outputs
    GUID._MIN_SIZE = 1
    GUID._MIN_RAW_SIZE = 0
    GUID._MIN_SALT_SIZE = 1
    GUID._COUNTER_BYTES = 0

    # testing all the combinations is impossible, in general, but even
    # testing all two byte combinations is prohibitively slow. However,
    # these variables can be customized to run extended tests
    MIN_TEST_BYTES = 1
    MAX_TEST_BYTES = 1

    # change to `True` if a random location within each search space is
    # desired
    start_at_random_location: bool = False

    previous_salts = []

    # these values do not change in the tests, but are displayed to
    # visually declare where their byte values are located in relation
    # to the raw guid which contains the timestamp & random bytes
    node_number = 0
    counter = 0

    for size in range(MIN_TEST_BYTES, MAX_TEST_BYTES + 1):
        start = token_bits(8 * size) if start_at_random_location else 0
        for salt_test in bytes_range.root(start, 256**size, size=size):
            i = -1

            guid = GUID(salt=salt_test, size=size)
            _size, gen, prime, subprime = guid._session_configuration
            assert size == _size

            isalt, osalt, xsalt = guid._encode_salt(guid._salt, prime, size)
            assert previous_salts != [isalt, osalt, xsalt]
            assert all([isalt, osalt])

            #                    |--------------- `size`-bytes ---------------|
            inner_guid = lambda: (node_number + raw_guid_simulator() + counter)
            _key = lambda: (
                xsalt ^ ((isalt * inner_guid() + osalt) % prime)
            ).to_bytes(size, BYTE_ORDER)

            history = set()
            for j in range(prime):
                result = _key()
                assert result not in history, (
                    f"salt_test={salt_test}--isalt={isalt}--osalt={osalt}--"
                    f"xsalt={xsalt}--size={size}--j={j}--i={i}--result={result}"
                )
                history.add(result)

            previous_salts = [isalt, osalt, xsalt]

    GUID._MIN_SIZE = MIN_GUID_BYTES
    GUID._MIN_RAW_SIZE = MIN_RAW_GUID_BYTES
    GUID._MIN_SALT_SIZE = 16
    GUID._COUNTER_BYTES = 1


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

