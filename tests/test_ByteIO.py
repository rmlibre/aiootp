# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2025 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from base64 import urlsafe_b64encode

from conftest import *

from aiootp._constants.datasets import (
    _WORD_LIST_256,
    _WORD_LIST_256_INVERSE,
)


NON_ZERO_PREFIX = choice(list(range(1, 256))).to_bytes(1, BIG)
data = NON_ZERO_PREFIX + token_bytes(choice(list(range(23, 33))))
encoded_data = urlsafe_b64encode(data)


class TestByteIO:
    async def test_abytes_to_urlsafe(self) -> None:
        result = await ByteIO.abytes_to_urlsafe(data)

        assert data != result
        assert data == await ByteIO.aurlsafe_to_bytes(result)
        assert data == await ByteIO.aurlsafe_to_bytes(result.decode())

        if b"=" in encoded_data:
            assert 0 != len(result) % 4
            assert result == encoded_data.replace(b"=", b"")
        else:
            assert 0 == len(result) % 4
            assert result == encoded_data

    async def test_bytes_to_urlsafe(self) -> None:
        result = ByteIO.bytes_to_urlsafe(data)

        assert data != result
        assert data == ByteIO.urlsafe_to_bytes(result)
        assert data == ByteIO.urlsafe_to_bytes(result.decode())

        if b"=" in encoded_data:
            assert 0 != len(result) % 4
            assert result == encoded_data.replace(b"=", b"")
        else:
            assert 0 == len(result) % 4
            assert result == encoded_data

    async def test_abytes_to_filename(self) -> None:
        result = await ByteIO.abytes_to_filename(data)

        assert set(Tables.BASE_38).issuperset(result)
        assert data == await ByteIO.afilename_to_bytes(result)

    async def test_bytes_to_filename(self) -> None:
        result = ByteIO.bytes_to_filename(data)

        assert set(Tables.BASE_38).issuperset(result)
        assert data == ByteIO.filename_to_bytes(result)

    async def test_abytes_to_phrase(self) -> None:
        blob = Slick256(csprng(64)).bytes_encrypt(b"")

        phrase = await ByteIO._abytes_to_phrase(blob)

        for byte, word in zip(blob, phrase.split(b" ")):
            assert word == _WORD_LIST_256[byte]
            assert byte.to_bytes(1, "big") == _WORD_LIST_256_INVERSE[word]

        assert blob == await ByteIO._aphrase_to_bytes(phrase)

    async def test_bytes_to_phrase(self) -> None:
        blob = Slick256(csprng(64)).bytes_encrypt(b"")

        phrase = ByteIO._bytes_to_phrase(blob)

        for byte, word in zip(blob, phrase.split(b" ")):
            assert word == _WORD_LIST_256[byte]
            assert byte.to_bytes(1, "big") == _WORD_LIST_256_INVERSE[word]

        assert blob == ByteIO._phrase_to_bytes(phrase)

    async def test_aread(self, path: t.Path) -> None:
        assert b"" == await ByteIO.aread(path)

        path.write_bytes(data)
        assert data == await ByteIO.aread(path)

        for size in range(len(data)):
            assert data[:size] == ByteIO.read(path, size)

    async def test_read(self, path: t.Path) -> None:
        assert b"" == ByteIO.read(path)

        path.write_bytes(data)
        assert data == ByteIO.read(path)

        for size in range(len(data)):
            assert data[:size] == ByteIO.read(path, size)

    async def test_awrite(self, path: t.Path) -> None:
        await ByteIO.awrite(path, data)
        assert data == path.read_bytes()

        await ByteIO.awrite(path, b"")
        assert b"" == path.read_bytes()

    async def test_write(self, path: t.Path) -> None:
        ByteIO.write(path, data)
        assert data == path.read_bytes()

        ByteIO.write(path, b"")
        assert b"" == path.read_bytes()

    async def test_aappend(self, path: t.Path) -> None:
        await ByteIO.aappend(path, data)
        assert data == path.read_bytes()

        await ByteIO.aappend(path, data)
        assert 2 * data == path.read_bytes()

        await ByteIO.aappend(path, data)
        assert 3 * data == path.read_bytes()

    async def test_append(self, path: t.Path) -> None:
        ByteIO.append(path, data)
        assert data == path.read_bytes()

        ByteIO.append(path, data)
        assert 2 * data == path.read_bytes()

        ByteIO.append(path, data)
        assert 3 * data == path.read_bytes()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})
