# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2024 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from base64 import urlsafe_b64encode, urlsafe_b64decode

from test_initialization import *


NON_ZERO_PREFIX = choice(list(range(1, 256))).to_bytes(1, BIG)
data = NON_ZERO_PREFIX + token_bytes(choice(list(range(23, 33))))
encoded_data = urlsafe_b64encode(data)


class TestByteIO:

    async def test_abytes_to_urlsafe(self) -> bytes:
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

    async def test_bytes_to_urlsafe(self) -> bytes:
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

    async def test_abytes_to_filename(self) -> str:
        result = await ByteIO.abytes_to_filename(data)

        assert set(Tables.BASE_38).issuperset(result)
        assert data == await ByteIO.afilename_to_bytes(result)

    async def test_bytes_to_filename(self) -> str:
        result = ByteIO.bytes_to_filename(data)

        assert set(Tables.BASE_38).issuperset(result)
        assert data == ByteIO.filename_to_bytes(result)

    async def test_aread(self, path: t.Path) -> bytes:
        assert b"" == await ByteIO.aread(path)

        path.write_bytes(data)
        assert data == await ByteIO.aread(path)

    async def test_read(self, path: t.Path) -> bytes:
        assert b"" == ByteIO.read(path)

        path.write_bytes(data)
        assert data == ByteIO.read(path)

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
        assert 2*data == path.read_bytes()

        await ByteIO.aappend(path, data)
        assert 3*data == path.read_bytes()

    async def test_append(self, path: t.Path) -> None:
        ByteIO.append(path, data)
        assert data == path.read_bytes()

        ByteIO.append(path, data)
        assert 2*data == path.read_bytes()

        ByteIO.append(path, data)
        assert 3*data == path.read_bytes()


__all__ = sorted({n for n in globals() if n.lower().startswith("test")})

