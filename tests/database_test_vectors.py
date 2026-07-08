# This file is part of aiootp:
# a high-level async cryptographic anonymity library to scale, simplify,
# & automate privacy best practices for secure data & identity processing,
# communication, & storage.
#
# Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#            <gonzo.development@protonmail.ch>
#           © 2019-2026 Ricchi (Richard) Machado <rmlibre@riseup.net>
# All rights reserved.
#


from copy import deepcopy
from pathlib import Path

from aiootp._typing import Typing as t
from aiootp._paths import RootPath
from aiootp.commons.namespaces import OpenNamespace


PATH_TO_DATABASE_TEST_VECTORS: Path = (RootPath().parent / "tests") / "db"


BYTES_TAG_DATA: str = b"bytes tag data".hex()
JSON_TAG_DATA: dict[str, t.JSONSerializable] = dict(
    integer=2,
    floating_point=2.5,
    string="json string",
    boolean=True,
    array=[0, "1", 2.0],
    null=None,
)

TAG_DATA: dict[str, t.JSONSerializable] = dict(
    bytes_tag=BYTES_TAG_DATA,
    json_tag=JSON_TAG_DATA.copy(),
)
METATAG_DATA: dict[str, t.JSONSerializable] = dict(
    empty_metatag=dict(
        tags=dict(),
        metatags=dict(),
    ),
    lightly_used_metatag=dict(
        tags=deepcopy(TAG_DATA),
        metatags=dict(),
    ),
)


database_test_vector_0 = OpenNamespace(
    login_key=(
        "889731127460d140726989827e8524f6476fc7047483b87eedfadd4910"
        "f3317219050a2d207d07769a9389211536d61fe30d6837e9d9eff046b2"
        "2e0cb3da442f"
    ),
    tags=deepcopy(TAG_DATA),
    metatags=dict(
        empty_metatag=dict(
            tags=dict(),
            metatags=dict(),
        ),
        used_metatag=dict(
            tags=deepcopy(TAG_DATA),
            metatags=deepcopy(METATAG_DATA),
        ),
    ),
)
