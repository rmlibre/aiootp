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


__all__ = ["GUID", "SequenceID"]


__doc__ = (
    "Types for creating & reading unique unblinded IDs, or IDs blinded "
    "with bijective, keyed permutations."
)


from .sequence_id_config import *
from .sequence_id import *
from .raw_guid_config import *
from .raw_guid import *
from .guid_config import *
from .guid import *


modules = dict(
    guid=guid,
    guid_config=guid_config,
    raw_guid=raw_guid,
    raw_guid_config=raw_guid_config,
    sequence_id=sequence_id,
    sequence_id_config=sequence_id_config,
)


module_api = dict(
    GUID=GUID,
    SequenceID=SequenceID,
    __all__=__all__,
    __doc__=__doc__,
    __file__=__file__,
    __name__=__name__,
    __spec__=__spec__,
    __loader__=__loader__,
    __package__=__package__,
)

