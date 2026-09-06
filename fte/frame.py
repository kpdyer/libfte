"""Deprecated compatibility imports for the internal frame implementation.

Use ``fte.BytesFormat`` for byte ranking and ``FTE.max_plaintext_bytes`` for
configured plaintext capacity. See ``docs/api.md`` for the public API.
"""

import warnings as _warnings

from fte._frame import (
    FRAME_VERSION,
    bytes_to_rank,
    capacity_plaintext_limit,
    frame_rank_limit,
    rank_byte_length,
    rank_offset,
    rank_to_bytes,
)

__all__ = [
    "FRAME_VERSION",
    "bytes_to_rank",
    "capacity_plaintext_limit",
    "frame_rank_limit",
    "rank_byte_length",
    "rank_offset",
    "rank_to_bytes",
]

_warnings.warn(
    "fte.frame is deprecated and will be removed in a future breaking release; "
    "use fte.BytesFormat.rank()/unrank() for byte ranking and "
    "FTE.max_plaintext_bytes for configured plaintext capacity. "
    "See docs/api.md for migration guidance.",
    DeprecationWarning,
    stacklevel=2,
)
