"""Deprecated compatibility imports for the internal DFA implementation.

Use ``fte.RegexFormat`` or implement ``fte.RankedFormat``. See ``docs/api.md``
for migration guidance when an application consumes raw DFA data.
"""

import warnings as _warnings

from fte.formats.regex._dfa import (
    DFA,
    InvalidFSTFormat,
    InvalidRankInput,
    InvalidUnrankInput,
)

__all__ = [
    "DFA",
    "InvalidFSTFormat",
    "InvalidRankInput",
    "InvalidUnrankInput",
]

_warnings.warn(
    "fte.formats.regex.dfa is deprecated and will be removed in a future "
    "breaking release; use fte.RegexFormat or implement fte.RankedFormat. "
    "There is no public raw-DFA replacement; see docs/api.md for migration guidance.",
    DeprecationWarning,
    stacklevel=2,
)
