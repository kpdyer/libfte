"""Ranked-format providers for :class:`fte.FTE`.

A provider is the one thing you supply to the engine to choose what covertext
looks like. :mod:`~fte.formats.base` defines the contract every provider
implements; :mod:`~fte.formats.regex` is the built-in reference implementation
and the template to copy for a new format.

    >>> import fte
    >>> from fte.formats import RegexFormat
    >>> cipher = fte.FTE(format=RegexFormat(r"^[0-9a-f]+$", length=96),
    ...                  key=bytes(range(32)))
"""

from fte.formats.base import FiniteRankedFormat, RankedFormat
from fte.formats.regex import RegexFormat


__all__ = ["RankedFormat", "FiniteRankedFormat", "RegexFormat"]
