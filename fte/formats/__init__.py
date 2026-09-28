"""Ranked-format providers for :class:`fte.FTE`.

A provider is the one thing you supply to the engine to choose what covertext
looks like. :mod:`~fte.formats.base` defines the contract every provider
implements, :mod:`~fte.formats.bytes` ranks raw byte strings, and
:mod:`~fte.formats.regex` holds the built-in regex provider, the reference
implementation for a new one.

    >>> import fte
    >>> from fte.formats import RegexFormat
    >>> cipher = fte.FTE(output_format=RegexFormat(r"^[0-9a-f]+$", length=96),
    ...                  key=b"0123456789abcdef" * 2)  # demo key; 32 bytes
"""

from fte.formats.base import RankedFormat
from fte.formats.bytes import BytesFormat


__all__ = ["BytesFormat", "RankedFormat", "RegexFormat"]


def __getattr__(name):
    # Import RegexFormat lazily (PEP 562) so that "import fte" does not pull
    # in the regex2dfa dependency; providers that bring their own format
    # never need it.
    if name == "RegexFormat":
        from fte.formats.regex import RegexFormat

        return RegexFormat
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(__all__)
