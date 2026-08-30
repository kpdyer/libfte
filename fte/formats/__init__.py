"""Ranked-format providers for :class:`fte.FTE`.

A provider is the one thing you supply to the engine to choose what covertext
looks like. :mod:`~fte.formats.base` defines the contract every provider
implements. Each provider lives in its own subpackage;
:mod:`~fte.formats.regex` is the built-in reference implementation and the
subpackage to copy for a new provider.

    >>> import fte
    >>> from fte.formats import RegexFormat
    >>> cipher = fte.FTE(output_format=RegexFormat(r"^[0-9a-f]+$", length=96),
    ...                  key=bytes(range(32)))
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
