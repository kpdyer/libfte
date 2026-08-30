"""FTE - Format-Transforming Encryption library.

This library implements Format-Transforming Encryption (FTE), a cryptographic
primitive whose ciphertexts are values drawn from a covertext language of your
choosing. The one engine, :class:`fte.FTE`, encrypts through a ranked-format
provider: pass a ``format`` and a 32-byte ``key`` and call ``encrypt`` /
``decrypt``.

Example usage:
    >>> import fte
    >>>
    >>> cipher = fte.FTE(
    ...     format=fte.RegexFormat('^[a-z]+$', length=128),
    ...     key=bytes(range(32)),
    ... )
    >>> covertext = cipher.encrypt(b'secret message')
    >>> assert cipher.decrypt(covertext) == b'secret message'

``fte.RegexFormat`` is the built-in regex provider; supply your own
:class:`fte.RankedFormat` to target any other covertext language. See
:mod:`fte.formats` for the provider contract and the reference implementation.

See the paper "Protocol Misidentification Made Easy with Format-Transforming
Encryption" for details: https://kpdyer.com/publications/ccs2013-fte.pdf
"""

from pathlib import Path

from fte.core import (
    FTE,
    FTEError,
    FormatCapacityError,
    FormatContractError,
    InvalidCovertextError,
    MessageTooLargeError,
)
from fte.formats import RankedFormat

__version__ = (Path(__file__).parent / '_version.txt').read_text().strip()
__author__ = 'Kevin P. Dyer'
__email__ = 'kpdyer@gmail.com'

__all__ = [
    'FTE',
    'RegexFormat',
    'RankedFormat',
    'FTEError',
    'FormatCapacityError',
    'FormatContractError',
    'InvalidCovertextError',
    'MessageTooLargeError',
]


def __getattr__(name):
    # Import RegexFormat lazily (PEP 562) so that "import fte" does not pull
    # in the regex2dfa dependency; providers that bring their own format
    # never need it.
    if name == 'RegexFormat':
        from fte.formats import RegexFormat

        return RegexFormat
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(__all__)
