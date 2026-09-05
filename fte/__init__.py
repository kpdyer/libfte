"""Format-transforming and format-preserving encryption.

Use :class:`FTE` with :class:`RegexFormat`, :class:`BytesFormat`, or a custom
:class:`RankedFormat`. Bytes input defaults to authenticated encryption;
matching finite formats infer the deterministic FF1 cipher.

    >>> import fte
    >>> cipher = fte.FTE(
    ...     output_format=fte.RegexFormat('^[a-z]+$', length=128),
    ...     key=bytes(range(32)),  # demonstration key
    ... )
    >>> assert cipher.decrypt(cipher.encrypt(b'hello')) == b'hello'

See ``docs/api.md`` for the API and ``SECURITY.md`` for the security model.
"""

from pathlib import Path

from fte.core import (
    FTE,
    FTEError,
    FormatCapacityError,
    FormatContractError,
    InvalidCovertextError,
    InvalidPlaintextError,
    MessageTooLargeError,
    SmallDomainError,
)
from fte.formats import BytesFormat, RankedFormat

__version__ = (Path(__file__).parent / '_version.txt').read_text().strip()
__author__ = 'Kevin P. Dyer'
__email__ = 'kpdyer@gmail.com'

__all__ = [
    'FTE',
    'RegexFormat',
    'BytesFormat',
    'RankedFormat',
    'FTEError',
    'FormatCapacityError',
    'FormatContractError',
    'InvalidCovertextError',
    'InvalidPlaintextError',
    'MessageTooLargeError',
    'SmallDomainError',
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
