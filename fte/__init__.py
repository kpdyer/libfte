"""FTE - Format-Transforming Encryption library.

This library implements Format-Transforming Encryption (FTE) and Format-
Preserving Encryption (FPE) with one engine, :class:`fte.FTE`. The engine maps
``rank_in -> transform -> unrank_out``: it ranks a value of the input format to
an integer, transforms that integer, and unranks the result into the output
format. Two independent choices shape it:

* the **format pair** (``input_format`` / ``output_format``), and
* the **cipher**: ``"aes-ctr-hmac"`` (randomized, authenticated, expanding:
  the classic AES-CTR + HMAC path) or ``"ff1"`` (deterministic, zero-expansion,
  format-preserving, via the optional libffx package).

FPE is simply the case ``input_format == output_format``: equal formats infer
the deterministic cipher and re-encrypt a value in place. Classic FTE (bytes
hidden as covertext) is the case where the input is raw bytes::

    >>> import fte
    >>> cipher = fte.FTE(
    ...     output_format=fte.RegexFormat('^[a-z]+$', length=128),
    ...     key=bytes(range(32)),
    ... )
    >>> covertext = cipher.encrypt(b'secret message')
    >>> assert cipher.decrypt(covertext) == b'secret message'

    >>> digits = fte.RegexFormat('^[0-9]+$', length=9)  # doctest: +SKIP
    >>> ssn = fte.FTE(                                  # doctest: +SKIP
    ...     input_format=digits,
    ...     output_format=digits,                       # equal formats -> FPE
    ...     key=bytes(range(16)),
    ... )                                               # needs the libffx extra

``fte.RegexFormat`` is the built-in regex provider and ``fte.BytesFormat`` is
the raw-bytes identity format (the default input). Supply your own
:class:`fte.RankedFormat` to target any other format. See :mod:`fte.formats`
for the provider contract and the reference implementation.

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
