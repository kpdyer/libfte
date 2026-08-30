"""FTE - Format-Transforming Encryption library.

This library implements Format-Transforming Encryption (FTE), a cryptographic
primitive that encodes ciphertexts as values produced by a ranked-format
provider: the built-in regular-expression provider, or any custom provider you
supply.

Example usage:
    >>> import fte
    >>>
    >>> # One engine: FTE over a RankedFormat provider. RegexFormat is the
    >>> # built-in regex provider (it uses regex2dfa under the hood).
    >>> cipher = fte.FTE(
    ...     format=fte.RegexFormat('^[a-z]+$', length=128),
    ...     key=bytes(range(32)),
    ... )
    >>> covertext = cipher.encrypt(b'secret message')
    >>> assert cipher.decrypt(covertext) == b'secret message'
    >>>
    >>> # fte.Encoder is a regex convenience wrapper over the same engine:
    >>> regex_cipher = fte.Encoder('^[a-z]+$', 128, key=bytes(range(32)))
    >>> ciphertext = regex_cipher.encrypt(b'secret message')
    >>> plaintext, _ = regex_cipher.decrypt(ciphertext)

See the paper "Protocol Misidentification Made Easy with Format-Transforming
Encryption" for details: https://kpdyer.com/publications/ccs2013-fte.pdf
"""

from pathlib import Path
from typing import Tuple

from fte.encoder import DecodeFailureError, InvalidInputException
from fte.encrypter import Encrypter
from fte.format import (
    FTE,
    FTEError,
    FiniteRankedFormat,
    FormatCapacityError,
    FormatContractError,
    InvalidCovertextError,
    MessageTooLargeError,
    RankedFormat,
)
from fte.regex_format import RegexFormat

__version__ = (Path(__file__).parent / '_version.txt').read_text().strip()
__author__ = 'Kevin P. Dyer'
__email__ = 'kpdyer@gmail.com'

__all__ = [
    'Encoder',
    'FTE',
    'FTEError',
    'FiniteRankedFormat',
    'FormatCapacityError',
    'FormatContractError',
    'InvalidCovertextError',
    'MessageTooLargeError',
    'RankedFormat',
    'RegexFormat',
    'Encrypter',
    'InvalidInputException',
    'DecodeFailureError',
    'encrypt',
    'decrypt',
]


class Encoder:
    """Regex FTE encoder -- a convenience wrapper over :class:`FTE` and
    :class:`RegexFormat`.

    ``Encoder(regex, fixed_slice)`` is exactly :class:`FTE` configured with
    ``RegexFormat(regex, length=fixed_slice)``. The two share one wire format
    and interoperate. This wrapper adds the historical regex ergonomics: a
    positional ``(regex, fixed_slice)`` constructor, a ``(plaintext, remainder)``
    decrypt return for parsing streams of fixed-length covertexts, an
    ``encrypt(b"") == b""`` shortcut, and a ``capacity`` property.

    Note:
        The wire format changed in this release. Covertext produced here is NOT
        compatible with the ``Encoder`` in libfte 0.3.x and earlier.

    Args:
        regex: A regular expression defining the output format.
            Examples: '^[a-z]+$', '^[0-9a-f]+$', '^[A-Za-z0-9]+$'
        fixed_slice: The exact byte length of each formatted covertext.
        key: The 32-byte key (16 bytes encryption + 16 bytes MAC), shared by
            both endpoints.

    Example:
        >>> cipher = fte.Encoder('^[0-9a-f]+$', 128, key=bytes(range(32)))
        >>> ciphertext = cipher.encrypt(b'secret')
        >>> plaintext, _ = cipher.decrypt(ciphertext)
    """

    def __init__(
        self,
        regex: str,
        fixed_slice: int,
        key: bytes,
    ):
        self.regex = regex
        self.fixed_slice = fixed_slice
        self._format = RegexFormat(regex, length=fixed_slice)
        self._fte = FTE(format=self._format, key=key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and format it to match the regex.

        Args:
            plaintext: The data to encrypt.

        Returns:
            A covertext of exactly ``fixed_slice`` bytes. Empty input returns
            empty output.

        Raises:
            InvalidInputException: If ``plaintext`` is not bytes.
            FormatCapacityError: If the fixed-length language cannot represent
                the encrypted message; choose a larger ``fixed_slice``.
        """
        if not isinstance(plaintext, bytes):
            raise InvalidInputException('Input must be of type bytes.')
        if not plaintext:
            return b''
        return self._fte.encrypt(plaintext)

    def decrypt(self, covertext: bytes) -> Tuple[bytes, bytes]:
        """Decrypt one covertext value back to plaintext.

        Consumes exactly ``fixed_slice`` bytes and returns any trailing bytes as
        the remainder, so a stream of concatenated covertexts can be parsed one
        message at a time.

        Args:
            covertext: The formatted covertext, at least ``fixed_slice`` bytes.

        Returns:
            A tuple of ``(plaintext, remainder)``.

        Raises:
            InvalidInputException: If ``covertext`` is not bytes.
            DecodeFailureError: If ``covertext`` is shorter than ``fixed_slice``.
            InvalidCovertextError: If the value cannot be authenticated.
        """
        if not isinstance(covertext, bytes):
            raise InvalidInputException('Input must be of type bytes.')
        if len(covertext) < self.fixed_slice:
            raise DecodeFailureError(
                "Covertext is shorter than fixed_slice, can't decrypt."
            )
        value = covertext[:self.fixed_slice]
        remainder = covertext[self.fixed_slice:]
        return self._fte.decrypt(value), remainder

    @property
    def capacity(self) -> int:
        """Usable capacity in bits: ``floor(log2(cardinality)) - 1``."""
        return self._format.cardinality.bit_length() - 2


# Convenience functions for one-shot encrypting/decrypting
_encoders = {}


def encrypt(
    plaintext: bytes,
    regex: str = '^[a-z]+$',
    fixed_slice: int = 256,
    *,
    key: bytes,
) -> bytes:
    """Encrypt plaintext with the regex Encoder (convenience function).

    A thin wrapper over :class:`Encoder` (and therefore over :class:`FTE` with
    :class:`RegexFormat`). Encoders are cached per ``(regex, fixed_slice, key)``
    for the lifetime of the process.

    Args:
        plaintext: The data to encrypt.
        regex: Output format as a regular expression.
        fixed_slice: Length of formatted output.
        key: The 32-byte key shared by both endpoints.

    Returns:
        Ciphertext formatted to match the regex.

    Example:
        >>> ciphertext = fte.encrypt(b'secret', regex='^[0-9a-f]+$', key=key)
    """
    cache_key = (regex, fixed_slice, key)
    if cache_key not in _encoders:
        _encoders[cache_key] = Encoder(regex, fixed_slice, key)
    return _encoders[cache_key].encrypt(plaintext)


def decrypt(
    ciphertext: bytes,
    regex: str = '^[a-z]+$',
    fixed_slice: int = 256,
    *,
    key: bytes,
) -> Tuple[bytes, bytes]:
    """Decrypt ciphertext with the regex Encoder (convenience function).

    A thin wrapper over :class:`Encoder`. The ``regex``, ``fixed_slice``, and
    ``key`` must match those used to encrypt.

    Args:
        ciphertext: The formatted ciphertext.
        regex: The regex used to encrypt (must match).
        fixed_slice: The fixed_slice used to encrypt (must match).
        key: The key used to encrypt (must match).

    Returns:
        A tuple of (plaintext, remainder).

    Example:
        >>> plaintext, _ = fte.decrypt(ciphertext, regex='^[0-9a-f]+$', key=key)
    """
    cache_key = (regex, fixed_slice, key)
    if cache_key not in _encoders:
        _encoders[cache_key] = Encoder(regex, fixed_slice, key)
    return _encoders[cache_key].decrypt(ciphertext)
