"""Generic FTE support for pluggable ranked formats."""

from __future__ import annotations

from typing import Generic, Protocol, TypeVar, runtime_checkable

from fte.encrypter import (
    CiphertextTypeError,
    Encrypter,
    RecoverableDecryptionError,
    UnrecoverableDecryptionError,
)


__all__ = [
    "FTE",
    "FTEError",
    "FiniteRankedFormat",
    "FormatCapacityError",
    "FormatContractError",
    "InvalidCovertextError",
    "MessageTooLargeError",
    "RankedFormat",
]


Covertext = TypeVar("Covertext")


class FTEError(Exception):
    """Base class for errors raised by the generic format API."""


class FormatContractError(FTEError):
    """Raised when a format violates the :class:`RankedFormat` contract."""


class FormatCapacityError(FTEError):
    """Raised when a format cannot represent an encrypted payload rank."""


class MessageTooLargeError(FTEError):
    """Raised when plaintext exceeds the configured resource limit."""


class InvalidCovertextError(FTEError):
    """Raised when a format value cannot be authenticated and decrypted."""


@runtime_checkable
class RankedFormat(Protocol[Covertext]):
    """A deterministic, reversible ordering of canonical covertext values.

    A conforming format must provide a contiguous zero-based rank space and
    satisfy both inverse laws for every supported rank and canonical value::

        format.rank(format.unrank(index)) == index
        format.unrank(format.rank(value)) == value

    The ordering is part of the wire format. Sender and receiver must therefore
    use compatible implementations and versions. Implementations should reject
    values outside their canonical format and indexes outside their capacity.
    """

    def rank(self, value: Covertext, /) -> int:
        """Return the non-negative integer assigned to ``value``."""

        ...

    def unrank(self, index: int, /) -> Covertext:
        """Return the canonical value assigned to non-negative ``index``."""

        ...


@runtime_checkable
class FiniteRankedFormat(RankedFormat[Covertext], Protocol[Covertext]):
    """A ranked format with an exact finite, contiguous rank space."""

    @property
    def cardinality(self) -> int:
        """Number of supported ranks, whose domain is ``range(cardinality)``."""

        ...


def _rank_offset(length: int) -> int:
    """Return the first rank assigned to byte strings of ``length``."""

    return (256 ** length - 1) // 255


def _bytes_to_rank(value: bytes) -> int:
    """Rank byte strings in length-first, then numeric, order."""

    offset = _rank_offset(len(value))
    return offset + int.from_bytes(value, "big")


def _rank_to_bytes(index: int) -> bytes:
    """Invert :func:`_bytes_to_rank`, preserving leading zero bytes."""

    length = _rank_byte_length(index)
    offset = _rank_offset(length)
    return (index - offset).to_bytes(length, "big")


def _rank_byte_length(index: int) -> int:
    """Return the byte-string length represented by a shortlex rank."""

    return ((255 * index + 1).bit_length() - 1) // 8


def _frame_rank_limit(frame_length: int) -> int:
    """Return the exclusive upper rank bound for version-one frames."""

    return _rank_offset(frame_length) + 2 * 256 ** (frame_length - 1)


class FTE(Generic[Covertext]):
    """Encrypt bytes into values supplied by a :class:`RankedFormat`.

    The format is structural: any object with callable ``rank`` and ``unrank``
    methods works without inheriting from this package or importing it at
    runtime.

    One complete format value represents one encrypted message. Since an
    arbitrary value has no generic stream boundary, ``decrypt`` consumes exactly
    one value and returns plaintext directly, without a stream remainder.
    """

    # The outer byte reserves a wire-format version. The shortlex byte ranking
    # below independently preserves the frame length and leading zero bytes.
    _FRAME_VERSION = b"\x01"
    _CIPHERTEXT_EXPANSION = Encrypter._CTXT_EXPANSION

    _DEFAULT_MAX_PLAINTEXT_BYTES = 1 << 20
    _ENCRYPTER_MAX_PLAINTEXT_BYTES = (1 << 32) - 1

    __slots__ = (
        "_format",
        "_encrypter",
        "_cardinality",
        "_max_plaintext_bytes",
        "_max_frame_bytes",
    )

    def __init__(
        self,
        *,
        format: RankedFormat[Covertext],
        key: bytes,
        max_plaintext_bytes: int = _DEFAULT_MAX_PLAINTEXT_BYTES,
    ) -> None:
        if isinstance(format, type):
            raise TypeError("format must be an instance, not a class")
        if not callable(getattr(format, "rank", None)) or not callable(
            getattr(format, "unrank", None)
        ):
            raise TypeError(
                "format must provide callable rank() and unrank() methods"
            )
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if len(key) != 32:
            raise ValueError(
                "Key must be exactly 32 bytes "
                "(16 for encryption + 16 for MAC)"
            )
        if (
            type(max_plaintext_bytes) is not int
            or not 0 <= max_plaintext_bytes <= self._ENCRYPTER_MAX_PLAINTEXT_BYTES
        ):
            raise ValueError(
                "max_plaintext_bytes must be an integer between 0 and 2**32 - 1"
            )

        cardinality = getattr(format, "cardinality", None)
        if cardinality is not None and (
            type(cardinality) is not int or cardinality <= 0
        ):
            raise FormatContractError(
                "format.cardinality must be a positive integer when provided"
            )

        self._format = format
        self._encrypter = Encrypter(key[:16], key[16:])
        self._cardinality = cardinality
        self._max_plaintext_bytes = max_plaintext_bytes
        self._max_frame_bytes = (
            max_plaintext_bytes + 1 + self._CIPHERTEXT_EXPANSION
        )

    @property
    def format(self) -> RankedFormat[Covertext]:
        """The ranked format used for covertext values."""

        return self._format

    @property
    def max_plaintext_bytes(self) -> int:
        """Configured resource ceiling; format capacity may impose a lower one."""

        return self._max_plaintext_bytes

    def encrypt(self, plaintext: bytes, /) -> Covertext:
        """Encrypt ``plaintext`` and unrank it into the configured format."""

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if len(plaintext) > self._max_plaintext_bytes:
            raise MessageTooLargeError(
                "plaintext exceeds the configured max_plaintext_bytes"
            )

        frame_length = len(plaintext) + 1 + self._CIPHERTEXT_EXPANSION
        if (
            self._cardinality is not None
            and self._cardinality < _frame_rank_limit(frame_length)
        ):
            raise FormatCapacityError(
                "format cannot represent every encrypted payload at this length"
            )

        ciphertext = self._encrypter.encrypt(plaintext)
        framed = self._FRAME_VERSION + ciphertext
        index = _bytes_to_rank(framed)
        try:
            return self._format.unrank(index)
        except Exception as exc:
            raise FormatCapacityError(
                "format cannot represent the encrypted payload rank"
            ) from exc

    def decrypt(self, covertext: Covertext, /) -> bytes:
        """Rank one complete format value and decrypt its plaintext."""

        try:
            index = self._format.rank(covertext)
        except Exception as exc:
            raise InvalidCovertextError("invalid covertext") from exc

        if type(index) is not int or index < 0:
            raise FormatContractError(
                "format.rank() must return a non-negative integer"
            )
        if self._cardinality is not None and index >= self._cardinality:
            raise InvalidCovertextError("invalid covertext")
        if index.bit_length() > 8 * self._max_frame_bytes + 1:
            raise InvalidCovertextError("invalid covertext")
        if _rank_byte_length(index) > self._max_frame_bytes:
            raise InvalidCovertextError("invalid covertext")

        framed = _rank_to_bytes(index)
        if not framed.startswith(self._FRAME_VERSION) or len(framed) < (
            len(self._FRAME_VERSION) + self._CIPHERTEXT_EXPANSION
        ):
            raise InvalidCovertextError("invalid covertext")

        ciphertext = framed[len(self._FRAME_VERSION):]
        try:
            if self._encrypter.getCiphertextLen(ciphertext) != len(ciphertext):
                raise InvalidCovertextError("invalid covertext")
            return self._encrypter.decrypt(ciphertext)
        except InvalidCovertextError:
            raise
        except (
            CiphertextTypeError,
            RecoverableDecryptionError,
            UnrecoverableDecryptionError,
        ) as exc:
            raise InvalidCovertextError("invalid covertext") from exc
