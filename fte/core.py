"""The FTE engine: encrypt bytes into values drawn from a ranked format.

This module owns the engine itself: authenticated encryption wrapped in the
version-1 wire frame defined by :mod:`fte.frame`. The covertext language is
supplied from :mod:`fte.formats` as a :class:`RankedFormat`, so the engine
never needs to know what the output looks like.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from fte import frame
from fte._encrypter import DecryptionError, Encrypter
from fte.formats.base import RankedFormat


__all__ = [
    "FTE",
    "FTEError",
    "FormatCapacityError",
    "FormatContractError",
    "InvalidCovertextError",
    "MessageTooLargeError",
]


Covertext = TypeVar("Covertext")


class FTEError(Exception):
    """Base class for errors raised by the FTE engine."""


class FormatContractError(FTEError):
    """Raised when a format violates the :class:`RankedFormat` contract."""


class FormatCapacityError(FTEError):
    """Raised when a format cannot represent an encrypted payload rank."""


class MessageTooLargeError(FTEError):
    """Raised when plaintext exceeds the configured resource limit."""


class InvalidCovertextError(FTEError):
    """Raised when a format value cannot be authenticated and decrypted."""


class FTE(Generic[Covertext]):
    """Encrypt bytes into values supplied by a :class:`RankedFormat`.

    The format is structural: any object with callable ``rank`` and ``unrank``
    methods works without inheriting from this package or importing it at
    runtime.

    One complete format value represents one encrypted message. Since an
    arbitrary value has no generic stream boundary, ``decrypt`` consumes exactly
    one value and returns plaintext directly, without a stream remainder.

    ``max_plaintext_bytes`` is the largest plaintext this instance will accept.
    Leave it unset and it is chosen for you: a finite format (one that exposes a
    ``cardinality``, such as :class:`~fte.formats.regex.RegexFormat`) uses the
    exact size its capacity allows, and an unbounded format falls back to a 1 MiB
    default. It is also the guard that lets ``decrypt`` reject an oversized
    covertext before materializing a huge integer, so set it explicitly only to
    tighten that bound (a smaller resource ceiling) or to cap an otherwise
    unbounded format. Both endpoints should agree on it when messages may exceed
    the default.
    """

    _FRAME_VERSION = frame.FRAME_VERSION
    _CIPHERTEXT_EXPANSION = Encrypter._CTXT_EXPANSION

    _DEFAULT_MAX_PLAINTEXT_BYTES = 1 << 20
    _ENCRYPTER_MAX_PLAINTEXT_BYTES = Encrypter._MAX_PLAINTEXT_LENGTH

    __slots__ = (
        "_format",
        "_encrypter",
        "_cardinality",
        "_resource_max",
        "_capacity_limit",
        "_max_plaintext_bytes",
        "_max_frame_bytes",
    )

    def __init__(
        self,
        *,
        format: RankedFormat[Covertext],
        key: bytes,
        max_plaintext_bytes: int | None = None,
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
        if max_plaintext_bytes is not None and (
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

        # The resource / DoS ceiling: an explicit value, else a flat default. It
        # is never derived, so it stays a real bound even for unbounded formats.
        resource_max = (
            self._DEFAULT_MAX_PLAINTEXT_BYTES
            if max_plaintext_bytes is None
            else max_plaintext_bytes
        )

        # For a finite format, the largest plaintext its capacity can hold; None
        # for an unbounded format. The effective ceiling is the tighter of the
        # two, and it drives the decrypt-side size guard.
        if cardinality is None:
            capacity_limit = None
            effective = resource_max
        else:
            capacity_limit = min(
                frame.capacity_plaintext_limit(
                    cardinality, self._CIPHERTEXT_EXPANSION
                ),
                self._ENCRYPTER_MAX_PLAINTEXT_BYTES,
            )
            if capacity_limit < 0:
                raise FormatCapacityError(
                    "format is too small to hold even an empty encrypted message"
                )
            effective = min(resource_max, capacity_limit)

        self._format = format
        self._encrypter = Encrypter(key[:16], key[16:])
        self._cardinality = cardinality
        self._resource_max = resource_max
        self._capacity_limit = capacity_limit
        self._max_plaintext_bytes = effective
        self._max_frame_bytes = effective + 1 + self._CIPHERTEXT_EXPANSION

    @property
    def format(self) -> RankedFormat[Covertext]:
        """The ranked format used for covertext values."""

        return self._format

    @property
    def max_plaintext_bytes(self) -> int:
        """Largest plaintext this instance accepts.

        For a finite format this defaults to the exact size its capacity allows;
        for an unbounded format it is the configured ceiling (1 MiB by default).
        An explicit ``max_plaintext_bytes`` lowers it further.
        """

        return self._max_plaintext_bytes

    def encrypt(self, plaintext: bytes, /) -> Covertext:
        """Encrypt ``plaintext`` and unrank it into the configured format."""

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        # Exceeding the resource ceiling is the caller's own limit; exceeding a
        # finite format's capacity is the format being too small. The capacity
        # check is the exact inverse of frame.capacity_plaintext_limit.
        if len(plaintext) > self._resource_max:
            raise MessageTooLargeError(
                "plaintext exceeds the configured max_plaintext_bytes"
            )
        if (
            self._capacity_limit is not None
            and len(plaintext) > self._capacity_limit
        ):
            raise FormatCapacityError(
                "format cannot represent every encrypted payload at this length"
            )

        ciphertext = self._encrypter.encrypt(plaintext)
        framed = self._FRAME_VERSION + ciphertext
        index = frame.bytes_to_rank(framed)
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
        # These size guards stay lazy per call: a precomputed 256**N rank bound
        # would make __init__ cost and retained memory linear in
        # max_plaintext_bytes, while these checks are cheap on every decrypt.
        if self._cardinality is not None and index >= self._cardinality:
            raise InvalidCovertextError("invalid covertext")
        if index.bit_length() > 8 * self._max_frame_bytes + 1:
            raise InvalidCovertextError("invalid covertext")
        if frame.rank_byte_length(index) > self._max_frame_bytes:
            raise InvalidCovertextError("invalid covertext")

        framed = frame.rank_to_bytes(index)
        if not framed.startswith(self._FRAME_VERSION) or len(framed) < (
            len(self._FRAME_VERSION) + self._CIPHERTEXT_EXPANSION
        ):
            raise InvalidCovertextError("invalid covertext")

        ciphertext = framed[len(self._FRAME_VERSION):]
        try:
            return self._encrypter.decrypt(ciphertext)
        except DecryptionError:
            pass
        # Raised outside the handler: pre-MAC header detail must not chain
        # into public errors, so neither __cause__ nor __context__ is set.
        raise InvalidCovertextError("invalid covertext") from None
