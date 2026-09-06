"""``BytesFormat``: the shortlex ranked format for raw byte strings.

This is the identity covertext language: every finite byte string is a valid
value, ordered length-first and then numerically (shortlex), exactly the
ordering used by the wire format. It is the default ``input_format`` for
:class:`fte.FTE`, so the classic ``bytes -> AE -> format`` pipeline is just
``input_format=BytesFormat()``.

Unlike :class:`~fte.formats.regex.RegexFormat`, this language is *unbounded*:
it exposes no ``cardinality`` because there is no largest byte string.
"""

from __future__ import annotations

from fte import _frame as frame


__all__ = ["BytesFormat"]


class BytesFormat:
    """The shortlex ranked format over every finite byte string.

    ``rank`` and ``unrank`` are inverse across the whole non-negative integer
    line: the empty string ranks 0, single bytes rank 1..256, two-byte strings
    follow, and so on, so length and leading zero bytes are always preserved.

    The language is unbounded, so this format deliberately exposes no
    ``cardinality``. Its ``fingerprint`` names the ordering as part of the
    wire contract; sender and receiver must use the same one.
    """

    __slots__ = ()

    #: Stable identifier for the ordering (part of the wire contract).
    fingerprint = b"fte:bytes:shortlex:1"

    def rank(self, value: bytes, /) -> int:
        """Return the shortlex rank of the byte string ``value``."""

        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("value must be bytes")
        return frame.bytes_to_rank(bytes(value))

    def unrank(self, index: int, /) -> bytes:
        """Return the byte string at shortlex rank ``index``."""

        if type(index) is not int or index < 0:
            raise ValueError("index must be a non-negative integer")
        return frame.rank_to_bytes(index)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "BytesFormat()"
