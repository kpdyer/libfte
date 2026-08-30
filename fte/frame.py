"""The version-1 wire frame: shortlex byte-string ranking and capacity math.

This module defines the mapping between encrypted frames and the integer
ranks a :class:`~fte.formats.base.RankedFormat` consumes, plus the capacity
math derived from it. Everything here is part of the wire format shared by
both endpoints, so any change breaks compatibility with existing peers.
"""

from __future__ import annotations


__all__ = [
    "FRAME_VERSION",
    "bytes_to_rank",
    "capacity_plaintext_limit",
    "frame_rank_limit",
    "rank_byte_length",
    "rank_offset",
    "rank_to_bytes",
]


# The outer byte reserves a wire-format version. The shortlex byte ranking
# below independently preserves the frame length and leading zero bytes.
FRAME_VERSION = b"\x01"


def rank_offset(length: int) -> int:
    """Return the first rank assigned to byte strings of ``length``."""

    return (256 ** length - 1) // 255


def bytes_to_rank(value: bytes) -> int:
    """Rank byte strings in length-first, then numeric, order."""

    offset = rank_offset(len(value))
    return offset + int.from_bytes(value, "big")


def rank_to_bytes(index: int) -> bytes:
    """Invert :func:`bytes_to_rank`, preserving leading zero bytes."""

    length = rank_byte_length(index)
    offset = rank_offset(length)
    return (index - offset).to_bytes(length, "big")


def rank_byte_length(index: int) -> int:
    """Return the byte-string length represented by a shortlex rank."""

    return ((255 * index + 1).bit_length() - 1) // 8


def frame_rank_limit(frame_length: int) -> int:
    """Return the exclusive upper rank bound for version-one frames."""

    return rank_offset(frame_length) + 2 * 256 ** (frame_length - 1)


def capacity_plaintext_limit(cardinality: int, expansion: int) -> int:
    """Largest plaintext length a finite format of ``cardinality`` can hold.

    Returns the greatest plaintext length ``L`` whose encrypted frame the format
    can still represent, or ``-1`` if it cannot represent even an empty message.
    This is the exact inverse of the per-length capacity check, so ``L`` bytes
    fit and ``L + 1`` bytes do not.
    """

    min_frame = 1 + expansion
    if cardinality < frame_rank_limit(min_frame):
        return -1
    # frame_rank_limit(fl) is dominated by 256**fl, so the frame length is
    # close to log256(cardinality). Estimate it, then correct by a step or two.
    frame_length = max(min_frame, cardinality.bit_length() // 8)
    # The estimate is never larger than the true frame length, so in practice
    # only the upward correction runs; the downward one is a defensive guard.
    while cardinality < frame_rank_limit(frame_length):  # pragma: no cover
        frame_length -= 1
    while cardinality >= frame_rank_limit(frame_length + 1):
        frame_length += 1
    return frame_length - 1 - expansion
