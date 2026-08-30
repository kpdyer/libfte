"""``RegexFormat``: the reference :class:`~fte.formats.base.RankedFormat`.

This is the provider libfte ships with, and the worked example to copy when you
write your own. Each instance is a format: a ranked, finite slice of the byte
language a pattern denotes, so ciphertext comes out looking like the pattern
you chose: hex, alphanumeric tokens, URL paths, and so on.

Covertext length is the format's choice, not the engine's. ``RegexFormat`` lets
you pin it or leave it to vary:

* ``RegexFormat(pattern, length=N)`` ranks the words of exactly ``N`` bytes, so
  every covertext is ``N`` bytes long. This is the classic fixed-slice behavior,
  which makes a stream trivial to parse (fixed-size chunks).
* ``RegexFormat(pattern, min_length=a, max_length=b)`` ranks the words whose
  length is in ``[a, b]``, ordered by length and then lexicographically, so a
  covertext's length varies with the message. ``min_length == max_length`` is
  the fixed case, identical to ``length=``.

There is deliberately no cryptography here. Compiling and ranking the DFA (in
the sibling :mod:`~fte.formats.regex.dfa` module) is the provider's only job;
:class:`fte.FTE` owns encryption, authentication, and framing. That separation
is exactly what makes a new provider easy to add.
"""

from __future__ import annotations

import hashlib

import regex2dfa

from fte.formats.regex.dfa import DFA


__all__ = ["RegexFormat"]


def _positive_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


class RegexFormat:
    """A ranked byte format compiled from a regular expression.

    Every covertext matches ``pattern`` and has a length in
    ``[min_length, max_length]``. The rank space is ``range(cardinality)``, where
    ``cardinality`` is the number of matching words in that length range;
    exposing it lets :class:`fte.FTE` reject an over-long message before
    encrypting it.

    Args:
        pattern: A regular expression denoting the covertext language.
        length: A single fixed covertext length. Shorthand for
            ``min_length == max_length == length``. Mutually exclusive with
            ``min_length`` / ``max_length``.
        min_length: The smallest covertext length (given together with
            ``max_length``).
        max_length: The largest covertext length (given together with
            ``min_length``).

    Attributes:
        pattern (str): The regular expression.
        min_length (int): The smallest covertext length.
        max_length (int): The largest covertext length (equals ``min_length``
            for a fixed-length format).
        cardinality (int): The number of matching words in the length range.

    Raises:
        TypeError: If ``pattern`` is not a string.
        ValueError: If the length arguments are missing, mixed, or not positive
            integers with ``min_length <= max_length``; if ``pattern`` is not a
            valid regular expression; or if the language has no words in the
            requested length range.

    Example:
        >>> fmt = RegexFormat(r"^[0-9a-f]+$", length=96)
        >>> (fmt.min_length, fmt.max_length) == (96, 96)
        True
        >>> fmt.unrank(fmt.rank(fmt.unrank(0))) == fmt.unrank(0)
        True
    """

    __slots__ = (
        "pattern",
        "min_length",
        "max_length",
        "cardinality",
        "_dfa",
        "_offsets",
        "_counts",
        "_fingerprint",
    )

    def __init__(
        self,
        pattern: str,
        *,
        length: int | None = None,
        min_length: int | None = None,
        max_length: int | None = None,
    ) -> None:
        if not isinstance(pattern, str):
            raise TypeError("pattern must be a string")

        if length is not None:
            if min_length is not None or max_length is not None:
                raise ValueError(
                    "pass either length, or min_length and max_length, "
                    "not both"
                )
            lo = hi = _positive_int("length", length)
        elif min_length is not None or max_length is not None:
            if min_length is None or max_length is None:
                raise ValueError(
                    "min_length and max_length must be given together"
                )
            lo = _positive_int("min_length", min_length)
            hi = _positive_int("max_length", max_length)
            if lo > hi:
                raise ValueError("min_length must not exceed max_length")
        else:
            raise ValueError("provide length, or min_length and max_length")

        try:
            dfa_str = regex2dfa.regex2dfa(pattern)
        except Exception as exc:  # regex2dfa raises its own parser errors
            raise ValueError(
                f"invalid regular expression: {pattern!r}"
            ) from exc
        dfa = DFA(dfa_str, hi)

        # Order the language's slice by length first, then lexicographically
        # within a length. Record where each length starts in the combined rank
        # space.
        offsets = {}
        counts = {}
        cumulative = 0
        for word_length in range(lo, hi + 1):
            count = dfa.num_words(word_length)
            offsets[word_length] = cumulative
            counts[word_length] = count
            cumulative += count
        if cumulative == 0:
            raise ValueError(
                f"pattern {pattern!r} has no words with length in [{lo}, {hi}]"
            )

        self.pattern = pattern
        self.min_length = lo
        self.max_length = hi
        self.cardinality = cumulative
        self._dfa = dfa
        self._offsets = offsets
        self._counts = counts
        self._fingerprint = hashlib.sha256(
            b"fte:regex:1|"
            + pattern.encode("utf-8")
            + b"|"
            + str(lo).encode("utf-8")
            + b"|"
            + str(hi).encode("utf-8")
        ).digest()

    @property
    def fingerprint(self) -> bytes:
        """Stable identifier for this pattern and length range.

        ``sha256(b"fte:regex:1|" + pattern + b"|" + min_length + b"|" +
        max_length)``, with the lengths in decimal UTF-8. Two ``RegexFormat``
        instances share a fingerprint exactly when they rank identically,
        which is what the deterministic engine relies on.
        """

        return self._fingerprint

    def slice_bounds(self, length: int, /) -> tuple[int, int]:
        """Return ``(offset, count)`` for the length-``length`` slice.

        ``offset`` is the first rank assigned to words of ``length`` bytes and
        ``count`` is how many there are (possibly zero). ``length`` must lie
        in ``[min_length, max_length]``.
        """

        if length < self.min_length or length > self.max_length:
            raise ValueError(
                f"length {length} outside "
                f"[{self.min_length}, {self.max_length}]"
            )
        return self._offsets[length], self._counts[length]

    def rank(self, value: bytes, /) -> int:
        """Return the rank of a canonical covertext ``value``."""

        n = len(value)
        if n < self.min_length or n > self.max_length:
            raise ValueError(
                f"value length {n} outside "
                f"[{self.min_length}, {self.max_length}]"
            )
        return self._offsets[n] + self._dfa.rank(value)

    def unrank(self, index: int, /) -> bytes:
        """Return the canonical covertext at ``index``."""

        if type(index) is not int or not 0 <= index < self.cardinality:
            raise ValueError(
                f"index {index!r} outside [0, {self.cardinality})"
            )
        for word_length in range(self.min_length, self.max_length + 1):
            count = self._counts[word_length]
            if index < count:
                return self._dfa.unrank(index, word_length)
            index -= count
        raise AssertionError("unreachable: cardinality guard already passed")
