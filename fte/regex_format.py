"""Built-in regular-expression implementation of RankedFormat[bytes]."""

from __future__ import annotations

import regex2dfa

from fte.dfa import DFA


__all__ = ["RegexFormat"]


class RegexFormat:
    """A fixed-length byte format compiled from a regular expression."""

    __slots__ = ("pattern", "length", "_dfa", "cardinality")

    def __init__(self, pattern: str, *, length: int) -> None:
        if not isinstance(pattern, str):
            raise TypeError("pattern must be a string")
        if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
            raise ValueError("length must be a positive integer")

        self.pattern = pattern
        self.length = length
        self._dfa = DFA(regex2dfa.regex2dfa(pattern), length)
        self.cardinality = self._dfa.num_words_in_language(length, length)

    def rank(self, value: bytes, /) -> int:
        """Return the lexicographic rank of a canonical fixed-length value."""

        return self._dfa.rank(value)

    def unrank(self, index: int, /) -> bytes:
        """Return the fixed-length value at ``index``."""

        return self._dfa.unrank(index)
