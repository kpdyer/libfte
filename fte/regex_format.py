"""Built-in regular-expression implementation of RankedFormat[bytes]."""

from __future__ import annotations

import regex2dfa

from fte.dfa import DFA, LanguageIsEmptySetException


__all__ = ["RegexFormat"]


class RegexFormat:
    """A fixed-length byte format compiled from a regular expression."""

    __slots__ = ("pattern", "length", "_dfa", "cardinality")

    def __init__(self, pattern: str, *, length: int) -> None:
        """Compile ``pattern`` into a fixed-length ranked byte format.

        Args:
            pattern: A regular expression describing the covertext language.
            length: The exact byte length of every covertext value.

        Raises:
            TypeError: If ``pattern`` is not a string.
            ValueError: If ``length`` is not a positive integer, if ``pattern``
                is not a valid regular expression, or if the language has no
                words of exactly ``length`` bytes.
        """
        if not isinstance(pattern, str):
            raise TypeError("pattern must be a string")
        if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
            raise ValueError("length must be a positive integer")

        try:
            dfa_str = regex2dfa.regex2dfa(pattern)
        except Exception as exc:  # regex2dfa raises its own parser errors
            raise ValueError(
                f"invalid regular expression: {pattern!r}"
            ) from exc

        try:
            dfa = DFA(dfa_str, length)
        except LanguageIsEmptySetException as exc:
            raise ValueError(
                f"pattern {pattern!r} has no words of length {length}"
            ) from exc

        self.pattern = pattern
        self.length = length
        self._dfa = dfa
        self.cardinality = self._dfa.num_words_in_language(length, length)

    def rank(self, value: bytes, /) -> int:
        """Return the lexicographic rank of a canonical fixed-length value."""

        return self._dfa.rank(value)

    def unrank(self, index: int, /) -> bytes:
        """Return the fixed-length value at ``index``."""

        return self._dfa.unrank(index)
