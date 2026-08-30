"""``RegexFormat`` -- the reference :class:`~fte.formats.base.RankedFormat`.

This is the format libfte ships with, and the worked example to copy when you
write your own provider. It turns a regular expression into a fixed-length byte
language and ranks that language, so ciphertext comes out looking like the
pattern you chose -- hex, alphanumeric tokens, URL paths, and so on.

The whole provider is three things:

* a constructor that compiles the pattern once and records the language size
  (``cardinality``), and
* the two inverse methods every ranked format owes the engine: ``rank`` and
  ``unrank``.

There is deliberately no cryptography here. Compiling and ranking a DFA is the
provider's only job; :class:`fte.FTE` owns encryption, authentication, and
framing. That separation is exactly what makes a new format easy to add.
"""

from __future__ import annotations

import regex2dfa

from fte.dfa import DFA, LanguageIsEmptySetException


__all__ = ["RegexFormat"]


class RegexFormat:
    """A fixed-length byte format compiled from a regular expression.

    Every covertext is exactly ``length`` bytes and matches ``pattern``. The
    rank space is ``range(cardinality)``, where ``cardinality`` is the number of
    words of that exact length in the language -- so the format is a
    :class:`~fte.formats.base.FiniteRankedFormat`, and :class:`fte.FTE` can
    reject an over-long message before encrypting it.

    Example:
        >>> fmt = RegexFormat(r"^[0-9a-f]+$", length=96)
        >>> fmt.unrank(fmt.rank(fmt.unrank(0))) == fmt.unrank(0)
        True
    """

    __slots__ = ("pattern", "length", "cardinality", "_dfa")

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
        self.cardinality = dfa.num_words_in_language(length, length)

    def rank(self, value: bytes, /) -> int:
        """Return the lexicographic rank of a canonical fixed-length value."""

        return self._dfa.rank(value)

    def unrank(self, index: int, /) -> bytes:
        """Return the fixed-length value at ``index``."""

        return self._dfa.unrank(index)
