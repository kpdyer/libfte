"""The built-in regex provider for :class:`~fte.formats.base.RankedFormat`.

Each format ranks a finite slice of a byte language. The sibling DFA module
implements ranking; ``fte/formats/regex/README.md`` documents the regex dialect.
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


# The backslash-letter escapes regex2dfa implements (checked against the DFAs
# it emits). ``\x`` is handled separately because it takes two hex digits.
# Every other backslash-letter or backslash-digit pair is compiled to the bare
# letter or digit, so the scanner below rejects it instead.
_ESCAPES = frozenset("ntr0dsw")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _check_pattern_syntax(pattern: str) -> None:
    """Reject syntax that regex2dfa would silently misread.

    regex2dfa raises its own error for lazy quantifiers, ``(?...)`` groups and
    malformed patterns, but it reads several other constructs as plain text
    (or drops them) rather than reporting them. The scanner and anchor checks
    catch those before compilation; see the ``RegexFormat`` docstring and
    ``fte/formats/regex/README.md`` for the dialect it enforces.
    """

    for i, c in enumerate(pattern):
        if ord(c) > 0xFF:
            raise ValueError(
                f"character {c!r} (U+{ord(c):04X}) at position {i} in "
                f"{pattern!r} is not a byte: patterns denote byte languages, "
                "so every character must be in U+0000..U+00FF"
            )

    n = len(pattern)
    i = 0
    # Escapes and classes become one atom, so anchor checks cannot mistake
    # their literal punctuation for groups, alternatives, or assertions.
    tokens: list[tuple[str, int]] = []
    # Whether the current alternative (since the pattern start, the last '('
    # or the last '|') has no atom yet, and which of those opened it.
    empty_alt = True
    alt_start = ""
    while i < n:
        c = pattern[i]
        if c == "\\":
            # An escape pair: the backslash and the character it protects.
            esc = pattern[i + 1 : i + 2]
            if esc == "" or (esc == "$" and i + 2 == n):
                # regex2dfa strips a final '$' before parsing, so a pattern
                # ending in '\' or '\$' leaves a dangling backslash that it
                # compiles to a NUL byte.
                raise ValueError(
                    f"pattern {pattern!r} ends in a dangling backslash: "
                    "regex2dfa strips the final '$' first and compiles what "
                    "is left to a NUL byte; write '\\$$' or '[$]' for a "
                    "literal '$'"
                )
            if esc == "x":
                digits = pattern[i + 2 : i + 4]
                if len(digits) != 2 or not set(digits) <= _HEX_DIGITS:
                    raise ValueError(
                        f"'\\x' at position {i} in {pattern!r} needs exactly "
                        "two hex digits: regex2dfa reads a shorter one at "
                        "the end of the pattern as a different byte"
                    )
                tokens.append(("atom", i))
                i += 4
                empty_alt = False
                continue
            if esc == "0" and pattern[i + 2 : i + 3] in tuple("0123456789"):
                raise ValueError(
                    f"regex2dfa has no octal escapes: {pattern[i:i + 3]!r} "
                    f"in {pattern!r} is a NUL byte followed by the literal "
                    f"digit {pattern[i + 2]!r}; write '\\xHH' instead"
                )
            if esc.isascii() and esc.isalnum() and esc not in _ESCAPES:
                raise ValueError(
                    f"regex2dfa does not implement the escape "
                    f"{pattern[i:i + 2]!r} at position {i} in {pattern!r}: "
                    "it is unsupported and would not mean what it means in "
                    "Python's re (the supported escapes are \\n \\t \\r \\0 "
                    "\\xHH \\d \\s \\w and a backslash before punctuation)"
                )
            tokens.append(("atom", i))
            i += 2
            empty_alt = False
            continue
        if c == "[":
            # A character class. regex2dfa has no escapes inside one (a
            # backslash is a literal backslash) and the first ']' always
            # closes it, so '[]' is empty and '[\]]' is not what it looks like.
            start = i + 2 if pattern.startswith("[^", i) else i + 1
            end = pattern.find("]", start)
            if end == -1:
                break  # unclosed: regex2dfa reports it
            body = pattern[start:end]
            if not body:
                raise ValueError(
                    f"regex2dfa closes a character class at the first ']', "
                    f"so {pattern[i:end + 1]!r} at position {i} in "
                    f"{pattern!r} is an empty class; write '\\]' outside a "
                    "class for a literal ']'"
                )
            if "\\" in body:
                raise ValueError(
                    f"regex2dfa has no escapes inside a character class: the "
                    f"backslash in {pattern[i:end + 1]!r} at position {i} in "
                    f"{pattern!r} is a literal backslash and ']' still closes "
                    "the class; write the escape outside the class or list "
                    "the characters directly"
                )
            if "[:" in body:
                raise ValueError(
                    f"regex2dfa has no POSIX classes: '[:' in "
                    f"{pattern[i:end + 1]!r} at position {i} in {pattern!r} "
                    "would be matched literally; write the range out instead "
                    "(e.g. '[A-Za-z]')"
                )
            tokens.append(("atom", i))
            i = end + 1
            empty_alt = False
            continue
        if c == "{":
            raise ValueError(
                f"regex2dfa has no brace quantifiers: '{{' at position {i} "
                f"in {pattern!r} would be matched literally; write '\\{{' "
                "or '[{]' for a literal brace"
            )
        tokens.append((c if c in "()|^$*+?" else "atom", i))
        # Empty alternatives and empty groups. regex2dfa rejects most empty
        # alternatives itself, but one right before ')' silently folds the
        # atom before the group into the alternation ('x(b|)y' becomes
        # '(x|b)y'), and a quantifier after '()' silently binds to the
        # preceding atom ('a()*' becomes 'a*').
        if c == "(":
            empty_alt = True
            alt_start = "("
        elif c == "|":
            if empty_alt:
                raise ValueError(_empty_alternative(pattern, i))
            empty_alt = True
            alt_start = "|"
        elif c == ")":
            if empty_alt and alt_start == "|":
                raise ValueError(_empty_alternative(pattern, i))
            if empty_alt:
                raise ValueError(
                    f"empty group '()' at position {i - 1} in {pattern!r}: "
                    "regex2dfa applies a quantifier after it to the "
                    "preceding atom instead ('a()*' becomes 'a*')"
                )
            empty_alt = False
        elif c not in "^$":
            empty_alt = False
        i += 1
    if empty_alt and alt_start == "|":
        raise ValueError(_empty_alternative(pattern, n))
    _check_anchors(pattern, tokens)


def _check_anchors(pattern: str, tokens: list[tuple[str, int]]) -> None:
    """Allow only assertions that whole-value matching already guarantees.

    A group edge is not necessarily a value edge: ``a(^b)`` and ``(a$)b``
    must be rejected too. Check each alternative with the prefix/suffix of
    its enclosing groups included. Reject quantified anchored groups rather
    than trying to implement assertion semantics that regex2dfa discards.
    """
    group_anchors: list[int | None] = [None]
    for j, (token, pos) in enumerate(tokens):
        if token == "(":
            group_anchors.append(None)
        elif token == ")":
            if len(group_anchors) == 1:
                return  # regex2dfa reports unmatched parentheses
            anchor_pos = group_anchors.pop()
            if anchor_pos is not None:
                if j + 1 < len(tokens) and tokens[j + 1][0] in "*+?":
                    raise ValueError(
                        f"anchor at position {anchor_pos} in {pattern!r} is "
                        "inside a quantified group: regex2dfa drops anchors; "
                        "place optional whole-value anchors outside quantifiers"
                    )
                group_anchors[-1] = anchor_pos
        elif token in ("^", "$"):
            group_anchors[-1] = pos
            if j + 1 < len(tokens) and tokens[j + 1][0] in "*+?":
                raise ValueError(
                    f"quantified anchor at position {pos} in {pattern!r}: "
                    "regex2dfa drops anchors; anchors cannot be quantified"
                )
    if len(group_anchors) != 1:
        return  # regex2dfa reports unmatched parentheses

    for anchor, opening, closing, ordered in (
        ("^", "(", ")", tokens),
        ("$", ")", "(", reversed(tokens)),
    ):
        # Each entry includes the surrounding prefix (or suffix on the
        # reverse pass). An alternative resets only its own group's atoms.
        seen_atom = [False]
        for token, pos in ordered:
            if token == opening:
                seen_atom.append(seen_atom[-1])
            elif token == closing:
                seen_atom.pop()
                seen_atom[-1] = True
            elif token == "|":
                seen_atom[-1] = seen_atom[-2] if len(seen_atom) > 1 else False
            elif token == anchor and seen_atom[-1]:
                literal = r"\^" if anchor == "^" else "[$]"
                raise ValueError(
                    f"regex2dfa ignores {anchor!r} in the middle of a pattern "
                    f"(position {pos} in {pattern!r}; every pattern is matched "
                    "in full): enclosing groups must also be at the value "
                    f"edge; write {literal!r} for a literal {anchor!r}"
                )
            elif token not in ("^", "$"):
                seen_atom[-1] = True


def _empty_alternative(pattern: str, i: int) -> str:
    return (
        f"empty alternative at position {i} in {pattern!r}: regex2dfa "
        "rejects most of these and silently rewrites the language for one "
        "before ')' ('x(b|)y' becomes '(x|b)y'); write '?' after a group "
        "for an optional group"
    )


class RegexFormat:
    r"""A ranked byte format compiled from a regular expression.

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
            integers with ``min_length <= max_length``; if ``pattern`` has a
            character above U+00FF (patterns denote byte languages); if it
            uses syntax regex2dfa would silently misread (a brace quantifier
            such as ``{3}``, an escape it does not implement such as ``\D``,
            a backslash inside ``[...]``, a ``^`` or ``$`` away from a value
            edge or inside a quantified group, an empty alternative or an
            empty group ``()``; see the regex guide);
            if ``pattern`` is otherwise not a valid regular expression
            (including one matching only the empty string, such as ``^$``); or
            if the language has no words in the requested length range.

    Example:
        >>> fmt = RegexFormat(r"^[0-9a-f]+$", length=96)
        >>> (fmt.min_length, fmt.max_length) == (96, 96)
        True
        >>> fmt.unrank(fmt.rank(fmt.unrank(0))) == fmt.unrank(0)
        True
        >>> RegexFormat(r"^\{[0-9]+\}$", length=4).unrank(0)
        b'{00}'
        >>> RegexFormat(r"^[0-9]{3}$", length=3)  # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        ValueError: regex2dfa has no brace quantifiers: ...
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

        _check_pattern_syntax(pattern)
        try:
            # regex2dfa raises its own parser errors; the DFA rejects an
            # automaton with no symbols, including patterns such as '^$'
            # that match only the empty string.
            dfa = DFA(regex2dfa.regex2dfa(pattern), hi)
        except Exception as exc:
            raise ValueError(
                f"invalid regular expression: {pattern!r}"
            ) from exc

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
        max_length)``, with the lengths in decimal UTF-8. It hashes the
        pattern *text*, so equal fingerprints guarantee identical ranking
        (which is what the deterministic engine relies on), but two spellings
        of one language get different fingerprints; use the same pattern
        string at both endpoints of a deterministic cipher.
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

        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("value must be bytes")
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
