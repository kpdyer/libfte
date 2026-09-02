"""Tests for the built-in RegexFormat provider (fixed and variable length)."""

import os
import re
import unittest

import fte


KEY = bytes(range(32))


class Tests(unittest.TestCase):
    # ------------------------------------------------------------------ #
    # Construction and the length arguments                              #
    # ------------------------------------------------------------------ #

    def test_length_is_shorthand_for_equal_min_max(self):
        fixed = fte.RegexFormat(r"^[0-9a-f]+$", length=96)
        equal = fte.RegexFormat(r"^[0-9a-f]+$", min_length=96, max_length=96)

        self.assertEqual((fixed.min_length, fixed.max_length), (96, 96))
        self.assertEqual((equal.min_length, equal.max_length), (96, 96))
        self.assertEqual(fixed.cardinality, equal.cardinality)
        self.assertEqual(fixed.cardinality, 16 ** 96)

    def test_variable_length_cardinality_sums_the_range(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", min_length=1, max_length=3)
        # 16 + 16**2 + 16**3 words.
        self.assertEqual(fmt.cardinality, 16 + 16 ** 2 + 16 ** 3)
        self.assertEqual((fmt.min_length, fmt.max_length), (1, 3))

    def test_pattern_must_be_str(self):
        with self.assertRaises(TypeError):
            fte.RegexFormat(b"^[0-9a-f]+$", length=8)

    def test_missing_length_arguments_is_value_error(self):
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^[0-9a-f]+$")

    def test_length_and_range_are_mutually_exclusive(self):
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^[0-9a-f]+$", length=8, max_length=8)

    def test_min_and_max_must_be_given_together(self):
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^[0-9a-f]+$", min_length=4)
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^[0-9a-f]+$", max_length=4)

    def test_length_arguments_must_be_positive_ints(self):
        for kwargs in (
            {"length": 0},
            {"length": -1},
            {"length": True},
            {"length": 1.0},
            {"min_length": 0, "max_length": 4},
            {"min_length": 4, "max_length": True},
        ):
            with self.assertRaises(ValueError):
                fte.RegexFormat(r"^[0-9a-f]+$", **kwargs)

    def test_min_greater_than_max_is_value_error(self):
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^[0-9a-f]+$", min_length=5, max_length=4)

    def test_invalid_pattern_is_value_error(self):
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^(ab", length=4)  # unbalanced parenthesis

    def test_empty_language_pattern_is_value_error(self):
        # These compile to an automaton with no symbols; the DFA's own error
        # must surface as ValueError, chained from the original.
        from fte.formats.regex.dfa import InvalidFSTFormat

        for pattern in ("", "^", "$", "^$"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(
                    ValueError, "invalid regular expression"
                ) as cm:
                    fte.RegexFormat(pattern, length=1)
                self.assertIsInstance(cm.exception.__cause__, InvalidFSTFormat)
        # '()' is rejected by the scanner before compilation.
        with self.assertRaises(ValueError):
            fte.RegexFormat("()", length=1)

    def test_non_latin1_character_is_value_error(self):
        # Patterns denote byte languages; a character above U+00FF has no byte.
        for pattern in ("^€$", "^😀$", "^[a-z€]$", "^a|😀$"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "U\\+0000..U\\+00FF"):
                    fte.RegexFormat(pattern, length=1)
        # U+00FF itself is the byte 0xff.
        self.assertEqual(fte.RegexFormat("^\xff$", length=1).unrank(0), b"\xff")

    def test_rank_rejects_non_bytes(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=4)
        for bad in ("abcd", [0x61] * 4, 0x61, None):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    fmt.rank(bad)
        self.assertEqual(fmt.rank(bytearray(b"abcd")), fmt.rank(b"abcd"))

    def test_empty_language_for_range_is_value_error(self):
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^(ab)+$", length=5)  # no words of odd length
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^abc$", length=2)  # literal longer than length

    def test_range_is_valid_when_some_lengths_are_empty(self):
        # ``(ab)+`` has words only at even lengths; a [1, 6] range still holds
        # ab, abab, ababab.
        fmt = fte.RegexFormat(r"^(ab)+$", min_length=1, max_length=6)
        self.assertEqual(fmt.cardinality, 3)
        self.assertEqual(
            sorted(fmt.unrank(i) for i in range(3)),
            [b"ab", b"abab", b"ababab"],
        )

    # ------------------------------------------------------------------ #
    # rank / unrank as a RankedFormat                                    #
    # ------------------------------------------------------------------ #

    def test_conforms_to_rankedformat_protocol(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=8)
        self.assertIsInstance(fmt, fte.RankedFormat)
        self.assertIs(type(fmt.cardinality), int)

    def test_fixed_length_inverse_laws(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=8)
        for index in (0, 1, 255, fmt.cardinality // 2, fmt.cardinality - 1):
            self.assertEqual(fmt.rank(fmt.unrank(index)), index)
        # Every fixed covertext is exactly `length` bytes.
        self.assertEqual(len(fmt.unrank(0)), 8)
        self.assertEqual(len(fmt.unrank(fmt.cardinality - 1)), 8)

    def test_variable_length_inverse_laws_and_ordering(self):
        fmt = fte.RegexFormat(r"^[a-z]+$", min_length=1, max_length=4)
        seen_lengths = set()
        prev_length = 0
        for index in range(fmt.cardinality):
            value = fmt.unrank(index)
            self.assertTrue(1 <= len(value) <= 4)
            self.assertEqual(fmt.rank(value), index)
            # Ranking is length-first: length never decreases as index grows.
            self.assertGreaterEqual(len(value), prev_length)
            prev_length = len(value)
            seen_lengths.add(len(value))
        self.assertEqual(seen_lengths, {1, 2, 3, 4})

    def test_unrank_rejects_out_of_range_index(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=8)
        for bad in (-1, fmt.cardinality, fmt.cardinality + 1, True, 1.0):
            with self.assertRaises(ValueError):
                fmt.unrank(bad)

    def test_rank_rejects_wrong_length_value(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", min_length=4, max_length=6)
        with self.assertRaises(ValueError):
            fmt.rank(b"abc")       # length 3, below min
        with self.assertRaises(ValueError):
            fmt.rank(b"abcdefg")   # length 7, above max

    def test_rank_rejects_non_member(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=4)
        with self.assertRaises(Exception):
            fmt.rank(b"zzzz")  # 'z' is not in the hex alphabet

    def test_multistate_dfa_roundtrips(self):
        # ``^(0|1)[a-z]+$`` compiles to a multi-state, non-dense DFA, exercising
        # the standard Goldberg-Sipser branches that a single self-looping state
        # never reaches. Test it both fixed and variable length.
        pattern = r"^(0|1)[a-z]+$"
        matcher = re.compile(pattern.encode())
        for fmt in (
            fte.RegexFormat(pattern, length=12),
            fte.RegexFormat(pattern, min_length=6, max_length=12),
        ):
            for index in (0, fmt.cardinality // 3, fmt.cardinality - 1):
                value = fmt.unrank(index)
                self.assertIsNotNone(matcher.fullmatch(value))
                self.assertEqual(fmt.rank(value), index)

    # ------------------------------------------------------------------ #
    # Syntax regex2dfa would silently misread                            #
    # ------------------------------------------------------------------ #

    def test_brace_quantifier_is_rejected(self):
        # regex2dfa has no brace quantifiers: it would match '{3}' literally.
        for pattern in (r"^[0-9]{3}$", r"^[0-9]{2,4}$"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "brace quantifier"):
                    fte.RegexFormat(pattern, length=4)

    def test_escaped_brace_is_a_literal_brace(self):
        self.assertEqual(fte.RegexFormat(r"^\{$", length=1).unrank(0), b"{")
        self.assertEqual(fte.RegexFormat(r"^[{]$", length=1).unrank(0), b"{")
        # '}' on its own needs no escape.
        self.assertEqual(fte.RegexFormat(r"^a}$", length=2).unrank(0), b"a}")

    def test_escaped_backslash_before_brace_is_rejected(self):
        # r"\\{" is an escaped backslash followed by an unescaped brace.
        with self.assertRaisesRegex(ValueError, "brace quantifier"):
            fte.RegexFormat(r"^\\{$", length=2)

    def test_negated_class_escapes_are_rejected(self):
        # regex2dfa compiles each of these to the bare letter.
        for escape in (r"\D", r"\S", r"\W"):
            with self.subTest(escape=escape):
                with self.assertRaisesRegex(ValueError, "does not implement"):
                    fte.RegexFormat("^" + escape + "$", length=1)

    def test_anchor_and_boundary_escapes_are_rejected(self):
        for escape in (r"\b", r"\B", r"\A", r"\Z", r"\z"):
            with self.subTest(escape=escape):
                with self.assertRaisesRegex(ValueError, "does not implement"):
                    fte.RegexFormat("^a" + escape + "$", length=2)

    def test_control_character_escapes_are_rejected(self):
        for escape in (r"\f", r"\v", r"\a", r"\e"):
            with self.subTest(escape=escape):
                with self.assertRaisesRegex(ValueError, "does not implement"):
                    fte.RegexFormat("^" + escape + "$", length=1)

    def test_unicode_and_quoting_escapes_are_rejected(self):
        for escape in (r"\u0041", r"\U00000041", r"\p{L}", r"\P{L}", r"\Qa\E"):
            with self.subTest(escape=escape):
                with self.assertRaisesRegex(ValueError, "does not implement"):
                    fte.RegexFormat("^" + escape + "$", length=1)

    def test_backreference_escape_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "does not implement"):
            fte.RegexFormat(r"^(a)\1$", length=2)  # regex2dfa: literal 'a1'

    def test_octal_escape_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "octal"):
            fte.RegexFormat(r"^\012$", length=1)

    def test_short_hex_escape_is_rejected(self):
        for pattern in (r"^\x4$", r"^\x$", r"^[a-z]\x$", r"^\xg1$"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "two hex digits"):
                    fte.RegexFormat(pattern, length=2)

    def test_trailing_backslash_is_rejected(self):
        # regex2dfa strips the final '$' before parsing, so each of these
        # would end in a dangling backslash that it compiles to a NUL byte.
        for pattern in (r"^a\$", r"^a\\\$", "^a\\"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "dangling backslash"):
                    fte.RegexFormat(pattern, length=2)
        # An escaped '$' followed by the anchor, mid-pattern, or in a class
        # is a literal dollar sign.
        self.assertEqual(fte.RegexFormat(r"^a\$$", length=2).unrank(0), b"a$")
        self.assertEqual(fte.RegexFormat(r"^a[$]$", length=2).unrank(0), b"a$")
        self.assertEqual(fte.RegexFormat(r"^a\$b$", length=3).unrank(0), b"a$b")

    def test_backslash_inside_class_is_rejected(self):
        # Inside [...] regex2dfa reads a backslash as a literal backslash and
        # the first ']' still closes the class.
        for pattern in (r"^[\d]$", r"^[\n]$", r"^[\]]$", r"^[\\]$", r"^[a\-z]$"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "inside a character"):
                    fte.RegexFormat(pattern, length=1)

    def test_empty_class_is_rejected(self):
        for pattern in (r"^[]$", r"^[]a]$", r"^[^]$", r"^[^]a]$"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "empty class"):
                    fte.RegexFormat(pattern, length=1)

    def test_posix_class_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "POSIX"):
            fte.RegexFormat(r"^[[:alpha:]]+$", length=4)

    def test_mid_pattern_anchor_is_rejected(self):
        for pattern in (r"^a$b$", r"^a^b$", r"a$b", r"a^b"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "middle of a pattern"):
                    fte.RegexFormat(pattern, length=2)

    def test_empty_alternative_is_rejected(self):
        # regex2dfa rejects most empty alternatives itself, but one right
        # before ')' silently folds the preceding atom into the alternation
        # ('x(b|)y' becomes '(x|b)y'), so the scanner rejects them all.
        for pattern in (
            r"^x(b|)y$", r"^(a|)b$", r"^xy(a|)$", r"^(a|b|)c$",   # before ')'
            r"^x(|b)y$", r"^(|a)b$",                              # after '('
            r"^a||b$", r"a||b",                                   # '||'
            r"^|ab$", r"|a", r"^$|^a$",                           # at start
            r"^ab|$", r"a|", r"^a$|$",                            # at end
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "empty alternative"):
                    fte.RegexFormat(pattern, min_length=1, max_length=3)
        # The optional-group spelling is the supported one.
        fmt = fte.RegexFormat(r"^x(b)?y$", min_length=1, max_length=3)
        self.assertEqual(
            {fmt.unrank(i) for i in range(fmt.cardinality)}, {b"xy", b"xby"}
        )

    def test_empty_group_is_rejected(self):
        # regex2dfa binds a quantifier after '()' to the preceding atom.
        for pattern in (r"^a()*$", r"^a()+$", r"^a()?$", r"^()a$", r"()"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "empty group"):
                    fte.RegexFormat(pattern, length=1)

    def test_anchors_at_alternative_edges_are_accepted(self):
        for pattern in (r"^a$|^b$", r"^(^a|^b)$", r"a|b", r"^a", r"a$", r"^^a$$"):
            with self.subTest(pattern=pattern):
                self.assertEqual(fte.RegexFormat(pattern, length=1).unrank(0), b"a")

    def test_supported_escapes_compile_to_their_meaning(self):
        self.assertEqual(
            fte.RegexFormat(r"^\x41\n\t\r\0\.$", length=6).unrank(0),
            b"A\n\t\r\x00.",
        )
        self.assertEqual(fte.RegexFormat(r"^\d$", length=1).cardinality, 10)
        self.assertEqual(fte.RegexFormat(r"^\w$", length=1).cardinality, 63)
        space = fte.RegexFormat(r"^\s$", length=1)
        self.assertEqual(
            {space.unrank(i) for i in range(space.cardinality)},
            {b"\t", b"\n", b"\r", b" "},
        )
        self.assertEqual(fte.RegexFormat(r"^.$", length=1).cardinality, 256)
        self.assertEqual(fte.RegexFormat(r"^[^a]$", length=1).cardinality, 255)

    # ------------------------------------------------------------------ #
    # Through the FTE engine                                             #
    # ------------------------------------------------------------------ #

    def test_fixed_length_covertext_through_fte(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=96)
        cipher = fte.FTE(output_format=fmt, key=KEY)
        for plaintext in (b"", b"x", b"hello", os.urandom(10)):
            covertext = cipher.encrypt(plaintext)
            self.assertEqual(len(covertext), 96)
            self.assertIsNotNone(re.fullmatch(rb"[0-9a-f]+", covertext))
            self.assertEqual(cipher.decrypt(covertext), plaintext)

    def test_variable_length_covertext_through_fte(self):
        fmt = fte.RegexFormat(r"^[a-z]+$", min_length=40, max_length=400)
        cipher = fte.FTE(output_format=fmt, key=KEY)
        lengths = set()
        for plaintext in (b"", b"hi", b"hello world", os.urandom(64)):
            covertext = cipher.encrypt(plaintext)
            self.assertTrue(40 <= len(covertext) <= 400)
            self.assertIsNotNone(re.fullmatch(rb"[a-z]+", covertext))
            self.assertEqual(cipher.decrypt(covertext), plaintext)
            lengths.add(len(covertext))
        # Different plaintext sizes yield covertexts of different lengths.
        self.assertGreater(len(lengths), 1)

    def test_cross_endpoint_roundtrip(self):
        for fmt_kwargs in ({"length": 96}, {"min_length": 40, "max_length": 200}):
            sender = fte.FTE(
                output_format=fte.RegexFormat(r"^[0-9a-f]+$", **fmt_kwargs), key=KEY
            )
            receiver = fte.FTE(
                output_format=fte.RegexFormat(r"^[0-9a-f]+$", **fmt_kwargs), key=KEY
            )
            self.assertEqual(
                receiver.decrypt(sender.encrypt(b"hello")), b"hello"
            )

    def test_insufficient_fixed_length_is_capacity_error(self):
        # length=8 is far too small for the authenticated frame, so building an
        # FTE around it fails fast.
        with self.assertRaises(fte.FormatCapacityError):
            fte.FTE(output_format=fte.RegexFormat(r"^[0-9a-f]+$", length=8), key=KEY)

    def test_fte_derives_capacity_ceiling_from_the_format(self):
        cipher = fte.FTE(
            output_format=fte.RegexFormat(r"^[0-9a-f]+$", length=96), key=KEY
        )
        limit = cipher.max_plaintext_bytes
        self.assertEqual(
            cipher.decrypt(cipher.encrypt(b"x" * limit)), b"x" * limit
        )
        with self.assertRaises(fte.FormatCapacityError):
            cipher.encrypt(b"x" * (limit + 1))


if __name__ == "__main__":
    unittest.main()
