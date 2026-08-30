"""Direct tests for the DFA ranker under RegexFormat.

RegexFormat exercises the DFA end to end, but the ranker also has its own
contract (per-length rank/unrank, counting, and input validation) worth testing
directly.
"""

import unittest

import regex2dfa

from fte.formats.regex.dfa import (
    DFA,
    InvalidFSTFormat,
    InvalidRankInput,
    InvalidUnrankInput,
)


def build(pattern, length):
    return DFA(regex2dfa.regex2dfa(pattern), length)


class Tests(unittest.TestCase):
    def test_counts_and_per_length_roundtrip(self):
        dfa = build(r"^[01]+$", 8)
        for length in range(1, 9):
            count = dfa.num_words(length)
            self.assertEqual(count, 2 ** length)
            for index in (0, count // 2, count - 1):
                word = dfa.unrank(index, length)
                self.assertEqual(len(word), length)
                self.assertEqual(dfa.rank(word), index)

    def test_num_words_counts_one_length(self):
        # ^[01]+$ has no empty word, so length zero counts zero.
        dfa = build(r"^[01]+$", 6)
        self.assertEqual(dfa.num_words(0), 0)
        for length in range(1, 7):
            self.assertEqual(dfa.num_words(length), 2 ** length)

    def test_unrank_rejects_out_of_range_rank(self):
        dfa = build(r"^[01]+$", 4)
        count = dfa.num_words(4)
        with self.assertRaises(InvalidUnrankInput):
            dfa.unrank(-1, 4)
        with self.assertRaises(InvalidUnrankInput):
            dfa.unrank(count, 4)

    def test_unrank_rejects_out_of_range_length(self):
        dfa = build(r"^[01]+$", 4)
        with self.assertRaises(InvalidUnrankInput):
            dfa.unrank(0, 5)   # beyond the built length
        with self.assertRaises(InvalidUnrankInput):
            dfa.unrank(0, -1)

    def test_rank_rejects_length_beyond_table(self):
        dfa = build(r"^[01]+$", 4)
        with self.assertRaises(InvalidRankInput):
            dfa.rank(b"01010")  # length 5 > built length 4

    def test_rank_rejects_symbol_outside_alphabet(self):
        dfa = build(r"^[01]+$", 4)
        with self.assertRaises(InvalidRankInput):
            dfa.rank(b"01\xff1")  # 0xff is not in the {0, 1} alphabet

    def test_rank_rejects_non_accepting_word(self):
        # ``^(0|1)[a-z]+$``: a leading digit must be followed by letters. A
        # second digit walks to a non-accepting (dead) state.
        dfa = build(r"^(0|1)[a-z]+$", 4)
        with self.assertRaises(InvalidRankInput):
            dfa.rank(b"0000")

    def test_malformed_fst_is_rejected(self):
        with self.assertRaises(InvalidFSTFormat):
            DFA("", 4)                 # no states
        with self.assertRaises(InvalidFSTFormat):
            DFA("0", 4)                # a final state but no transitions/symbols
        with self.assertRaises(InvalidFSTFormat):
            DFA("0\t1\t2", 4)          # a 3-field line is neither transition nor final


if __name__ == "__main__":
    unittest.main()
