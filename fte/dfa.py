#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""DFA ranking/unranking for FTE.

Implements the DFA (Deterministic Finite Automaton) ranking and unranking used
by FTE, in pure Python using Python's built-in arbitrary precision integers.

The algorithm is based on:
- "Compression and ranking" by Goldberg & Sipser
- "Protocol Misidentification Made Easy with Format-Transforming Encryption"
"""

import math
from typing import Dict, List, Set


class InvalidFSTFormat(Exception):
    """Raised when the AT&T FST input is malformed."""


class InvalidRankInput(Exception):
    """Raised when a string cannot be ranked in the language."""


class InvalidUnrankInput(Exception):
    """Raised when a rank is outside the valid range."""


class LanguageIsEmptySetException(Exception):
    """Raised when the language has no words of length ``fixed_slice``."""


class DFA:
    """Rank and unrank strings of a regular language.

    Parses a minimized AT&T FST, builds the Goldberg-Sipser counting table, and
    maps between strings of length ``fixed_slice`` and their lexicographic index
    via :meth:`rank` and :meth:`unrank`.

    Args:
        dfa_str: A minimized AT&T FST formatted DFA string.
        fixed_slice: The fixed string length for ranking/unranking.

    Attributes:
        capacity: Usable capacity in bits, ``floor(log2(N)) - 1`` where ``N`` is
            the number of words of length ``fixed_slice`` in the language.

    Raises:
        LanguageIsEmptySetException: If the language has no words of length
            ``fixed_slice``.
    """

    def __init__(self, dfa_str: str, fixed_slice: int):
        self._fixed_slice = fixed_slice
        self._start_state = 0
        self._states: List[int] = []
        self._symbols: List[int] = []
        self._final_states: Set[int] = set()
        self._sigma: Dict[int, int] = {}          # index -> symbol byte value
        self._sigma_reverse: Dict[int, int] = {}  # symbol byte value -> index
        self._delta: List[List[int]] = []         # transition table
        self._delta_dense: List[bool] = []        # all-transitions-equal flag
        self._T: List[List[int]] = []             # counting table

        self._parse_dfa(dfa_str)
        self._build_table()

        self._words_in_slice = self.num_words_in_language(fixed_slice, fixed_slice)
        if self._words_in_slice == 0:
            raise LanguageIsEmptySetException()
        self.capacity = int(math.floor(math.log(self._words_in_slice, 2))) - 1

    def _parse_dfa(self, dfa_str: str) -> None:
        """Parse the AT&T FST formatted DFA string."""
        states_set: Set[int] = set()
        symbols_set: Set[int] = set()
        transitions: List[tuple] = []
        start_state_set = False

        for line in dfa_str.split('\n'):
            line = line.strip()
            if not line:
                continue

            parts = line.split('\t')

            if len(parts) == 4:
                # Transition: src_state, dst_state, input_symbol, output_symbol
                src = int(parts[0])
                dst = int(parts[1])
                symbol = int(parts[2])

                states_set.add(src)
                states_set.add(dst)
                symbols_set.add(symbol)
                transitions.append((src, dst, symbol))

                if not start_state_set:
                    self._start_state = src
                    start_state_set = True

            elif len(parts) == 1:
                # Final state
                final = int(parts[0])
                self._final_states.add(final)
                states_set.add(final)
            elif len(parts) > 1:
                raise InvalidFSTFormat("Invalid FST format")

        if not states_set:
            raise InvalidFSTFormat("DFA has no states")
        if not symbols_set:
            raise InvalidFSTFormat("DFA has no symbols")

        # Sort for consistent ordering
        self._states = sorted(states_set)
        self._symbols = sorted(symbols_set)

        # Add dead state
        dead_state = len(self._states)
        self._states.append(dead_state)

        num_states = len(self._states)
        num_symbols = len(self._symbols)

        # Build sigma mappings (index <-> byte value)
        for idx, symbol in enumerate(self._symbols):
            self._sigma[idx] = symbol
            self._sigma_reverse[symbol] = idx

        # Initialize delta (transition table) to dead state
        self._delta = [[dead_state] * num_symbols for _ in range(num_states)]

        # Fill in transitions
        for src, dst, symbol in transitions:
            symbol_idx = self._sigma_reverse[symbol]
            self._delta[src][symbol_idx] = dst

        # Compute delta_dense optimization
        # A state is "dense" if all its transitions go to the same state
        self._delta_dense = []
        for q in range(num_states):
            if num_symbols > 0:
                first_dst = self._delta[q][0]
                is_dense = all(self._delta[q][a] == first_dst for a in range(num_symbols))
            else:
                is_dense = True
            self._delta_dense.append(is_dense)

    def _build_table(self) -> None:
        """Build T[q][i] = number of accepting paths of length i from state q."""
        num_states = len(self._states)

        # Initialize T to zeros
        self._T = [[0] * (self._fixed_slice + 1) for _ in range(num_states)]

        # Base case: T[q][0] = 1 if q is a final state
        prev_col = [0] * num_states
        for q in self._final_states:
            self._T[q][0] = 1
            prev_col[q] = 1

        # Collapse each state's transitions into (next_state, count) pairs and
        # split states by how many distinct destinations they have. Most states
        # send *every* symbol to a single destination (e.g. every letter in
        # ``[a-z]`` leads to the same next state), so those reduce to one
        # ``count * T[next_state]`` multiply -- replacing a run of identical
        # big-integer additions. Partitioning up front keeps that common
        # single-destination path free of any per-state branching.
        single = []   # (q, next_state, count)
        multi = []    # (q, [(next_state, count), ...])
        for q in range(num_states):
            counts: Dict[int, int] = {}
            for next_state in self._delta[q]:
                counts[next_state] = counts.get(next_state, 0) + 1
            if len(counts) == 1:
                (next_state, count), = counts.items()
                single.append((q, next_state, count))
            else:
                multi.append((q, list(counts.items())))

        # Fill the table column by column: T[q][i] = sum over symbols a of
        # T[delta[q][a]][i-1].
        T = self._T
        for i in range(1, self._fixed_slice + 1):
            cur_col = [0] * num_states
            for q, next_state, count in single:
                v = count * prev_col[next_state]
                cur_col[q] = v
                T[q][i] = v
            for q, items in multi:
                total = 0
                for next_state, count in items:
                    v = prev_col[next_state]
                    if v:
                        total += count * v if count > 1 else v
                cur_col[q] = total
                T[q][i] = total
            prev_col = cur_col

    def rank(self, X: bytes) -> int:
        """Return the lexicographic rank of string ``X`` in the language.

        Args:
            X: A bytes string of length ``fixed_slice``.

        Returns:
            The integer rank of ``X``.

        Raises:
            InvalidRankInput: If ``X`` has the wrong length or is not in the
                language.
        """
        if len(X) != self._fixed_slice:
            raise InvalidRankInput(
                f"Input length {len(X)} != fixed_slice {self._fixed_slice}"
            )

        q = self._start_state
        n = len(X)

        # Hoist attribute lookups out of the per-character loop.
        T = self._T
        delta = self._delta
        dense = self._delta_dense
        sigma_reverse = self._sigma_reverse

        # Collect each position's contribution, then sum them smallest-first.
        # Earlier positions carry far larger weights than later ones, so adding
        # them big-first (as a running ``c += ...`` does) forces every addition
        # to full width. Deferring the sum lets us add the small tail first and
        # keep the running total narrow for most of the additions. The inner
        # non-dense loop also accumulates into a small local before appending,
        # instead of repeatedly widening the grand total.
        terms = []
        append = terms.append

        for i in range(1, n + 1):
            byte_val = X[i - 1]

            symbol_idx = sigma_reverse.get(byte_val, -1)
            if symbol_idx < 0:
                raise InvalidRankInput(f"Symbol {byte_val} not in alphabet")

            delta_q = delta[q]
            col = n - i

            if dense[q]:
                # Optimized: all transitions from q go to same state
                if symbol_idx:
                    append(T[delta_q[0]][col] * symbol_idx)
            else:
                # Standard Goldberg-Sipser ranking
                s = 0
                for j in range(symbol_idx):
                    s += T[delta_q[j]][col]
                if s:
                    append(s)

            q = delta_q[symbol_idx]

        # Verify we ended in a final state
        if q not in self._final_states:
            raise InvalidRankInput("String does not end in accepting state")

        # ``terms`` runs from largest weight (position 1) to smallest; summing
        # the reversed sequence adds smallest-first.
        return sum(reversed(terms))

    def unrank(self, c: int) -> bytes:
        """Return the string at lexicographic rank ``c`` in the language.

        This is the inverse of :meth:`rank`.

        Args:
            c: The integer rank.

        Returns:
            The bytes string at rank ``c``.

        Raises:
            InvalidUnrankInput: If ``c`` is out of range.
        """
        words_in_slice = self._words_in_slice

        if c < 0 or c >= words_in_slice:
            raise InvalidUnrankInput(
                f"Rank {c} out of range [0, {words_in_slice})"
            )

        result = bytearray()
        q = self._start_state
        fixed_slice = self._fixed_slice

        # Hoist attribute lookups out of the per-character loop.
        T = self._T
        delta = self._delta
        dense = self._delta_dense
        sigma = self._sigma

        for i in range(1, fixed_slice + 1):
            delta_q = delta[q]
            col = fixed_slice - i

            if dense[q]:
                # Optimized: all transitions from q go to same state
                state = delta_q[0]
                divisor = T[state][col]
                if divisor:
                    # divmod computes quotient and remainder in one division.
                    char_idx, c = divmod(c, divisor)
                else:
                    char_idx = 0
            else:
                # Standard Goldberg-Sipser unranking
                char_idx = 0
                state = delta_q[0]
                threshold = T[state][col]
                while c >= threshold:
                    c -= threshold
                    char_idx += 1
                    state = delta_q[char_idx]
                    threshold = T[state][col]

            result.append(sigma[char_idx])
            # In both branches ``state`` is delta[q][char_idx], so it is the
            # next state regardless of density.
            q = state

        # Verify we ended in a final state
        if q not in self._final_states:
            raise InvalidUnrankInput("Unrank did not end in accepting state")

        return bytes(result)

    def num_words_in_language(self, min_len: int, max_len: int) -> int:
        """Return the number of words with length in ``[min_len, max_len]``.

        Args:
            min_len: Minimum word length (inclusive).
            max_len: Maximum word length (inclusive).

        Returns:
            The count of words in the specified length range.
        """
        assert 0 <= min_len <= max_len <= self._fixed_slice
        return sum(
            self._T[self._start_state][length]
            for length in range(min_len, max_len + 1)
        )
