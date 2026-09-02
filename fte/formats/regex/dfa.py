#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""DFA ranking/unranking for FTE.

Implements the DFA (Deterministic Finite Automaton) ranking and unranking used
by FTE, in pure Python using Python's built-in arbitrary precision integers.

The algorithm is based on:
- "Compression and ranking" by Goldberg & Sipser
- "Protocol Misidentification Made Easy with Format-Transforming Encryption"
"""

from itertools import groupby
from typing import (
    Dict, FrozenSet, List, NamedTuple, Optional, Set, Tuple, Union,
)

__all__ = [
    "DFA",
    "ParsedFst",
    "parse_att_fst",
    "InvalidFSTFormat",
    "InvalidRankInput",
    "InvalidUnrankInput",
]

# A non-dense state takes the run-grouped rank/unrank path only when its
# transitions collapse into at most ``1 / _RUN_PATH_DIVISOR`` as many runs as
# there are alphabet symbols. Each run costs roughly twice what one symbol
# costs in the per-symbol walk (tuple unpack, bound check, multiply), so the
# grouping only pays off when it removes most of the iterations; at ratios
# near one (2-symbol alphabets, states whose neighbours all differ) the plain
# per-symbol walk stays ahead. Measured break-even: rank at a runs/symbols
# ratio of about 0.4, unrank at about 0.9; one third keeps both ahead.
_RUN_PATH_DIVISOR = 3


class InvalidFSTFormat(Exception):
    """Raised when the AT&T FST input is malformed."""


class InvalidRankInput(Exception):
    """Raised when a string cannot be ranked in the language."""


class InvalidUnrankInput(Exception):
    """Raised when a rank is outside the valid range."""


class ParsedFst(NamedTuple):
    """A parsed automaton: the DFA structure without any ranking tables.

    Attributes:
        start_state: The automaton's start state.
        final_states: The accepting states.
        transitions: (src_state, dst_state, symbol) triples.
        symbols: The alphabet, in lexicographic (ranking) order.
    """

    start_state: int
    final_states: FrozenSet[int]
    transitions: Tuple[Tuple[int, int, int], ...]
    symbols: Tuple[int, ...]


def parse_att_fst(dfa_str: str) -> ParsedFst:
    """Parse a minimized AT&T FST formatted DFA string.

    Args:
        dfa_str: A minimized AT&T FST formatted DFA string.

    Returns:
        The parsed automaton as a :class:`ParsedFst`.

    Raises:
        InvalidFSTFormat: If the input has a line that is neither a transition
            nor a final state, no states, no symbols, or states not numbered
            densely from zero.
    """
    states_set: Set[int] = set()
    symbols_set: Set[int] = set()
    final_states: Set[int] = set()
    transitions: List[Tuple[int, int, int]] = []
    start_state = 0
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
                start_state = src
                start_state_set = True

        elif len(parts) == 1:
            # Final state
            final = int(parts[0])
            final_states.add(final)
            states_set.add(final)
        elif len(parts) > 1:
            raise InvalidFSTFormat("Invalid FST format")

    if not states_set:
        raise InvalidFSTFormat("DFA has no states")
    if not symbols_set:
        raise InvalidFSTFormat("DFA has no symbols")

    # Sort for consistent ordering. The transition table is indexed by raw
    # state id, so states must be numbered densely from zero.
    states = sorted(states_set)
    if states != list(range(len(states))):
        raise InvalidFSTFormat("DFA states must be numbered 0..N-1")

    return ParsedFst(
        start_state=start_state,
        final_states=frozenset(final_states),
        transitions=tuple(transitions),
        symbols=tuple(sorted(symbols_set)),
    )


class DFA:
    """Rank and unrank the words of a regular language by length.

    Builds the Goldberg-Sipser counting table up to a maximum ``length`` from a
    minimized AT&T FST string (parsed via :func:`parse_att_fst`) or from a
    :class:`ParsedFst` supplied directly. :meth:`rank` and :meth:`unrank` then
    map between a word and its lexicographic index among the accepted words of
    that word's length, and :meth:`num_words` counts the accepted words of one
    length. Whether any words exist at the lengths the caller cares about is
    the caller's concern.

    Args:
        dfa_str: A minimized AT&T FST formatted DFA string, or a
            :class:`ParsedFst`.
        length: The maximum word length the counting table supports.

    Raises:
        InvalidFSTFormat: If the string does not parse (see
            :func:`parse_att_fst`) or the alphabet has a symbol outside the
            byte range 0..255.
    """

    def __init__(self, dfa_str: Union[str, ParsedFst], length: int):
        self._length = length
        if isinstance(dfa_str, ParsedFst):
            parsed = dfa_str
        else:
            parsed = parse_att_fst(dfa_str)
        self._start_state = parsed.start_state
        self._num_states = 0
        self._symbols: List[int] = list(parsed.symbols)
        self._final_states: Set[int] = set(parsed.final_states)
        self._sigma_reverse: Dict[int, int] = {}  # symbol byte value -> index
        self._symbol_index: List[int] = []        # byte value -> index or -1
        self._delta: List[List[int]] = []         # transition table
        self._delta_dense: List[bool] = []        # all-transitions-equal flag
        # Per state: runs of consecutive symbols sharing a destination, as
        # (next_state, first_symbol_idx, count) triples in symbol order, or
        # None when rank/unrank should walk that state symbol by symbol.
        self._runs: List[Optional[List[Tuple[int, int, int]]]] = []
        self._T: List[List[int]] = []             # counting table

        self._build_delta(parsed.transitions)
        self._build_table()

    def _build_delta(
        self, transitions: Tuple[Tuple[int, int, int], ...]
    ) -> None:
        """Build the transition table from the parsed transitions."""
        # One extra dead state absorbs missing transitions. State ids index
        # the table directly, so the dead state follows the highest real id.
        max_state = self._start_state
        for state in self._final_states:
            max_state = max(max_state, state)
        for src, dst, _ in transitions:
            max_state = max(max_state, src, dst)
        dead_state = max_state + 1
        self._num_states = dead_state + 1
        num_symbols = len(self._symbols)

        self._sigma_reverse = {
            symbol: idx for idx, symbol in enumerate(self._symbols)
        }
        # Same map as a 256-entry list so rank can index by byte value
        # instead of calling ``dict.get`` for every symbol. That fixes the
        # alphabet to byte values: a larger symbol would not fit the list and
        # a negative one would silently alias another entry.
        for symbol in self._symbols:
            if not 0 <= symbol <= 255:
                raise InvalidFSTFormat(
                    f"symbol {symbol} is outside the byte range 0..255"
                )
        self._symbol_index = [-1] * 256
        for symbol, idx in self._sigma_reverse.items():
            self._symbol_index[symbol] = idx

        # Initialize delta (transition table) to dead state
        self._delta = [
            [dead_state] * num_symbols for _ in range(self._num_states)
        ]

        # Fill in transitions
        for src, dst, symbol in transitions:
            symbol_idx = self._sigma_reverse[symbol]
            self._delta[src][symbol_idx] = dst

    def _build_table(self) -> None:
        """Build T[q][i] = number of accepting paths of length i from state q."""
        num_states = self._num_states

        # Initialize T to zeros
        self._T = [[0] * (self._length + 1) for _ in range(num_states)]

        # Base case: T[q][0] = 1 if q is a final state
        prev_col = [0] * num_states
        for q in self._final_states:
            self._T[q][0] = 1
            prev_col[q] = 1

        # Group each state's transitions into runs of consecutive symbols that
        # share a destination, collapse those into (next_state, count) pairs,
        # and split states by how many distinct destinations they have. Most
        # states send *every* symbol to a single destination (e.g. every
        # letter in ``[a-z]`` leads to the same next state), so those reduce
        # to one ``count * T[next_state]`` multiply, replacing a run of
        # identical big-integer additions. Partitioning up front keeps that
        # common single-destination path free of any per-state branching.
        # States with few runs relative to the alphabet (a literal or wildcard
        # in a 256-symbol alphabet) keep their run list so rank and unrank can
        # step over each run in one multiply; see ``_RUN_PATH_DIVISOR``.
        single = []   # (q, next_state, count)
        multi = []    # (q, [(next_state, count), ...])
        max_runs = len(self._symbols) // _RUN_PATH_DIVISOR
        self._delta_dense = [False] * num_states
        self._runs = [None] * num_states
        for q in range(num_states):
            row = self._delta[q]
            counts: Dict[int, int] = {}
            for next_state in row:
                counts[next_state] = counts.get(next_state, 0) + 1
            if len(counts) == 1:
                # A "dense" state sends every symbol to one destination; rank
                # and unrank use the flag to take their optimized branch.
                self._delta_dense[q] = True
                (next_state, count), = counts.items()
                single.append((q, next_state, count))
                continue
            multi.append((q, list(counts.items())))
            # A state has at least as many runs as destinations, so only
            # states that can pass the run threshold pay for the grouping.
            if len(counts) > max_runs:
                continue
            runs: List[Tuple[int, int, int]] = []
            start = 0
            for next_state, group in groupby(row):
                count = len(list(group))
                runs.append((next_state, start, count))
                start += count
            if len(runs) <= max_runs:
                self._runs[q] = runs

        # Fill the table column by column: T[q][i] = sum over symbols a of
        # T[delta[q][a]][i-1].
        T = self._T
        for i in range(1, self._length + 1):
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
        """Return the lexicographic rank of ``X`` among words of its own length.

        The rank is taken within the accepted words of length ``len(X)``; the
        caller composes a whole-language rank across lengths.

        Args:
            X: A bytes string no longer than the built ``length``.

        Returns:
            The integer rank of ``X`` among accepted words of length ``len(X)``.

        Raises:
            InvalidRankInput: If ``X`` is not bytes, is longer than ``length``,
                or is not in the language.
        """
        if not isinstance(X, (bytes, bytearray)):
            raise InvalidRankInput(
                f"Input must be bytes, not {type(X).__name__}"
            )
        if len(X) > self._length:
            raise InvalidRankInput(
                f"Input length {len(X)} exceeds built length {self._length}"
            )

        q = self._start_state
        n = len(X)

        # Hoist attribute lookups out of the per-character loop.
        T = self._T
        delta = self._delta
        dense = self._delta_dense
        runs = self._runs
        symbol_index = self._symbol_index

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

            symbol_idx = symbol_index[byte_val]
            if symbol_idx < 0:
                raise InvalidRankInput(f"Symbol {byte_val} not in alphabet")

            delta_q = delta[q]
            col = n - i

            if dense[q]:
                # Optimized: all transitions from q go to same state
                if symbol_idx:
                    append(T[delta_q[0]][col] * symbol_idx)
            elif runs[q] is None:
                # Standard Goldberg-Sipser ranking
                s = 0
                for j in range(symbol_idx):
                    s += T[delta_q[j]][col]
                if s:
                    append(s)
            else:
                # Run-grouped ranking: every symbol in a run leads to the same
                # state, so a whole run below ``symbol_idx`` contributes
                # ``count * T[next_state][col]`` in one multiply, and the run
                # containing ``symbol_idx`` contributes its prefix.
                s = 0
                for next_state, start, count in runs[q]:
                    if start + count <= symbol_idx:
                        v = T[next_state][col]
                        if v:
                            s += count * v if count > 1 else v
                    else:
                        k = symbol_idx - start
                        if k:
                            s += k * T[next_state][col]
                        break
                if s:
                    append(s)

            q = delta_q[symbol_idx]

        # Verify we ended in a final state
        if q not in self._final_states:
            raise InvalidRankInput("String does not end in accepting state")

        # ``terms`` runs from largest weight (position 1) to smallest; summing
        # the reversed sequence adds smallest-first.
        return sum(reversed(terms))

    def unrank(self, c: int, length: int) -> bytes:
        """Return the word of the given ``length`` at rank ``c``.

        Inverse of :meth:`rank` for words of exactly ``length`` bytes.

        Args:
            c: The integer rank among accepted words of ``length`` bytes.
            length: The word length to produce (0 <= length <= built length).

        Returns:
            The bytes string at rank ``c`` among words of ``length`` bytes.

        Raises:
            InvalidUnrankInput: If ``c`` is out of range for that length.
        """
        if not 0 <= length <= self._length:
            raise InvalidUnrankInput(
                f"length {length} outside [0, {self._length}]"
            )

        num_words = self._T[self._start_state][length]
        if c < 0 or c >= num_words:
            raise InvalidUnrankInput(
                f"Rank {c} out of range [0, {num_words}) for length {length}"
            )

        result = bytearray()
        append = result.append
        q = self._start_state

        # Hoist attribute lookups out of the per-character loop.
        T = self._T
        delta = self._delta
        dense = self._delta_dense
        runs = self._runs
        symbols = self._symbols

        # Position i of the word draws on column length - i of the table.
        for col in range(length - 1, -1, -1):
            delta_q = delta[q]

            if dense[q]:
                # Optimized: all transitions from q go to same state
                state = delta_q[0]
                divisor = T[state][col]
                if divisor:
                    # divmod computes quotient and remainder in one division.
                    char_idx, c = divmod(c, divisor)
                else:
                    char_idx = 0
            elif runs[q] is None:
                # Standard Goldberg-Sipser unranking
                char_idx = 0
                state = delta_q[0]
                threshold = T[state][col]
                while c >= threshold:
                    c -= threshold
                    char_idx += 1
                    state = delta_q[char_idx]
                    threshold = T[state][col]
            else:
                # Run-grouped unranking: skip whole runs whose block of
                # ``count`` equal thresholds lies below ``c``, then locate the
                # symbol inside the absorbing run with a single divmod.
                for state, start, count in runs[q]:
                    threshold = T[state][col]
                    if not threshold:
                        continue
                    block = count * threshold if count > 1 else threshold
                    if c >= block:
                        c -= block
                        continue
                    if count > 1:
                        k, c = divmod(c, threshold)
                        char_idx = start + k
                    else:
                        char_idx = start
                    break
                else:
                    # Unreachable: the range check above guarantees that the
                    # blocks of some run absorb ``c``.
                    raise InvalidUnrankInput("Rank not absorbed by any run")

            append(symbols[char_idx])
            # In every branch ``state`` is delta[q][char_idx], so it is the
            # next state regardless of which walk produced it.
            q = state

        # Verify we ended in a final state
        if q not in self._final_states:
            raise InvalidUnrankInput("Unrank did not end in accepting state")

        return bytes(result)

    def num_words(self, length: int) -> int:
        """Return the number of accepted words of exactly ``length`` bytes.

        Args:
            length: The word length to count (0 <= length <= built length).

        Returns:
            The count of accepted words of that length.
        """
        assert 0 <= length <= self._length
        return self._T[self._start_state][length]
