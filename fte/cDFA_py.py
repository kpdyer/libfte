#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Pure Python implementation of DFA ranking/unranking.

This module provides a pure Python fallback for the C++ extension,
implementing the same ranking/unranking algorithm using Python's
native arbitrary precision integers.

The algorithm is based on:
- "Compression and ranking" by Goldberg & Sipser
- "Protocol Misidentification Made Easy with Format-Transforming Encryption"
"""

from typing import Dict, List, Set


class InvalidFSTFormat(Exception):
    """Raised when the FST format is invalid."""
    pass


class InvalidRankInput(Exception):
    """Raised when rank input is invalid."""
    pass


class InvalidUnrankInput(Exception):
    """Raised when unrank input is invalid."""
    pass


class DFA:
    """Pure Python DFA implementation for ranking/unranking.
    
    This class parses an AT&T FST formatted DFA and provides
    rank/unrank operations for strings in the language.
    
    Args:
        dfa_str: A minimized AT&T FST formatted DFA string.
        max_len: The maximum string length for ranking operations.
    """
    
    def __init__(self, dfa_str: str, max_len: int):
        self._fixed_slice = max_len
        self._start_state = 0
        self._states: List[int] = []
        self._symbols: List[int] = []
        self._final_states: Set[int] = set()
        self._sigma: Dict[int, int] = {}  # index -> symbol byte value
        self._sigma_reverse: Dict[int, int] = {}  # symbol byte value -> index
        self._delta: List[List[int]] = []  # transition table
        self._delta_dense: List[bool] = []  # optimization flag
        self._T: List[List[int]] = []  # counting table
        
        self._parse_dfa(dfa_str)
        self._build_table()
    
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
        """Build the counting table T[q][i] = number of accepting paths of length i from state q."""
        num_states = len(self._states)
        num_symbols = len(self._symbols)
        
        # Initialize T to zeros
        self._T = [[0] * (self._fixed_slice + 1) for _ in range(num_states)]
        
        # Base case: T[q][0] = 1 if q is a final state
        for q in self._final_states:
            self._T[q][0] = 1
        
        # Fill table: T[q][i] = sum over all symbols a of T[delta[q][a]][i-1]
        for i in range(1, self._fixed_slice + 1):
            for q in range(len(self._delta)):
                for a in range(num_symbols):
                    next_state = self._delta[q][a]
                    self._T[q][i] += self._T[next_state][i - 1]
    
    def rank(self, X: bytes) -> int:
        """Compute the lexicographic rank of string X in the language.
        
        Args:
            X: A bytes string of length fixed_slice.
            
        Returns:
            The integer rank of X.
            
        Raises:
            InvalidRankInput: If X has wrong length or is not in the language.
        """
        if len(X) != self._fixed_slice:
            raise InvalidRankInput(
                f"Input length {len(X)} != fixed_slice {self._fixed_slice}"
            )
        
        c = 0
        q = self._start_state
        n = len(X)
        
        for i in range(1, n + 1):
            byte_val = X[i - 1]
            
            if byte_val not in self._sigma_reverse:
                raise InvalidRankInput(f"Symbol {byte_val} not in alphabet")
            
            symbol_idx = self._sigma_reverse[byte_val]
            
            if self._delta_dense[q]:
                # Optimized: all transitions from q go to same state
                state = self._delta[q][0]
                c += self._T[state][n - i] * symbol_idx
            else:
                # Standard Goldberg-Sipser ranking
                for j in range(symbol_idx):
                    state = self._delta[q][j]
                    c += self._T[state][n - i]
            
            q = self._delta[q][symbol_idx]
        
        # Verify we ended in a final state
        if q not in self._final_states:
            raise InvalidRankInput("String does not end in accepting state")
        
        return c
    
    def unrank(self, c: int) -> bytes:
        """Compute the string at lexicographic rank c in the language.
        
        Args:
            c: The integer rank.
            
        Returns:
            The bytes string at rank c.
            
        Raises:
            InvalidUnrankInput: If c is out of range.
        """
        words_in_slice = self.getNumWordsInLanguage(self._fixed_slice, self._fixed_slice)
        
        if c < 0 or c >= words_in_slice:
            raise InvalidUnrankInput(
                f"Rank {c} out of range [0, {words_in_slice})"
            )
        
        result = bytearray()
        q = self._start_state
        
        for i in range(1, self._fixed_slice + 1):
            if self._delta_dense[q]:
                # Optimized: all transitions from q go to same state
                state = self._delta[q][0]
                divisor = self._T[state][self._fixed_slice - i]
                if divisor > 0:
                    char_idx = c // divisor
                    c = c % divisor
                else:
                    char_idx = 0
            else:
                # Standard Goldberg-Sipser unranking
                char_idx = 0
                state = self._delta[q][char_idx]
                
                while c >= self._T[state][self._fixed_slice - i]:
                    c -= self._T[state][self._fixed_slice - i]
                    char_idx += 1
                    state = self._delta[q][char_idx]
            
            result.append(self._sigma[char_idx])
            q = self._delta[q][char_idx] if not self._delta_dense[q] else state
        
        # Verify we ended in a final state
        if q not in self._final_states:
            raise InvalidUnrankInput("Unrank did not end in accepting state")
        
        return bytes(result)
    
    def getNumWordsInLanguage(self, min_len: int, max_len: int) -> int:
        """Get the number of words in the language within a length range.
        
        Args:
            min_len: Minimum word length (inclusive).
            max_len: Maximum word length (inclusive).
            
        Returns:
            The count of words in the specified length range.
        """
        assert 0 <= min_len <= max_len <= self._fixed_slice
        
        count = 0
        for length in range(min_len, max_len + 1):
            count += self._T[self._start_state][length]
        return count
