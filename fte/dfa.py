#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""DFA wrapper module for FTE.

This module provides a wrapper around the DFA implementation,
handling ranking and unranking operations on regular languages.

By default, it uses a pure Python implementation. If the C++ extension
is available and FTE_USE_NATIVE=1 is set, it will use the faster
C++ implementation.
"""

import math
import os

# Try to import C++ extension, fall back to pure Python
_USE_NATIVE = os.environ.get('FTE_USE_NATIVE', '0') == '1'
_NATIVE_AVAILABLE = False

if _USE_NATIVE:
    try:
        import fte.cDFA as _cDFA_module
        _NATIVE_AVAILABLE = True
    except ImportError:
        _NATIVE_AVAILABLE = False

# Always import pure Python as fallback
import fte.cDFA_py as _cDFA_py


def using_native() -> bool:
    """Check if the native C++ extension is being used.
    
    Returns:
        True if using C++ extension, False if using pure Python.
    """
    return _USE_NATIVE and _NATIVE_AVAILABLE


class LanguageIsEmptySetException(Exception):
    """Raised when the input language has no words of the specified length."""
    pass


class IntegerOutOfRangeException(Exception):
    """Raised when an integer is outside the valid range for ranking."""
    pass


class InvalidRegexParametersException(Exception):
    """Raised when regex parameters are invalid."""
    pass


class DFA:
    """DFA wrapper for ranking/unranking implementation.
    
    Uses pure Python by default. Set environment variable FTE_USE_NATIVE=1
    to use the C++ extension for better performance (requires GMP library).
    
    Args:
        cDFA: A DFA object (either C++ or Python implementation).
        fixed_slice: The fixed length for ranking/unranking operations.
        
    Raises:
        LanguageIsEmptySetException: If no words of length fixed_slice
            exist in the language.
    """

    def __init__(self, cDFA, fixed_slice: int):
        self._cDFA = cDFA
        self.fixed_slice = fixed_slice

        self._words_in_language = self._cDFA.getNumWordsInLanguage(
            0, self.fixed_slice
        )
        self._words_in_slice = self._cDFA.getNumWordsInLanguage(
            self.fixed_slice, self.fixed_slice
        )

        self._offset = self._words_in_language - self._words_in_slice

        if self._words_in_slice == 0:
            raise LanguageIsEmptySetException()

        self._capacity = int(math.floor(math.log(self._words_in_slice, 2))) - 1

    def rank(self, X: bytes) -> int:
        """Get the lexicographical rank of a string in the language.
        
        Args:
            X: A bytes string of length fixed_slice that is in the language.
            
        Returns:
            The integer rank of X (0-indexed position in lexicographic order).
        """
        return self._cDFA.rank(X)

    def unrank(self, c: int) -> bytes:
        """Get the string at the given rank in the language.
        
        This is the inverse of rank().
        
        Args:
            c: An integer rank.
            
        Returns:
            The bytes string at rank c in the language.
        """
        return self._cDFA.unrank(c)

    def getCapacity(self) -> int:
        """Get the capacity of the language in bits.
        
        Returns:
            floor(log2(number of words of length fixed_slice)) - 1
        """
        return self._capacity

    def getNumWordsInSlice(self, n: int) -> int:
        """Get the number of words of exactly length n in the language.
        
        Args:
            n: The word length.
            
        Returns:
            The count of words of length n.
        """
        return self._cDFA.getNumWordsInLanguage(n, n)


def create_dfa(dfa_str: str, fixed_slice: int):
    """Create a DFA object using the appropriate backend.
    
    Args:
        dfa_str: The DFA specification in AT&T FST format.
        fixed_slice: The fixed length for encoded strings.
        
    Returns:
        A DFA implementation object (C++ or Python).
    """
    if using_native():
        return _cDFA_module.DFA(dfa_str, fixed_slice)
    else:
        return _cDFA_py.DFA(dfa_str, fixed_slice)
