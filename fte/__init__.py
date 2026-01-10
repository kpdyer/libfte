"""FTE - Format-Transforming Encryption library.

This library implements Format-Transforming Encryption (FTE), a cryptographic
primitive that allows encoding ciphertexts as strings matching a specified
regular language.

Example usage:
    >>> import fte
    >>> 
    >>> encoder = fte.Encoder('^[a-z]+$', 128)
    >>> ciphertext = encoder.encode(b'secret message')
    >>> plaintext, _ = encoder.decode(ciphertext)
    >>> 
    >>> assert plaintext == b'secret message'

See the paper "Protocol Misidentification Made Easy with Format-Transforming
Encryption" for details: https://kpdyer.com/publications/ccs2013-fte.pdf
"""

from pathlib import Path
from typing import Optional, Tuple

import regex2dfa

from fte.encoder import DfaEncoder
from fte.encrypter import Encrypter

__version__ = (Path(__file__).parent / '_version.txt').read_text().strip()
__author__ = 'Kevin P. Dyer'
__email__ = 'kpdyer@gmail.com'

__all__ = ['Encoder', 'DfaEncoder', 'Encrypter', 'encode', 'decode']


class Encoder:
    """Format-Transforming Encryption encoder.
    
    This is the main interface for FTE. It encrypts data and formats the
    ciphertext to match a specified regular expression.
    
    Args:
        regex: A regular expression defining the output format.
            Examples: '^[a-z]+$', '^[0-9a-f]+$', '^[A-Za-z0-9]+$'
        fixed_slice: Length of the formatted output string.
        key: Optional 32-byte key (16 bytes encryption + 16 bytes MAC).
            If not provided, random keys are generated.
    
    Example:
        >>> encoder = fte.Encoder('^[0-9a-f]+$', 128)
        >>> ciphertext = encoder.encode(b'secret')
        >>> plaintext, _ = encoder.decode(ciphertext)
    """
    
    def __init__(
        self,
        regex: str,
        fixed_slice: int,
        key: Optional[bytes] = None
    ):
        self.regex = regex
        self.fixed_slice = fixed_slice
        
        # Convert regex to DFA
        dfa = regex2dfa.regex2dfa(regex)
        
        # Split key into K1 (encryption) and K2 (MAC) if provided
        if key is not None:
            if len(key) != 32:
                raise ValueError("Key must be exactly 32 bytes (16 for encryption + 16 for MAC)")
            K1, K2 = key[:16], key[16:]
        else:
            K1, K2 = None, None
        
        self._encoder = DfaEncoder(dfa, fixed_slice, K1=K1, K2=K2)
    
    def encode(self, plaintext: bytes, seed: Optional[bytes] = None) -> bytes:
        """Encrypt and encode plaintext to match the regex format.
        
        Args:
            plaintext: The data to encrypt.
            seed: Optional 8-byte seed for deterministic output.
        
        Returns:
            Ciphertext formatted to match the regex.
        """
        return self._encoder.encode(plaintext, seed=seed)
    
    def decode(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        """Decode and decrypt ciphertext.
        
        Args:
            ciphertext: The formatted ciphertext to decrypt.
        
        Returns:
            A tuple of (plaintext, remainder) where remainder is any
            extra data after the decoded message.
        """
        return self._encoder.decode(ciphertext)
    
    @property
    def capacity(self) -> int:
        """Get the capacity in bits."""
        return self._encoder.getCapacity()


# Convenience functions for one-shot encoding/decoding
_encoders = {}


def encode(
    plaintext: bytes,
    regex: str = '^[a-z]+$',
    fixed_slice: int = 256,
    key: Optional[bytes] = None
) -> bytes:
    """Encode plaintext using FTE (convenience function).
    
    Args:
        plaintext: The data to encrypt.
        regex: Output format as a regular expression.
        fixed_slice: Length of formatted output.
        key: Optional 32-byte key.
    
    Returns:
        Ciphertext formatted to match the regex.
    
    Example:
        >>> ciphertext = fte.encode(b'secret', regex='^[0-9a-f]+$')
    """
    cache_key = (regex, fixed_slice, key)
    if cache_key not in _encoders:
        _encoders[cache_key] = Encoder(regex, fixed_slice, key)
    return _encoders[cache_key].encode(plaintext)


def decode(
    ciphertext: bytes,
    regex: str = '^[a-z]+$',
    fixed_slice: int = 256,
    key: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Decode ciphertext using FTE (convenience function).
    
    Args:
        ciphertext: The formatted ciphertext.
        regex: The regex used for encoding (must match).
        fixed_slice: The fixed_slice used for encoding (must match).
        key: The key used for encoding (must match).
    
    Returns:
        A tuple of (plaintext, remainder).
    
    Example:
        >>> plaintext, _ = fte.decode(ciphertext, regex='^[0-9a-f]+$')
    """
    cache_key = (regex, fixed_slice, key)
    if cache_key not in _encoders:
        _encoders[cache_key] = Encoder(regex, fixed_slice, key)
    return _encoders[cache_key].decode(ciphertext)
