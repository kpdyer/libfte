#!/usr/bin/env python
"""Choose a covertext format and check how much plaintext it holds.

The pattern and length decide what covertext looks like and how much it can
carry: authenticated encryption adds 29 bytes to every message, and a message
that does not fit raises FormatCapacityError. With min_length and max_length,
the covertext length grows with the message. Format membership does not
guarantee natural words or a uniform distribution over the format.
"""

import os

import fte


CONSONANTS = "bcdfghjklmnpqrstvwxyz"
VOWELS = "aeiou"

FORMATS = [
    ("Hex", fte.RegexFormat(r"^[0-9a-f]+$", length=128)),
    ("Alphanumeric", fte.RegexFormat(r"^[A-Za-z0-9]+$", length=64)),
    ("Consonant/vowel pairs",
     fte.RegexFormat(f"^([{CONSONANTS}][{VOWELS}])+$", length=128)),
    ("Lowercase, 40-400 bytes",
     fte.RegexFormat(r"^[a-z]+$", min_length=40, max_length=400)),
]


def main():
    key = os.urandom(32)  # 32-byte key, shared by both endpoints
    plaintext = b"Secret message"

    for name, fmt in FORMATS:
        cipher = fte.FTE(output_format=fmt, key=key)
        covertext = cipher.encrypt(plaintext)
        assert cipher.decrypt(covertext) == plaintext
        print(f"=== {name}: up to {cipher.max_plaintext_bytes} plaintext bytes")
        print(f"  {covertext.decode()}")

    print("\nA variable-length format grows the covertext with the message:")
    cipher = fte.FTE(output_format=FORMATS[-1][1], key=key)
    for size in (2, 24, 64):
        covertext = cipher.encrypt(os.urandom(size))
        print(f"  {size:>3}-byte message -> {len(covertext):>3}-byte covertext")

    cipher = fte.FTE(output_format=FORMATS[0][1], key=key)
    try:
        cipher.encrypt(b"A" * 100)
    except fte.FormatCapacityError:
        print("\n128 hex characters cannot hold 100 plaintext bytes.")
    else:
        raise AssertionError("an oversized message was accepted")


if __name__ == "__main__":
    main()
