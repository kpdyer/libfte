#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Variable-length covertext.

Pass a ``min_length``/``max_length`` range instead of a fixed ``length`` and
the covertext length varies with the message, staying within the range. The
words are ordered by length, then lexicographically within a length.
"""

import os

import fte


def main():
    print("=== Variable-Length Covertext ===\n")

    # Lowercase covertext somewhere between 40 and 400 bytes long.
    cipher = fte.FTE(
        format=fte.RegexFormat('^[a-z]+$', min_length=40, max_length=400),
        key=os.urandom(32),
    )

    for plaintext in (b'hi', b'a slightly longer secret', os.urandom(64)):
        covertext = cipher.encrypt(plaintext)
        print(f"  {len(plaintext):>3}-byte message -> "
              f"{len(covertext):>3}-byte covertext")
        assert 40 <= len(covertext) <= 400
        assert cipher.decrypt(covertext) == plaintext

    print("\nLarger messages produce longer covertext, all within [40, 400].")


if __name__ == '__main__':
    main()
