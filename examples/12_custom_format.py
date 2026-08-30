#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Writing a custom format provider.

FTE's one extension point is the ranked format: any object with reversible
``rank()`` / ``unrank()`` methods. No inheritance or registration is needed,
just the same structural contract that ``fte.RegexFormat`` implements (see
``fte/formats/regex/``). Here we target decimal-digit strings.
"""

import os

import fte


class DecimalText:
    """Ranked format over canonical decimal strings: rank N <-> str(N)."""

    def rank(self, value: str, /) -> int:
        if not value.isascii() or not value.isdigit():
            raise ValueError("not canonical decimal text")
        if value != "0" and value.startswith("0"):
            raise ValueError("not canonical decimal text")
        return int(value)

    def unrank(self, index: int, /) -> str:
        if type(index) is not int or index < 0:
            raise ValueError("invalid rank")
        return str(index)


def main():
    print("=== Custom Format Provider ===\n")

    # Plug the provider into the same engine used for regex formats.
    cipher = fte.FTE(format=DecimalText(), key=os.urandom(32))

    plaintext = b'Quick and easy!'
    covertext = cipher.encrypt(plaintext)
    recovered = cipher.decrypt(covertext)

    print(f"Plaintext:  {plaintext}")
    print(f"Covertext:  {covertext}")   # a decimal-digit string
    print(f"Recovered:  {recovered}")

    assert covertext.isdigit()
    assert recovered == plaintext
    print("\nSuccess! The custom provider round-trips through fte.FTE.")


if __name__ == '__main__':
    main()
