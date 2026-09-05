#!/usr/bin/env python
"""Inspect format capacity and check whether a message fits."""

import fte

KEY = bytes(range(32))  # demonstration key; its value does not affect capacity


def analyze_format(name, pattern, length):
    fmt = fte.RegexFormat(pattern, length=length)
    capacity_bits = fmt.cardinality.bit_length() - 1  # floor(log2(cardinality))
    print(f"{name}: {length} covertext bytes, {capacity_bits} capacity bits")
    try:
        limit = fte.FTE(output_format=fmt, key=KEY).max_plaintext_bytes
        print(f"  Accepts up to {limit} plaintext bytes")
    except fte.FormatCapacityError:
        print("  Too small for even an empty authenticated message")


def main():
    for name, pattern, length in [
        ("Binary", r"^[01]+$", 256),
        ("Hex", r"^[0-9a-f]+$", 256),
        ("Lowercase", r"^[a-z]+$", 256),
        ("Alphanumeric", r"^[A-Za-z0-9]+$", 256),
        ("Printable ASCII", r"^[ -~]+$", 256),
    ]:
        analyze_format(name, pattern, length)

    plaintext = b"A" * 100
    for length in (128, 256):
        cipher = fte.FTE(
            output_format=fte.RegexFormat(r"^[0-9a-f]+$", length=length),
            key=KEY,
        )
        try:
            covertext = cipher.encrypt(plaintext)
        except fte.FormatCapacityError:
            print(f"{length} hex characters cannot hold {len(plaintext)} plaintext bytes")
        else:
            assert cipher.decrypt(covertext) == plaintext
            print(f"{length} hex characters hold {len(plaintext)} plaintext bytes")


if __name__ == "__main__":
    main()
