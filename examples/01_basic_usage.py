#!/usr/bin/env python
"""Encrypt between two endpoints sharing a key, and reject a wrong key."""

import os

import fte


def main():
    key = os.urandom(32)  # securely share this key with the receiving endpoint
    fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=87)
    sender = fte.FTE(output_format=fmt, key=key)
    receiver = fte.FTE(output_format=fmt, key=key)

    plaintext = b"Hello, World!"
    covertext = sender.encrypt(plaintext)
    recovered = receiver.decrypt(covertext)
    assert recovered == plaintext
    print(f"Plaintext: {plaintext}")
    print(f"Covertext: {covertext.decode()}")
    print(f"Recovered: {recovered}")

    wrong_key = fte.FTE(output_format=fmt, key=os.urandom(32))
    try:
        wrong_key.decrypt(covertext)
    except fte.InvalidCovertextError:
        print("A different key fails authentication.")
    else:
        raise AssertionError("wrong key was accepted")


if __name__ == "__main__":
    main()
