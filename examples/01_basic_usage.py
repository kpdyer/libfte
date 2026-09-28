#!/usr/bin/env python
"""Encrypt between two endpoints that share a key, and reject a wrong key.

Every covertext of a fixed-length format has the same length, so a stream of
them needs no delimiter: the receiver splits it into equal chunks.
"""

import os

import fte


def main():
    key = os.urandom(32)  # securely share this key with the receiving endpoint
    fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=128)
    sender = fte.FTE(output_format=fmt, key=key)
    receiver = fte.FTE(output_format=fmt, key=key)

    messages = [b"Hello, World!", b"Second message", b"Third message"]
    stream = b"".join(sender.encrypt(message) for message in messages)
    print(f"Stream of {len(stream)} bytes: {stream[:48].decode()}...")

    recovered = [
        receiver.decrypt(stream[offset:offset + fmt.max_length])
        for offset in range(0, len(stream), fmt.max_length)
    ]
    assert recovered == messages
    for message in recovered:
        print(f"Recovered: {message}")

    wrong_key = fte.FTE(output_format=fmt, key=os.urandom(32))
    try:
        wrong_key.decrypt(stream[:fmt.max_length])
    except fte.InvalidCovertextError:
        print("A different key fails authentication.")
    else:
        raise AssertionError("wrong key was accepted")


if __name__ == "__main__":
    main()
