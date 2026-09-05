#!/usr/bin/env python
"""Parse concatenated fixed-length covertexts one message at a time."""

import os

import fte


def main():
    length = 128
    cipher = fte.FTE(
        output_format=fte.RegexFormat(r"^[a-z]+$", length=length),
        key=os.urandom(32),
    )
    messages = [b"First message", b"Second message", b"Third message"]
    stream = b"".join(cipher.encrypt(message) for message in messages)

    # Fixed-length covertexts need no additional delimiter in this stream.
    recovered = [
        cipher.decrypt(stream[offset:offset + length])
        for offset in range(0, len(stream), length)
    ]
    assert recovered == messages
    print(f"Recovered {len(recovered)} messages from {len(stream)} bytes:")
    for message in recovered:
        print(message)


if __name__ == "__main__":
    main()
