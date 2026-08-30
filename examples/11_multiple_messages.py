#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encrypting multiple messages.

Each covertext from a fixed-length RegexFormat is exactly ``length`` bytes, so
a stream of concatenated messages can be parsed back one fixed-size chunk at a
time.
"""

import os

import fte


def main():
    print("=== Multiple Messages ===\n")

    length = 128
    cipher = fte.FTE(
        format=fte.RegexFormat('^[a-z]+$', length=length),
        key=os.urandom(32),
    )

    # Encrypt multiple messages
    messages = [
        b'First message',
        b'Second message',
        b'Third message',
    ]

    print("Encrypting messages:")
    ciphertexts = []
    for i, msg in enumerate(messages):
        ct = cipher.encrypt(msg)
        ciphertexts.append(ct)
        print(f"  Message {i+1}: {msg}")
        print(f"    Ciphertext length: {len(ct)} bytes")

    # Concatenate all ciphertexts (simulating a stream)
    stream = b''.join(ciphertexts)
    print(f"\nConcatenated stream: {len(stream)} bytes")

    # Decrypt from the stream: every covertext is exactly `length` bytes.
    print("\nDecrypting from stream:")
    decrypted_messages = []
    for offset in range(0, len(stream), length):
        chunk = stream[offset:offset + length]
        plaintext = cipher.decrypt(chunk)
        decrypted_messages.append(plaintext)
        print(f"  Decrypted: {plaintext}")

    # Verify all messages recovered
    print("\nVerification:")
    for orig, recovered in zip(messages, decrypted_messages):
        match = "✓" if orig == recovered else "✗"
        print(f"  {match} {orig} == {recovered}")

    assert messages == decrypted_messages, "Message recovery failed!"
    print("\nAll messages recovered correctly!")


if __name__ == '__main__':
    main()
