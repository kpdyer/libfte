#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encrypting multiple messages.

This example shows how to encrypt and decrypt multiple messages
in sequence, demonstrating the remainder handling.
"""

import os

import fte


def main():
    print("=== Multiple Messages ===\n")

    cipher = fte.Encoder(regex='^[a-z]+$', fixed_slice=128, key=os.urandom(32))
    
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
    
    # Decrypt from stream
    print("\nDecrypting from stream:")
    buffer = stream
    decrypted_messages = []
    
    while len(buffer) >= 128:
        plaintext, remainder = cipher.decrypt(buffer)
        decrypted_messages.append(plaintext)
        print(f"  Decrypted: {plaintext}")
        print(f"    Remainder: {len(remainder)} bytes")
        buffer = remainder
    
    if buffer:
        print(f"\nLeftover buffer: {len(buffer)} bytes")
    
    # Verify all messages recovered
    print("\nVerification:")
    for orig, recovered in zip(messages, decrypted_messages):
        match = "✓" if orig == recovered else "✗"
        print(f"  {match} {orig} == {recovered}")
    
    assert messages == decrypted_messages, "Message recovery failed!"
    print("\nAll messages recovered correctly!")


if __name__ == '__main__':
    main()
