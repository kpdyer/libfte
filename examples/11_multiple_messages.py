#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encoding multiple messages.

This example shows how to encode and decode multiple messages
in sequence, demonstrating the remainder handling.
"""

import fte


def main():
    print("=== Multiple Messages ===\n")
    
    encoder = fte.Encoder(regex='^[a-z]+$', fixed_slice=128)
    
    # Encode multiple messages
    messages = [
        b'First message',
        b'Second message',
        b'Third message',
    ]
    
    print("Encoding messages:")
    ciphertexts = []
    for i, msg in enumerate(messages):
        ct = encoder.encode(msg)
        ciphertexts.append(ct)
        print(f"  Message {i+1}: {msg}")
        print(f"    Ciphertext length: {len(ct)} bytes")
    
    # Concatenate all ciphertexts (simulating a stream)
    stream = b''.join(ciphertexts)
    print(f"\nConcatenated stream: {len(stream)} bytes")
    
    # Decode from stream
    print("\nDecoding from stream:")
    buffer = stream
    decoded_messages = []
    
    while len(buffer) >= 128:
        plaintext, remainder = encoder.decode(buffer)
        decoded_messages.append(plaintext)
        print(f"  Decoded: {plaintext}")
        print(f"    Remainder: {len(remainder)} bytes")
        buffer = remainder
    
    if buffer:
        print(f"\nLeftover buffer: {len(buffer)} bytes")
    
    # Verify all messages recovered
    print("\nVerification:")
    for orig, recovered in zip(messages, decoded_messages):
        match = "✓" if orig == recovered else "✗"
        print(f"  {match} {orig} == {recovered}")
    
    assert messages == decoded_messages, "Message recovery failed!"
    print("\nAll messages recovered correctly!")


if __name__ == '__main__':
    main()
