#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Performance comparison between pure Python and native.

This example benchmarks encoding/decoding performance and shows
how to check which implementation is being used.
"""

import time
import fte
from fte.dfa import using_native


def benchmark(encoder, plaintext, iterations=100):
    """Benchmark encode/decode operations."""
    # Warmup
    ct = encoder.encode(plaintext)
    encoder.decode(ct)
    
    # Benchmark encode
    start = time.perf_counter()
    for _ in range(iterations):
        ct = encoder.encode(plaintext)
    encode_time = (time.perf_counter() - start) / iterations * 1000
    
    # Benchmark decode
    start = time.perf_counter()
    for _ in range(iterations):
        encoder.decode(ct)
    decode_time = (time.perf_counter() - start) / iterations * 1000
    
    return encode_time, decode_time


def main():
    print("=== Performance Comparison ===")
    print(f"\nCurrent implementation: {'Native (C++/GMP)' if using_native() else 'Pure Python'}")
    print("\nTo switch implementations:")
    print("  Pure Python (default): unset FTE_USE_NATIVE")
    print("  Native: export FTE_USE_NATIVE=1")
    
    # Setup
    encoder = fte.Encoder(regex='^[a-z]+$', fixed_slice=256)
    
    print(f"\nBenchmark settings:")
    print(f"  Regex: ^[a-z]+$")
    print(f"  Fixed slice: 256")
    
    # Test with different message sizes
    sizes = [10, 50, 100]
    
    print(f"\n{'Message Size':<15} {'Encode (ms)':<15} {'Decode (ms)':<15}")
    print("-" * 45)
    
    for size in sizes:
        plaintext = b'A' * size
        encode_ms, decode_ms = benchmark(encoder, plaintext, iterations=50)
        print(f"{size} bytes{'':<9} {encode_ms:<15.3f} {decode_ms:<15.3f}")
    
    print("\n" + "=" * 45)
    print("\nTypical performance:")
    print("  Pure Python: ~5-15ms per operation")
    print("  Native (C++): ~1-3ms per operation")
    print("\nNative is typically 3-5x faster.")


if __name__ == '__main__':
    main()
