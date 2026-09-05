#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Benchmark suite for libfte (Format-Transforming Encryption).

libfte's ranking engine is pure Python, and this script measures the two costs that matter
when you use it:

  1. Cipher construction:  the one-time cost of compiling a regex into a
     DFA and pre-computing the ranking tables. Paid once per (regex, length).
  2. encrypt() / decrypt(): the steady-state cost paid per message. This is
     dominated by the DFA rank/unrank on large integers, so it grows with the
     covertext ``length`` (the DFA walk) and with the plaintext size (the
     magnitude of the integer being ranked): a payload that fills the format's
     capacity can cost several times (up to ~10x) more than a short one.

To show both ends of that range, every format is timed with a short 18-byte
payload and with a full-capacity payload (``cipher.max_plaintext_bytes``).
It runs across a range of output formats (binary, hex, words, URLs, ...) and
also sweeps the covertext ``length`` for one format to show how per-message
cost scales. One round-trip per format and payload is verified before timing.
It prints the CPU / OS / Python it ran on, since absolute
timings only mean something alongside the hardware.

Usage:
    python benchmark.py                 # full run
    python benchmark.py --quick         # fewer iterations, skip the length sweep
    python benchmark.py --iterations 500
"""

import argparse
import platform
import statistics
import subprocess
import time

import fte


# (label, regex, length): one representative format per output style.
# length values are chosen so each language has ample capacity for the
# sample payload while keeping runtimes comparable.
FORMATS = [
    ("Binary",       r"^[01]+$",                  512),
    ("Hex",          r"^[0-9a-f]+$",              256),
    ("Lowercase",    r"^[a-z]+$",                 256),
    ("Alphanumeric", r"^[A-Za-z0-9]+$",           192),
    ("URL path",     r"^/[a-z]+/[a-z]+\.html$",   128),
    ("Words",        r"^([a-z]+ )+[a-z]+$",       120),
]

# length values swept for a single format to show per-message scaling.
LENGTH_SWEEP_REGEX = r"^[a-z]+$"
LENGTH_SWEEP_VALUES = [128, 256, 512, 1024, 2048]

# Kept short so it fits every fixed-length format above. Per-message cost also
# depends on the payload size, so each format is timed with this payload and
# with one that fills its capacity (see _full_payload).
SAMPLE_PAYLOAD = b"benchmark payload."

# Fixed key; its value does not affect timing.
BENCH_KEY = bytes(range(32))


# --------------------------------------------------------------------------- #
# Hardware / environment detection                                            #
# --------------------------------------------------------------------------- #

def _cpu_model():
    """Best-effort human-readable CPU model string, cross-platform."""
    system = platform.system()
    try:
        if system == "Darwin":
            return subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
            ).strip()
        if system == "Linux":
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.startswith("model name"):
                        return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or platform.machine() or "unknown"


def _print_machine_header():
    print("=" * 76)
    print("libfte benchmark (pure-Python ranking, OpenSSL AES/HMAC)")
    print("=" * 76)
    print(f"CPU     : {_cpu_model()}")
    print(f"Arch    : {platform.machine()}")
    print(f"OS      : {platform.platform()}")
    print(f"Python  : {platform.python_version()} "
          f"({platform.python_implementation()})")
    print(f"libfte  : {fte.__version__}")
    print("=" * 76)


# --------------------------------------------------------------------------- #
# Measurement primitives                                                       #
# --------------------------------------------------------------------------- #

def _median_ms(fn, iterations):
    """Return the median per-call time in milliseconds over ``iterations`` runs."""
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(samples)


def _bench_build(regex, length, iterations):
    """Median time to construct a cipher (regex -> DFA -> counting table)."""
    def build():
        fte.FTE(output_format=fte.RegexFormat(regex, length=length), key=BENCH_KEY)
    return _median_ms(build, iterations)


def _full_payload(cipher):
    """A deterministic payload of exactly ``cipher.max_plaintext_bytes`` bytes."""
    n = cipher.max_plaintext_bytes
    return (bytes(range(256)) * (n // 256 + 1))[:n]


def _bench_round_trip(cipher, payload, iterations, warmup):
    """Median encrypt / decrypt time for one payload, plus a round-trip check."""
    # Correctness: the whole benchmark is meaningless if the round-trip is wrong.
    ok = cipher.decrypt(cipher.encrypt(payload)) == payload

    # Warm up so first-call overhead does not skew the median.
    for _ in range(warmup):
        cipher.decrypt(cipher.encrypt(payload))

    encrypt_ms = _median_ms(lambda: cipher.encrypt(payload), iterations)
    ct = cipher.encrypt(payload)
    decrypt_ms = _median_ms(lambda: cipher.decrypt(ct), iterations)
    return ok, encrypt_ms, decrypt_ms


def _bench_format(label, regex, length, payload, iterations, warmup):
    """Benchmark one cipher: build, then encrypt / decrypt a small payload and
    a full-capacity payload, verifying both round-trips."""
    build_ms = _bench_build(regex, length, max(3, iterations // 5))

    fmt = fte.RegexFormat(regex, length=length)
    cipher = fte.FTE(output_format=fmt, key=BENCH_KEY)
    capacity = fmt.cardinality.bit_length() - 1  # floor(log2(cardinality))

    full = _full_payload(cipher)
    small_ok, encrypt_ms, decrypt_ms = _bench_round_trip(
        cipher, payload, iterations, warmup
    )
    full_ok, full_encrypt_ms, full_decrypt_ms = _bench_round_trip(
        cipher, full, iterations, warmup
    )

    return {
        "label": label,
        "length": length,
        "capacity": capacity,
        "bits_per_char": capacity / length,
        "build_ms": build_ms,
        "encrypt_ms": encrypt_ms,
        "decrypt_ms": decrypt_ms,
        "full_bytes": len(full),
        "full_encrypt_ms": full_encrypt_ms,
        "full_decrypt_ms": full_decrypt_ms,
        "ok": small_ok and full_ok,
    }


# --------------------------------------------------------------------------- #
# Rendering                                                                    #
# --------------------------------------------------------------------------- #

# Per-message columns: the small payload (SAMPLE_PAYLOAD) and the
# full-capacity payload (``max(B)`` bytes, the cipher's max_plaintext_bytes).
_MESSAGE_HEADER = (
    f"{'enc/small':>11}{'dec/small':>11}"
    f"{'max(B)':>8}{'enc/max':>10}{'dec/max':>10}"
)


def _format_message_cells(r):
    return (
        f"{r['encrypt_ms']:>11.3f}{r['decrypt_ms']:>11.3f}"
        f"{r['full_bytes']:>8}{r['full_encrypt_ms']:>10.3f}"
        f"{r['full_decrypt_ms']:>10.3f}"
    )


def _print_format_table(rows):
    header = (
        f"{'Format':<14}{'length':>8}{'cap(bits)':>11}{'bits/char':>11}"
        f"{'build(ms)':>12}" + _MESSAGE_HEADER
    )
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['label']:<14}{r['length']:>8}{r['capacity']:>11}"
            f"{r['bits_per_char']:>11.2f}{r['build_ms']:>12.3f}"
            + _format_message_cells(r)
        )


def _print_sweep_table(rows):
    header = f"{'length':<8}{'cap(bits)':>11}" + _MESSAGE_HEADER
    print(header)
    print("-" * len(header))
    for r in rows:
        print(f"{r['length']:<8}{r['capacity']:>11}" + _format_message_cells(r))


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Benchmark libfte encrypt/decrypt performance.",
    )
    parser.add_argument(
        "-n", "--iterations", type=int, default=100,
        help="Timed iterations per measurement (default: 100).",
    )
    parser.add_argument(
        "-w", "--warmup", type=int, default=5,
        help="Warmup iterations before timing (default: 5).",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Fast run: 20 iterations and skip the length sweep.",
    )
    args = parser.parse_args(argv)

    iterations = 20 if args.quick else args.iterations
    warmup = args.warmup
    payload = SAMPLE_PAYLOAD

    _print_machine_header()
    print()
    print(f"Payloads: small = {len(payload)} bytes; max = the format's full "
          f"capacity (max_plaintext_bytes)")
    print(f"Timing  : median of {iterations} iterations ({warmup} warmup); "
          f"times in ms")
    print()

    print("Per-format performance (per-message times in ms)")
    rows = [
        _bench_format(label, regex, length, payload, iterations, warmup)
        for label, regex, length in FORMATS
    ]
    _print_format_table(rows)

    sweep = []
    if not args.quick:
        print()
        print(f"Per-message scaling vs. length (regex {LENGTH_SWEEP_REGEX})")
        sweep = [
            _bench_format(f"length={n}", LENGTH_SWEEP_REGEX, n,
                          payload, iterations, warmup)
            for n in LENGTH_SWEEP_VALUES
        ]
        _print_sweep_table(sweep)

    print()
    failures = [r["label"] for r in rows + sweep if not r["ok"]]
    if failures:
        print("ROUND-TRIP FAILURES: " + ", ".join(failures))
        return 1
    print("All round-trips verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
