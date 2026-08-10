#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Benchmark suite for libfte (Format-Transforming Encryption).

libfte is pure Python, and this script measures the two costs that matter
when you use it:

  1. Encoder construction  -- the one-time cost of compiling a regex into a
     DFA and pre-computing the ranking tables. Paid once per (regex, slice).
  2. encode() / decode()   -- the steady-state cost paid per message. This is
     dominated by the DFA rank/unrank on large integers, so it grows with the
     ``fixed_slice`` (output length), not with the plaintext size.

It runs across a range of output formats (binary, hex, words, URLs, ...) and
also sweeps ``fixed_slice`` for one format to show how per-message cost scales.
Every timed round-trip is verified, so a clean run also doubles as a
correctness check. It prints the CPU / OS / Python it ran on, since absolute
timings only mean something alongside the hardware.

Usage:
    python benchmark.py                 # full run
    python benchmark.py --quick         # fewer iterations, skip the slice sweep
    python benchmark.py --iterations 500
"""

import argparse
import platform
import statistics
import subprocess
import time

import fte
import fte.encoder


# (label, regex, fixed_slice) -- one representative encoder per output format.
# fixed_slice values are chosen so each language has ample capacity for the
# sample payload while keeping runtimes comparable.
FORMATS = [
    ("Binary",       r"^[01]+$",                  512),
    ("Hex",          r"^[0-9a-f]+$",              256),
    ("Lowercase",    r"^[a-z]+$",                 256),
    ("Alphanumeric", r"^[A-Za-z0-9]+$",           192),
    ("URL path",     r"^/[a-z]+/[a-z]+\.html$",   128),
    ("Words",        r"^([a-z]+ )+[a-z]+$",       120),
]

# fixed_slice values swept for a single format to show per-message scaling.
SLICE_SWEEP_REGEX = r"^[a-z]+$"
SLICE_SWEEP_VALUES = [128, 256, 512, 1024, 2048]

SAMPLE_PAYLOAD = b"The quick brown fox jumps over the lazy dog. " * 2


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
    print("libfte benchmark (pure Python)")
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


def _clear_encoder_cache():
    """Drop libfte's internal encoder cache so each build is measured fresh."""
    cache = getattr(fte.encoder, "_instance", None)
    if isinstance(cache, dict):
        cache.clear()


def _bench_build(regex, fixed_slice, iterations):
    """Median time to construct an Encoder (regex -> DFA -> counting table)."""
    def build():
        _clear_encoder_cache()
        fte.Encoder(regex=regex, fixed_slice=fixed_slice)
    return _median_ms(build, iterations)


def _bench_format(label, regex, fixed_slice, payload, iterations, warmup):
    """Benchmark one encoder: build, encode, decode, and verify the round-trip."""
    build_ms = _bench_build(regex, fixed_slice, max(3, iterations // 5))

    encoder = fte.Encoder(regex=regex, fixed_slice=fixed_slice)

    # Correctness: the whole benchmark is meaningless if the round-trip is wrong.
    recovered, _ = encoder.decode(encoder.encode(payload))
    ok = recovered == payload

    # Warm up so first-call overhead does not skew the median.
    for _ in range(warmup):
        encoder.decode(encoder.encode(payload))

    encode_ms = _median_ms(lambda: encoder.encode(payload), iterations)
    ct = encoder.encode(payload)
    decode_ms = _median_ms(lambda: encoder.decode(ct), iterations)

    return {
        "label": label,
        "fixed_slice": fixed_slice,
        "capacity": encoder.capacity,
        "bits_per_char": encoder.capacity / fixed_slice,
        "build_ms": build_ms,
        "encode_ms": encode_ms,
        "decode_ms": decode_ms,
        "ok": ok,
    }


# --------------------------------------------------------------------------- #
# Rendering                                                                    #
# --------------------------------------------------------------------------- #

def _print_format_table(rows):
    header = (
        f"{'Format':<14}{'slice':>7}{'cap(bits)':>11}{'bits/char':>11}"
        f"{'build(ms)':>12}{'encode(ms)':>12}{'decode(ms)':>12}"
    )
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['label']:<14}{r['fixed_slice']:>7}{r['capacity']:>11}"
            f"{r['bits_per_char']:>11.2f}{r['build_ms']:>12.3f}"
            f"{r['encode_ms']:>12.3f}{r['decode_ms']:>12.3f}"
        )


def _print_sweep_table(rows):
    header = (f"{'fixed_slice':<13}{'cap(bits)':>11}"
              f"{'encode(ms)':>12}{'decode(ms)':>12}")
    print(header)
    print("-" * len(header))
    for r in rows:
        print(f"{r['fixed_slice']:<13}{r['capacity']:>11}"
              f"{r['encode_ms']:>12.3f}{r['decode_ms']:>12.3f}")


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Benchmark libfte encode/decode performance.",
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
        help="Fast run: 20 iterations and skip the fixed_slice sweep.",
    )
    args = parser.parse_args(argv)

    iterations = 20 if args.quick else args.iterations
    warmup = args.warmup
    payload = SAMPLE_PAYLOAD

    _print_machine_header()
    print()
    print(f"Payload : {len(payload)} bytes")
    print(f"Timing  : median of {iterations} iterations ({warmup} warmup)")
    print()

    print("Per-format performance")
    rows = [
        _bench_format(label, regex, fixed_slice, payload, iterations, warmup)
        for label, regex, fixed_slice in FORMATS
    ]
    _print_format_table(rows)

    sweep = []
    if not args.quick:
        print()
        print(f"Per-message scaling vs. fixed_slice (regex {SLICE_SWEEP_REGEX})")
        sweep = [
            _bench_format(f"slice={fs}", SLICE_SWEEP_REGEX, fs,
                          payload, iterations, warmup)
            for fs in SLICE_SWEEP_VALUES
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
