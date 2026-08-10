#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Benchmark suite for libfte (Format-Transforming Encryption).

This script measures the two costs that matter when using FTE in practice:

  1. Encoder construction  -- the one-time cost of compiling a regex into a
     DFA and pre-computing the ranking tables. Paid once per (regex, slice).
  2. encode() / decode()   -- the steady-state cost paid per message. This is
     dominated by the DFA rank/unrank on large integers, so it grows with the
     ``fixed_slice`` (output length), not with the plaintext size.

It runs across a range of output formats (binary, hex, words, URLs, ...) and
also sweeps ``fixed_slice`` for one format to show how per-message cost scales.
Every timed round-trip is verified, so a clean run also doubles as a
correctness check.

libfte has two interchangeable backends selected by the FTE_USE_NATIVE
environment variable: a pure-Python implementation (default) and a native
C++/GMP extension. When the C++ extension is available this script runs BOTH
backends -- each in its own subprocess so the env var is honoured at import
time, exactly as a real user would set it -- and reports the speed-up. The run
also prints the CPU / OS / Python it executed on, since absolute numbers only
mean something alongside the hardware.

Usage:
    python benchmark.py                 # auto: run both backends if C++ is built
    python benchmark.py --quick         # fewer iterations, skip the slice sweep
    python benchmark.py --iterations 500
    python benchmark.py --backend python    # force a single backend
    python benchmark.py --backend native
    python benchmark.py --backend both

Building the C++ backend (needs GMP) enables the comparison:
    brew install gmp                    # or: apt-get install libgmp-dev
    FTE_BUILD_NATIVE=1 pip install --force-reinstall -e .
"""

import argparse
import importlib.util
import json
import os
import platform
import statistics
import subprocess
import sys
import time

import fte
from fte.dfa import using_native


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


def _cpu_counts():
    """Return (physical_cores_or_None, logical_cores)."""
    logical = os.cpu_count()
    physical = None
    system = platform.system()
    try:
        if system == "Darwin":
            physical = int(subprocess.check_output(
                ["sysctl", "-n", "hw.physicalcpu"], text=True
            ).strip())
        elif system == "Linux":
            pairs, phys = set(), None
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.startswith("physical id"):
                        phys = line.split(":", 1)[1].strip()
                    elif line.startswith("core id") and phys is not None:
                        pairs.add((phys, line.split(":", 1)[1].strip()))
            physical = len(pairs) or None
    except Exception:
        physical = None
    return physical, logical


def _print_machine_header(version):
    physical, logical = _cpu_counts()
    if physical and logical:
        cores = f"{physical} physical / {logical} logical"
    elif logical:
        cores = f"{logical} logical"
    else:
        cores = "unknown"

    print("=" * 88)
    print("libfte benchmark")
    print("=" * 88)
    print(f"CPU     : {_cpu_model()}")
    print(f"Cores   : {cores}")
    print(f"Arch    : {platform.machine()}")
    print(f"OS      : {platform.platform()}")
    print(f"Python  : {platform.python_version()} "
          f"({platform.python_implementation()})")
    print(f"libfte  : {version}")
    print("=" * 88)


# --------------------------------------------------------------------------- #
# Measurement primitives                                                       #
# --------------------------------------------------------------------------- #

def _time_op(fn, iterations):
    """Return the median per-call time in milliseconds over ``iterations`` runs."""
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(samples)


def _bench_format(label, regex, fixed_slice, payload, iterations, warmup):
    """Benchmark one encoder: build, encode, decode, and verify the round-trip."""
    start = time.perf_counter()
    encoder = fte.Encoder(regex=regex, fixed_slice=fixed_slice)
    build_ms = (time.perf_counter() - start) * 1000.0

    # Correctness: the whole benchmark is meaningless if the round-trip is wrong.
    ciphertext = encoder.encode(payload)
    recovered, _ = encoder.decode(ciphertext)
    ok = recovered == payload

    # Warm up so the first-call overhead does not skew the median.
    for _ in range(warmup):
        encoder.decode(encoder.encode(payload))

    encode_ms = _time_op(lambda: encoder.encode(payload), iterations)
    ct = encoder.encode(payload)
    decode_ms = _time_op(lambda: encoder.decode(ct), iterations)

    capacity = encoder.capacity
    return {
        "label": label,
        "fixed_slice": fixed_slice,
        "capacity": capacity,
        "bits_per_char": capacity / fixed_slice,
        "build_ms": build_ms,
        "encode_ms": encode_ms,
        "decode_ms": decode_ms,
        "ok": ok,
    }


def _bench_slice_sweep(payload, iterations, warmup):
    """Sweep fixed_slice for one format to show per-message cost scaling."""
    return [
        _bench_format(
            f"slice={fixed_slice}", SLICE_SWEEP_REGEX, fixed_slice,
            payload, iterations, warmup,
        )
        for fixed_slice in SLICE_SWEEP_VALUES
    ]


def run_measurements(iterations, warmup, do_sweep):
    """Run every measurement for the backend selected by this process's env."""
    payload = SAMPLE_PAYLOAD
    formats = [
        _bench_format(label, regex, fixed_slice, payload, iterations, warmup)
        for label, regex, fixed_slice in FORMATS
    ]
    sweep = _bench_slice_sweep(payload, iterations, warmup) if do_sweep else []
    return {
        "backend": "native" if using_native() else "python",
        "iterations": iterations,
        "warmup": warmup,
        "payload_bytes": len(payload),
        "formats": formats,
        "sweep": sweep,
    }


# --------------------------------------------------------------------------- #
# Single-backend rendering                                                     #
# --------------------------------------------------------------------------- #

def _print_single(result):
    print(f"Backend : {result['backend']}   "
          f"(median of {result['iterations']} iters, "
          f"{result['warmup']} warmup, payload {result['payload_bytes']} B)")
    print()
    print("Per-format encode/decode")
    header = (
        f"{'Format':<14}{'slice':>7}{'cap(b)':>9}{'bits/ch':>9}"
        f"{'build(ms)':>11}{'encode(ms)':>12}{'decode(ms)':>12}"
        f"{'enc op/s':>10}{'ok':>5}"
    )
    print(header)
    print("-" * len(header))
    for r in result["formats"]:
        ops = 1000.0 / r["encode_ms"] if r["encode_ms"] else float("inf")
        print(
            f"{r['label']:<14}{r['fixed_slice']:>7}{r['capacity']:>9}"
            f"{r['bits_per_char']:>9.2f}{r['build_ms']:>11.2f}"
            f"{r['encode_ms']:>12.3f}{r['decode_ms']:>12.3f}"
            f"{ops:>10.0f}{('yes' if r['ok'] else 'FAIL'):>5}"
        )
    if result["sweep"]:
        print()
        print(f"Per-message scaling vs. fixed_slice (regex {SLICE_SWEEP_REGEX})")
        header = (f"{'fixed_slice':<14}{'capacity(b)':>13}"
                  f"{'encode(ms)':>12}{'decode(ms)':>12}")
        print(header)
        print("-" * len(header))
        for r in result["sweep"]:
            print(f"{r['fixed_slice']:<14}{r['capacity']:>13}"
                  f"{r['encode_ms']:>12.3f}{r['decode_ms']:>12.3f}")


# --------------------------------------------------------------------------- #
# Two-backend comparison rendering (Python vs. C++)                            #
# --------------------------------------------------------------------------- #

def _speedup(py, na):
    return (py / na) if na else float("inf")


def _print_comparison(py_res, na_res):
    print(f"Backends: python vs. native (C++/GMP)   "
          f"(median of {py_res['iterations']} iters, "
          f"{py_res['warmup']} warmup, payload {py_res['payload_bytes']} B)")
    print("Times in ms; 'x' columns are python/native (higher = native faster).")
    print()
    print("Per-format encode/decode")
    header = (
        f"{'Format':<14}{'slice':>6}{'bits/ch':>8}"
        f"{'py-enc':>9}{'na-enc':>9}{'enc x':>7}"
        f"{'py-dec':>9}{'na-dec':>9}{'dec x':>7}{'ok':>5}"
    )
    print(header)
    print("-" * len(header))

    enc_speedups, dec_speedups = [], []
    for p, n in zip(py_res["formats"], na_res["formats"]):
        es = _speedup(p["encode_ms"], n["encode_ms"])
        ds = _speedup(p["decode_ms"], n["decode_ms"])
        enc_speedups.append(es)
        dec_speedups.append(ds)
        ok = p["ok"] and n["ok"]
        print(
            f"{p['label']:<14}{p['fixed_slice']:>6}{p['bits_per_char']:>8.2f}"
            f"{p['encode_ms']:>9.3f}{n['encode_ms']:>9.3f}{es:>6.1f}x"
            f"{p['decode_ms']:>9.3f}{n['decode_ms']:>9.3f}{ds:>6.1f}x"
            f"{('yes' if ok else 'FAIL'):>5}"
        )

    if py_res["sweep"] and na_res["sweep"]:
        print()
        print(f"Per-message scaling vs. fixed_slice (regex {SLICE_SWEEP_REGEX})")
        header = (
            f"{'fixed_slice':<12}{'cap(b)':>9}"
            f"{'py-enc':>9}{'na-enc':>9}{'enc x':>7}"
            f"{'py-dec':>9}{'na-dec':>9}{'dec x':>7}"
        )
        print(header)
        print("-" * len(header))
        for p, n in zip(py_res["sweep"], na_res["sweep"]):
            es = _speedup(p["encode_ms"], n["encode_ms"])
            ds = _speedup(p["decode_ms"], n["decode_ms"])
            print(
                f"{p['fixed_slice']:<12}{p['capacity']:>9}"
                f"{p['encode_ms']:>9.3f}{n['encode_ms']:>9.3f}{es:>6.1f}x"
                f"{p['decode_ms']:>9.3f}{n['decode_ms']:>9.3f}{ds:>6.1f}x"
            )

    py_build = statistics.mean(r["build_ms"] for r in py_res["formats"])
    na_build = statistics.mean(r["build_ms"] for r in na_res["formats"])
    print()
    print("Summary")
    print(f"  encode: native is {statistics.geometric_mean(enc_speedups):.1f}x "
          f"faster (geo-mean across formats)")
    print(f"  decode: native is {statistics.geometric_mean(dec_speedups):.1f}x "
          f"faster (geo-mean across formats)")
    print(f"  build : python avg {py_build:.2f} ms, native avg {na_build:.2f} ms")


# --------------------------------------------------------------------------- #
# Subprocess orchestration                                                     #
# --------------------------------------------------------------------------- #

def _native_available():
    """True if the compiled fte.cDFA extension can be imported."""
    try:
        return importlib.util.find_spec("fte.cDFA") is not None
    except Exception:
        return False


def _run_backend_worker(use_native, iterations, warmup, do_sweep):
    """Run one backend in a fresh subprocess and return its JSON results.

    A subprocess is used so FTE_USE_NATIVE is read at import time -- the same
    way a user selects the backend -- rather than being toggled mid-process.
    """
    env = dict(os.environ)
    env["FTE_USE_NATIVE"] = "1" if use_native else "0"
    cmd = [sys.executable, os.path.abspath(__file__), "--_emit-json",
           "-n", str(iterations), "-w", str(warmup)]
    if not do_sweep:
        cmd.append("--no-sweep")
    out = subprocess.check_output(cmd, env=env, text=True)
    return json.loads(out)


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Benchmark libfte encode/decode performance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        "--backend", choices=["auto", "python", "native", "both"], default="auto",
        help="Which backend(s) to run. 'auto' compares both when C++ is built "
             "(default).",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Fast run: 20 iterations and skip the fixed_slice sweep.",
    )
    # Internal flags used when this script re-invokes itself as a worker.
    parser.add_argument("--_emit-json", dest="emit_json", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--no-sweep", dest="no_sweep", action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    iterations = 20 if args.quick else args.iterations
    do_sweep = not (args.quick or args.no_sweep)

    # Worker mode: run for this process's backend and emit machine-readable JSON.
    if args.emit_json:
        result = run_measurements(iterations, args.warmup, do_sweep)
        print(json.dumps(result))
        return 0

    # Parent mode: print the machine header and orchestrate the backend runs.
    _print_machine_header(fte.__version__)
    print()

    native_ok = _native_available()
    backend = args.backend
    if backend == "auto":
        backend = "both" if native_ok else "python"
    if backend in ("native", "both") and not native_ok:
        print("NOTE: native C++ extension (fte.cDFA) is not built; "
              "running pure Python only.")
        print("      Build it with: FTE_BUILD_NATIVE=1 pip install "
              "--force-reinstall -e .")
        print()
        backend = "python"

    if backend == "both":
        py_res = _run_backend_worker(False, iterations, args.warmup, do_sweep)
        na_res = _run_backend_worker(True, iterations, args.warmup, do_sweep)
        _print_comparison(py_res, na_res)
        results = [py_res, na_res]
    else:
        result = _run_backend_worker(
            backend == "native", iterations, args.warmup, do_sweep)
        _print_single(result)
        results = [result]

    print()
    failures = [
        f"{res['backend']}:{r['label']}"
        for res in results for r in res["formats"] + res["sweep"] if not r["ok"]
    ]
    if failures:
        print("ROUND-TRIP FAILURES: " + ", ".join(failures))
        return 1
    print("All round-trips verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
