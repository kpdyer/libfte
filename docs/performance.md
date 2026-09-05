# Performance

[benchmark.py](../benchmark.py) measures regex/cipher construction and per-message
`encrypt()` and `decrypt()` costs across binary, hex, lowercase, alphanumeric,
URL-path, and word formats. Each format uses an 18-byte payload and a payload
of `cipher.max_plaintext_bytes` bytes. One initial round trip is checked for
each format/payload pair before the operations are timed.

```bash
python benchmark.py            # 100 timed iterations, including a length sweep
python benchmark.py --quick    # 20 iterations, no length sweep
python benchmark.py --help
```

Construction compiles a regex to a DFA and builds its counting tables. Reuse
formats and cipher instances across messages. Per-message cost grows with both
the covertext length (the DFA walk) and the plaintext size (the width of the
integers being ranked).

The script reports CPU, OS, Python, and libfte versions. The following historical
run used an Apple M3 Pro and Python 3.14; times are milliseconds, medians of
100 iterations. Results depend on hardware and software versions.

```
Per-format performance (per-message times in ms)
Format          length  cap(bits)  bits/char   build(ms)  enc/small  dec/small  max(B)   enc/max   dec/max
----------------------------------------------------------------------------------------------------------
Binary             512        512       1.00       0.110      0.051      0.043      35     0.060     0.050
Hex                256       1024       4.00       0.076      0.026      0.020      99     0.046     0.037
Lowercase          256       1203       4.70       0.082      0.026      0.021     122     0.047     0.040
Alphanumeric       192       1143       5.95       0.097      0.021      0.017     114     0.039     0.031
URL path           128        575       4.49       0.186      0.031      0.030      43     0.038     0.037
Words              120        570       4.75       0.120      0.031      0.028      43     0.037     0.035

Per-message scaling vs. length (regex ^[a-z]+$)
length    cap(bits)  enc/small  dec/small  max(B)   enc/max   dec/max
---------------------------------------------------------------------
128             601      0.019      0.016      47     0.023     0.020
256            1203      0.028      0.021     122     0.047     0.039
512            2406      0.046      0.034     272     0.132     0.098
1024           4813      0.082      0.059     573     0.436     0.293
2048           9626      0.152      0.111    1175     1.612     0.943
```

In this run, increasing lowercase covertext length from 128 to 2048 increased
small-payload encryption time about 8x and full-capacity encryption time about
70x. Full-capacity messages grow with the format, making integer arithmetic
more expensive as well as lengthening the DFA walk.
