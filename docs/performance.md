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

Once the rest of a covertext may be any string over the format's alphabet, as
after the first symbol of `^[0-9a-f]+$` or `^[a-z]+$`, it is converted as one
base-b numeral with Python's built-in integer conversions instead of one DFA
step per symbol. Such formats scale much better. The gain is largest for
binary, octal, hex, and any-byte (`.`) alphabets, and for decrypting alphabets
of up to 36 symbols.

The script reports CPU, OS, Python, and libfte versions. The following run
used an Intel Xeon E5-2683 v4 and Python 3.14.4; times are milliseconds,
medians of 100 iterations. Results depend on hardware and software versions.

```
Per-format performance (per-message times in ms)
Format          length  cap(bits)  bits/char   build(ms)  enc/small  dec/small  max(B)   enc/max   dec/max
----------------------------------------------------------------------------------------------------------
Binary             512        512       1.00       0.388      0.024      0.024      35     0.025     0.025
Hex                256       1024       4.00       0.272      0.023      0.024      99     0.023     0.024
Lowercase          256       1203       4.70       0.302      0.053      0.023     122     0.063     0.026
Alphanumeric       192       1143       5.95       0.331      0.048      0.039     114     0.057     0.047
URL path           128        575       4.49       0.584      0.094      0.084      43     0.115     0.105
Words              120        570       4.75       0.461      0.094      0.078      43     0.107     0.093

Per-message scaling vs. length (regex ^[a-z]+$)
length    cap(bits)  enc/small  dec/small  max(B)   enc/max   dec/max
---------------------------------------------------------------------
128             601      0.041      0.023      47     0.044     0.024
256            1203      0.053      0.023     122     0.064     0.026
512            2406      0.077      0.025     272     0.113     0.032
1024           4813      0.127      0.029     573     0.252     0.052
2048           9626      0.228      0.034    1175     0.661     0.113
```

In this run, increasing lowercase covertext length from 128 to 2048 increased
small-payload encryption time about 5.6x and full-capacity encryption time
about 15x. Decryption, which parses the numeral with `int()`, grew about 1.5x
and 4.7x. Full-capacity messages grow with the format, making the integer
arithmetic more expensive.
