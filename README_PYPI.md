# libfte

[![PyPI version](https://img.shields.io/pypi/v/fte.svg)](https://pypi.org/project/fte/)
[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Format-Transforming Encryption** — encrypt data so the ciphertext matches any format you specify.

## What is FTE?

Unlike standard encryption that produces random-looking output, FTE produces ciphertext that looks like whatever format you specify with a regular expression—hex strings, alphanumeric tokens, or any regex-expressible pattern.

## Installation

```bash
pip install fte
```

Works out of the box with pure Python—no compilation required.

## Quick Example

Encrypt a secret so the ciphertext looks like words:

```python
import fte

# Create encoder: output will be lowercase "words" with spaces
encoder = fte.Encoder(regex=r'^([a-z]+ )+[a-z]+$', fixed_slice=80)

# Encrypt
ciphertext = encoder.encode(b'Attack at dawn')
print(ciphertext.decode())
# → "kqpvx mzbjw tnrdc fyhls wqaem xocgi znvub pdkry lfstj bhwce"

# Decrypt
plaintext, _ = encoder.decode(ciphertext)
# → b'Attack at dawn'
```

## Use Cases

- **Protocol obfuscation**: Make encrypted traffic look like benign data
- **Bypassing filters**: Evade systems that block encrypted-looking content  
- **Steganography**: Hide data within expected formats

## Performance

For ~3x better performance, enable the optional native extension:

```bash
sudo apt-get install libgmp-dev  # or: brew install gmp
FTE_BUILD_NATIVE=1 pip install --force-reinstall fte
export FTE_USE_NATIVE=1
```

## Documentation

Full docs and examples: [github.com/kpdyer/libfte](https://github.com/kpdyer/libfte)

## Reference

Based on [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (ACM CCS 2013).

## License

MIT
