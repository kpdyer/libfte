# Examples

Install `fte` using the [development setup](../BUILDING.md#development-setup), or
`python -m pip install fte`, then run a script from the repository root:

```bash
python examples/01_basic_usage.py
```

| File | Demonstrates |
|------|--------------|
| [01_basic_usage.py](01_basic_usage.py) | Encrypt a stream of fixed-length covertexts with a shared key; reject a wrong key |
| [02_formats_and_capacity.py](02_formats_and_capacity.py) | Covertext formats, their capacity, and variable-length covertext |
| [03_error_handling.py](03_error_handling.py) | Handling invalid input, capacity errors, and tampering |
| [04_custom_format.py](04_custom_format.py) | Writing a ranked-format provider |
| [05_authenticated_fte.py](05_authenticated_fte.py) | Authenticated encryption of a structured input |
| [06_fpe_digits.py](06_fpe_digits.py) | Format-preserving encryption of digits |
| [07_deterministic_fte.py](07_deterministic_fte.py) | Deterministic encryption from digits to hex |

See the [API reference](../docs/api.md) and
[regex guide](../fte/formats/regex/README.md) for parameters and capacity limits.
