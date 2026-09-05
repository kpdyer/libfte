# Examples

Install `fte` using the [development setup](../BUILDING.md#development-setup), or
`python -m pip install fte`, then run a script from the repository root:

```bash
python examples/01_basic_usage.py
```

| File | Demonstrates |
|------|--------------|
| [01_basic_usage.py](01_basic_usage.py) | Encrypt/decrypt with a shared key; reject a wrong key |
| [03_regex_formats.py](03_regex_formats.py) | A gallery of covertext formats |
| [04_variable_length.py](04_variable_length.py) | Variable-length covertext |
| [05_capacity_calculation.py](05_capacity_calculation.py) | Inspecting format capacity |
| [06_error_handling.py](06_error_handling.py) | Handling invalid input, capacity errors, and tampering |
| [07_multiple_messages.py](07_multiple_messages.py) | Parsing a stream of fixed-length covertexts |
| [08_custom_format.py](08_custom_format.py) | Writing a ranked-format provider |
| [09_authenticated_fte.py](09_authenticated_fte.py) | Authenticated encryption of a structured input |
| [10_fpe_digits.py](10_fpe_digits.py) | Format-preserving encryption of digits |
| [11_deterministic_fte.py](11_deterministic_fte.py) | Deterministic encryption from digits to hex |

See the [API reference](../docs/api.md) and
[regex guide](../fte/formats/regex/README.md) for parameters and capacity limits.
