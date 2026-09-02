# Security Policy

## Supported Versions

Security fixes are applied to the latest released line only. Older versions do
not receive backported patches, so please upgrade to a supported version.

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Security model

- **Authenticated encryption** (`cipher="aes-ctr-hmac"`, the default for a
  bytes input): AES-128-CTR, then HMAC-SHA256 over the nonce and ciphertext
  truncated to a 128-bit tag (Encrypt-then-MAC). The 32-byte key is split into
  a 16-byte AES key and a 16-byte MAC key. Each message gets a fresh 12-byte
  nonce from `os.urandom`; the frame is
  `version (1) || nonce (12) || ciphertext || tag (16)`.
- **Nonce bound**: keep the number of messages per key well under 2^32. At
  2^32 messages the probability of a repeated nonce is about 2^-33, and a
  repeat exposes the confidentiality of the colliding pair only, never
  authenticity.
- **Decryption order**: `decrypt` rejects a covertext outside the format, an
  impossible rank or length, or a wrong version byte before the tag check, then
  verifies the tag (constant-time compare) before decrypting anything. The
  pre-tag rejection timing reveals only what is computable without the key. Do
  not expose `decrypt` to untrusted callers as a timing oracle.
- **Deterministic cipher** (`cipher="ff1"` or a cipher object): deterministic
  and unauthenticated. Equal plaintexts give equal covertexts, so it leaks
  plaintext equality unless each record gets a distinct `tweak`, and it has no
  integrity protection. Domains below one million values are refused (per
  length slice when length is preserved). Never reuse a key across the two
  ciphers.
- **Patterns and lengths are trusted input**: never build a `RegexFormat` from
  attacker-controlled values. The ranking table takes O(states x length^2)
  memory, and the DFA state count can be exponential in the pattern.
- **Covertext format is not a secret**: `rank`/`unrank` need no key, so anyone
  can re-encode a covertext from one output format into another. This is
  inherent to FTE; the key protects the plaintext and (with AE) integrity, not
  the choice of format. With a bytes input the frame length also reveals the
  plaintext length.
- **Wire format**: 0.4.x covertexts are not compatible with 0.3.x and earlier,
  which used a different construction and frame layout; both endpoints must
  run 0.4.x.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Report vulnerabilities privately through GitHub's private vulnerability
reporting:

1. Go to the repository's [**Security** tab](https://github.com/kpdyer/libfte/security).
2. Click **Report a vulnerability** to open a private advisory
   (direct link: <https://github.com/kpdyer/libfte/security/advisories/new>).
3. Include as much detail as you can:
   - the affected version(s) and platform,
   - a description of the issue and its impact,
   - steps to reproduce or a proof of concept,
   - any suggested remediation.

You will receive a response acknowledging the report. If the issue is
confirmed, a fix will be prepared and released, and the advisory will be
published (crediting you unless you prefer to remain anonymous).

Thank you for helping keep this project and its users safe.
