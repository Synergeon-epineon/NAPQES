# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| Python reference (napqes.py, v6 wire format) | ✅ |
| Rust core (rust/) | ✅ |
| C port (C/) | ✅ |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues by e-mail to:

```
a.jakjoud@epineon.ai
```

### PGP Key

A PGP key for encrypting sensitive reports will be published at the same mailbox address before public launch. Until then, use the e-mail address above; plaintext reports are accepted.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEag8KOxYJKwYBBAHaRw8BAQdAHW4qGwOaGrkEWeXEIG2XRh+gxEczvktn
OUQBUDEcFHXNJ0FiZGVzbGFtIEpha2pvdWQgPGEuamFram91ZEBlcGluZW9u
LmFpPsLAEwQTFgoAhQWCag8KOwMLCQcJEK7QZyBB2pn9RRQAAAAAABwAIHNh
bHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmdS2LuopVGuUzTWNRf+W79dSufg
ylFjTxoVO3OQ/OUScAUVCggODAQWAAIBAhkBApsDAh4BFiEEQJfen/VHxtJh
sukzrtBnIEHamf0AAOC2AP9UK5diW3hATPm1wTGDqVBMFtgKQtHhNKjEWFr2
VXYaEgEAm85yGB8BCXrqiM2d6Ek/NlHtuJkhRITT2zteGMlJPwrOOARqDwo7
EgorBgEEAZdVAQUBAQdARnnupytDKh2Ruwnz2sYD7koZqfVcdkOl2wurRCRZ
2jEDAQgHwr4EGBYKAHAFgmoPCjsJEK7QZyBB2pn9RRQAAAAAABwAIHNhbHRA
bm90YXRpb25zLm9wZW5wZ3Bqcy5vcmf2HnKPGWpiSql/G+S2yiysDEoxi9Dq
MEl8DAT9qjqXQgKbDBYhBECX3p/1R8bSYbLpM67QZyBB2pn9AAAlDAEAvNR2
ozWSozPa7tAoN87zr05IVX7EdKVkMkE2mb3a5ZAA/ibDmal27eNEJE3/zQh9
sAZ6D8kKJsrP6MxZuOn3KYQH
=5+IP
-----END PGP PUBLIC KEY BLOCK-----
```


### What to include

Please include as much of the following as possible:

- Description of the vulnerability and the affected component (napqes.py,
  Rust core, C port, wire format, etc.).
- Steps to reproduce or proof-of-concept code.
- Impact assessment (confidentiality, integrity, authentication bypass, …).
- Suggested severity (Critical / High / Medium / Low / Informational).
- Whether you intend to publish (so we can coordinate disclosure timing).

## Disclosure Policy

We follow a **90-day coordinated disclosure policy**:

1. Acknowledge receipt within **5 business days**.
2. Provide a preliminary assessment within **15 business days**.
3. Target a fix or mitigation within **90 days** of the report.
4. Notify you when a fix is released and agree on a public disclosure date.
5. Publish a security advisory and credit your report (unless you prefer
   to remain anonymous).

For critical vulnerabilities with active exploitation evidence we may
request a shorter timeline. For complex issues requiring major
architectural change, we will negotiate an extension with you.

## Known Limitations (Not Vulnerabilities)

The following are documented design trade-offs, not reportable
vulnerabilities:

- **Streaming RUP (CAV-001).** `decrypt_stream` releases plaintext before
  the authentication tag is verified. It is gated behind an explicit
  opt-in flag. Use `decrypt_stream_strict` for authenticated streaming.
  Phase 3 will implement online-AE to remove this limitation.
- **16-bit length cap (CAV-002).** Block-mode plaintext is capped at
  65535 codepoints. Exceeding the cap raises `ValueError` immediately.
- **Padding length-bucket leak (CAV-003).** Block-mode padding reveals
  the power-of-two bucket of the plaintext length.
- **Ciphertext expansion (CAV-004).** Noise tokens inflate ciphertext size.

See [`docs/CAVEATS.md`](docs/CAVEATS.md) for full triage.

## Scope

In-scope:
- Confidentiality, integrity, or authentication failures in the v6 AEAD
  scheme.
- Key-recovery attacks.
- Authentication-bypass vulnerabilities.
- Implementation defects in napqes.py, the Rust core, or the C port.
- Vulnerabilities in the HMAC-SHA256 domain-separation scheme.
- Weaknesses in the noise-token construction.

Out-of-scope:
- Theoretical improvements to key size or noise parameters (submit as a
  research paper or ePrint rather than a vulnerability).
- Performance issues (not a security concern).
- UI / web-demo issues in `main.py` / `templates/` (report as GitHub issues
  once the repo is public).
- Known limitations listed above.
