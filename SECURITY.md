# Security Policy

## Supported Versions
OIP is currently a **draft specification**. The reference tools are provided for interoperability testing and prototyping.

| Version | Supported |
|--------:|:---------:|
| v0.1    | ✅ Yes     |

## Reporting a Vulnerability
Please report security issues responsibly by opening a **private** report when possible.

If private reporting is not available in your workflow, open an issue with:
- minimal reproduction steps
- affected files / commit hash
- expected vs observed behavior
- impact assessment (tamper, replay, spoofing, etc.)

Do **not** publish private keys, secrets, or sensitive incident data.

## Scope
In scope:
- signature verification correctness
- deterministic canonicalization failures
- event_id computation ambiguity
- chain/link validation correctness
- downgrade/rollback detection gaps (firmware/model binding)

Out of scope:
- physical compromise of hardware
- side-channel extraction of keys
- transport-layer security (TLS/mTLS/etc.)
- policy decisions (e.g., when an actuator should block)
