# OIP Threat Model (Draft)

## Goals
OIP aims to provide:
- tamper-evident action logging
- cryptographic attribution to operational identities
- deterministic verification for audit and forensics

## Assets
- private signing keys
- OID records (public keys, firmware/model hashes)
- event chains (AEO logs)
- verifier implementation and canonicalization rules

## Adversaries
- remote attacker modifying logs
- malicious insider attempting to deny actions
- compromised node attempting replay or deletion
- supply-chain attacker swapping firmware/model artifacts

## Attacks & Mitigations

### 1) Event tampering
**Attack:** modify event fields post-hoc.  
**Mitigation:** signature + event_id derived from canonical body.

### 2) Event deletion
**Attack:** remove events to hide actions.  
**Mitigation:** append-only chain expectations + sequence continuity + prev hash linking.

### 3) Replay
**Attack:** re-submit old events to fabricate actions.  
**Mitigation:** sequence monotonicity + uniqueness constraints + prev hash checks.

### 4) Identity spoofing
**Attack:** pretend to be another entity.  
**Mitigation:** signature verification using OID public key; OID revocation.

### 5) Firmware/model rollback
**Attack:** run older unsafe firmware/model while claiming current version.  
**Mitigation:** firmware_hash/model_hash binding in OID and per-event.

## Out of Scope / Limitations
- full physical compromise of hardware
- undetected private key theft (without revocation visibility)
- sensor spoofing before digesting input
- transport-layer security (left to integrators)

## Recommendations
- hardware-backed key storage when possible (TPM/SE/TEE)
- secure time sources for timestamping
- periodic anchoring for high-risk events (R3-R5)
