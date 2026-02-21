# OIP Quickstart (v0.1.0)

This guide lets you generate an OID, emit a signed event, and verify it locally in under 2 minutes.

## Requirements
- Python 3.9+
- No external dependencies

## 1) Generate keys
```bash
python3 reference/emitter-cli/oip_emit.py gen-key --out keys.json

2) Create an OID

PUB=$(python3 -c "import json;print(json.load(open('keys.json'))['public_key'])")

python3 reference/emitter-cli/oip_emit.py make-oid \
  --oid OID-ROBOT-0001 \
  --public-key-base64 "$PUB" \
  --manufacturer-id "ACME Robotics" \
  --firmware-hash eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  --out oid.json

3) Emit an event (and save to chain)

SEED=$(python3 -c "import json;print(json.load(open('keys.json'))['private_key_seed'])")

python3 reference/emitter-cli/oip_emit.py emit \
  --oid-json oid.json \
  --private-key-seed-base64 "$SEED" \
  --action-type navigation_decision \
  --risk-level R2 \
  --input-digest bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --decision-digest cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --state-digest dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  --chain-dir ./chain \
  --out event.json

4) Verify

python3 reference/verifier-cli/oip_verify.py verify --event event.json --oid oid.json --chain-dir ./chain

Expected output:

VALID


5) Run the conformance suite

python3 tests/run_tests.py

Expected output:

ALL TESTS PASSED


## 2) `RELEASES/v0.1.0.md` (file completo)
```md
# OIP v0.1.0 — Initial Deterministic Release

## Summary
OIP v0.1.0 is the first draft reference release of a minimal deterministic attribution and verification protocol for autonomous and AI-driven systems.

## Included
- Specification: `SPEC/OIP-v0.1.md` (v0.1.0)
- Reference verifier (pure Python, deterministic, fail-closed)
- Reference emitter (pure Python: keygen, OID builder, event emit, chain save)
- Conformance test suite
- Security and governance baseline docs

## Normative Rules (Highlights)
- Canonical JSON required for all hashing/signing (deterministic)
- `event_id` computed over EventBody excluding `event_id` and `signature`
- Signature computed over the same EventBody
- Append-only chain requirements per OID
- Verifier outputs: VALID / INVALID / INCOMPLETE / REVOKED

## Intended Use
- Interoperability testing
- OEM integration evaluation
- Safety/audit logging prototypes
- Forensic reconstruction demos

Status: Draft (reference implementation).


---




Scrivimi “fatto” quando hai pushato anche questo.
