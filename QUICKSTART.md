# OIP Quickstart (v0.1.0)

Generate an operational identity, emit a signed event, and verify it locally in under two minutes.

Requirements:
Python 3.9+  
No external dependencies

---

## 1. Generate keypair

```bash
python3 reference/emitter-cli/oip_emit.py gen-key --out keys.json


---

2. Create Operational Identity (OID)

PUB=$(python3 -c "import json;print(json.load(open('keys.json'))['public_key'])")

python3 reference/emitter-cli/oip_emit.py make-oid \
  --oid OID-ROBOT-0001 \
  --public-key-base64 "$PUB" \
  --manufacturer-id "ACME Robotics" \
  --firmware-hash eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  --out oid.json


---

3. Emit signed event

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


---

4. Verify event

python3 reference/verifier-cli/oip_verify.py verify \
  --event event.json \
  --oid oid.json \
  --chain-dir ./chain

Expected output:

VALID


---

5. Run conformance suite

python3 tests/run_tests.py

Expected:

ALL TESTS PASSED

---

# 📄 FILE 2  
## crea cartella: `RELEASES/`

poi file:

## `RELEASES/v0.1.0.md`

```md
# OIP v0.1.0 — Initial Deterministic Release

Operational Identity Protocol v0.1.0 is the first reference release of a minimal deterministic attribution and verification protocol for autonomous and AI-driven systems.

---

## Included

- Core specification v0.1.0
- Deterministic canonical JSON rules
- Reference verifier (pure Python)
- Reference emitter (pure Python)
- Conformance test suite
- Security baseline
- Governance baseline

---

## Core Properties

Deterministic verification  
Fail-closed validation  
Append-only identity-bound event chains  
Vendor-neutral implementation  
Local-first operation  

---

## Verification Outputs

VALID  
INVALID  
INCOMPLETE  
REVOKED  

---

## Intended Use

Autonomous systems  
Robotics  
Industrial automation  
AI decision systems  
Forensic reconstruction  
Safety audit logging  

---

## Status

Draft reference implementation.  
Intended for interoperability testing and OEM evaluation.


