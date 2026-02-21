# OIP Verifier CLI (Reference)

This is a reference implementation of the OIP verification engine.

## Requirements
- Python 3.9+ (no external dependencies)

## Usage

Verify a single event against an OID:

```bash
python3 oip_verify.py verify --event examples/robot-event.json --oid oid.json

Verify an event with a previous event (chain link check):

python3 oip_verify.py verify --event event.json --oid oid.json --prev prev_event.json

Verify an event against a chain directory (loads prev by hash if found):

python3 oip_verify.py verify --event event.json --oid oid.json --chain-dir ./chain/

Exit codes:

0: VALID

1: INVALID

2: REVOKED

3: INCOMPLETE


Outputs (stdout):

VALID | INVALID | REVOKED | INCOMPLETE


Notes:

Canonical JSON: stable, deterministic encoding (sorted keys, no whitespace).

Non-deterministic JSON (floats, NaN, Infinity) is rejected (fail-closed).

Signatures: Ed25519 verify (pure python reference; not optimized).


---

## 2) `reference/verifier-cli/oip_verify.py`
```python
#!/usr/bin/env python3
"""
OIP Verifier CLI (Reference) — pure Python, deterministic, fail-closed.

Implements:
- Minimal schema checks for OID and AEO (Action Event Object)
- Canonical JSON serialization (deterministic)
- event_id recomputation (SHA-256 over canonical body without signature)
- Ed25519 signature verification (pure python reference)
- Optional chain verification via --prev or --chain-dir
- Output: VALID | INVALID | REVOKED | INCOMPLETE
- Exit codes: 0 VALID, 1 INVALID, 2 REVOKED, 3 INCOMPLETE
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
from typing import Any, Dict, Optional, Tuple


# ==========================
# Utilities: deterministic JSON
# ==========================

def _reject_nondeterministic_json(x: Any, path: str = "$") -> None:
    """
    Reject floats/NaN/Infinity and any non-JSON types.
    Fail-closed: deterministic hashing requires deterministic encoding.
    """
    if x is None:
        return
    if isinstance(x, (str, bool, int)):
        return
    if isinstance(x, float):
        raise ValueError(f"Non-deterministic JSON number (float) at {path}")
    if isinstance(x, list):
        for i, v in enumerate(x):
            _reject_nondeterministic_json(v, f"{path}[{i}]")
        return
    if isinstance(x, dict):
        for k, v in x.items():
            if not isinstance(k, str):
                raise ValueError(f"Non-deterministic JSON key type at {path}: {type(k)}")
            _reject_nondeterministic_json(v, f"{path}.{k}")
        return
    raise ValueError(f"Unsupported JSON type at {path}: {type(x)}")


def canonical_json(obj: Any) -> bytes:
    """
    Deterministic canonical JSON encoding:
    - sorted keys
    - no whitespace
    - UTF-8
    - rejects floats (fail-closed)
    """
    _reject_nondeterministic_json(obj)
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ==========================
# Parsing helpers
# ==========================

def load_json(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        raw = f.read()
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid JSON file: {path}: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"Top-level JSON must be an object: {path}")
    return obj


def is_hex_64(s: Any) -> bool:
    if not isinstance(s, str):
        return False
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False


def parse_pubkey(pubkey_str: str) -> bytes:
    """
    Accepts:
    - hex (32 bytes -> 64 hex chars)
    - base64 (32 bytes)
    """
    pubkey_str = pubkey_str.strip()
    # hex
    if len(pubkey_str) == 64:
        try:
            return bytes.fromhex(pubkey_str)
        except Exception:
            pass
    # base64
    try:
        b = base64.b64decode(pubkey_str, validate=True)
        if len(b) == 32:
            return b
    except Exception:
        pass
    raise ValueError("public_key must be 32 bytes (hex64 or base64)")

def parse_signature(sig_str: str) -> bytes:
    """
    Accepts:
    - hex (64 bytes -> 128 hex chars)
    - base64 (64 bytes)
    """
    sig_str = sig_str.strip()
    # hex
    if len(sig_str) == 128:
        try:
            return bytes.fromhex(sig_str)
        except Exception:
            pass
    # base64
    try:
        b = base64.b64decode(sig_str, validate=True)
        if len(b) == 64:
            return b
    except Exception:
        pass
    raise ValueError("signature must be 64 bytes (hex128 or base64)")


# ==========================
# Minimal schema validation (fail-closed)
# ==========================

def validate_oid(oid: Dict[str, Any]) -> Tuple[bool, str]:
    req = ["oid", "public_key", "manufacturer_id", "firmware_hash", "created_at", "status"]
    for k in req:
        if k not in oid:
            return False, f"OID missing required field: {k}"

    if not isinstance(oid["oid"], str) or not (8 <= len(oid["oid"]) <= 128):
        return False, "OID.oid invalid"

    if not isinstance(oid["manufacturer_id"], str) or not (1 <= len(oid["manufacturer_id"]) <= 128):
        return False, "OID.manufacturer_id invalid"

    if not isinstance(oid["created_at"], str) or len(oid["created_at"]) < 10:
        return False, "OID.created_at invalid"

    if oid["status"] not in ("ACTIVE", "REVOKED", "SUSPENDED"):
        return False, "OID.status invalid"

    if not is_hex_64(oid["firmware_hash"]):
        return False, "OID.firmware_hash must be sha256 hex"

    if "model_hash" in oid and oid["model_hash"] is not None:
        if not is_hex_64(oid["model_hash"]):
            return False, "OID.model_hash must be sha256 hex or null"

    # public_key parse
    try:
        _ = parse_pubkey(oid["public_key"])
    except Exception as e:
        return False, f"OID.public_key invalid: {e}"

    return True, "OK"


def validate_event(ev: Dict[str, Any]) -> Tuple[bool, str]:
    req = [
        "event_id", "oid", "timestamp", "sequence", "prev_event_hash",
        "action_type", "risk_level", "input_digest", "decision_digest",
        "state_digest", "firmware_hash", "model_hash", "signature"
    ]
    for k in req:
        if k not in ev:
            return False, f"Event missing required field: {k}"

    if not is_hex_64(ev["event_id"]):
        return False, "event_id must be sha256 hex"

    if not isinstance(ev["oid"], str) or not (8 <= len(ev["oid"]) <= 128):
        return False, "event.oid invalid"

    if not isinstance(ev["timestamp"], str) or len(ev["timestamp"]) < 10:
        return False, "event.timestamp invalid"

    if not isinstance(ev["sequence"], int) or ev["sequence"] < 1:
        return False, "event.sequence invalid"

    if ev["prev_event_hash"] is not None and not is_hex_64(ev["prev_event_hash"]):
        return False, "event.prev_event_hash must be sha256 hex or null"

    if not isinstance(ev["action_type"], str) or not (1 <= len(ev["action_type"]) <= 64):
        return False, "event.action_type invalid"

    if ev["risk_level"] not in ("R0", "R1", "R2", "R3", "R4", "R5"):
        return False, "event.risk_level invalid"

    for d in ("input_digest", "decision_digest", "state_digest", "firmware_hash"):
        if not is_hex_64(ev[d]):
            return False, f"event.{d} must be sha256 hex"

    if ev["model_hash"] is not None and not is_hex_64(ev["model_hash"]):
        return False, "event.model_hash must be sha256 hex or null"

    try:
        _ = parse_signature(ev["signature"])
    except Exception as e:
        return False, f"event.signature invalid: {e}"

    return True, "OK"


# ==========================
# Ed25519 verify (pure python reference)
# Based on public-domain style implementations of ed25519 arithmetic.
# Not optimized. Intended for reference/testing.
# ==========================

# Curve constants
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493

def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)

def _xrecover(y: int) -> int:
    xx = (y*y - 1) * _inv(486662 * y*y + 1) % _q
    x = pow(xx, (_q + 3) // 8, _q)
    if (x*x - xx) % _q != 0:
        x = (x * pow(2, (_q - 1) // 4, _q)) % _q
    if x % 2 != 0:
        x = _q - x
    return x

_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q - 1) // 4, _q)

def _edwards(P: Tuple[int,int], Q: Tuple[int,int]) -> Tuple[int,int]:
    (x1, y1) = P
    (x2, y2) = Q
    x3 = (x1*y2 + x2*y1) * _inv(1 + _d*x1*x2*y1*y2) % _q
    y3 = (y1*y2 + x1*x2) * _inv(1 - _d*x1*x2*y1*y2) % _q
    return (x3, y3)

def _scalarmult(P: Tuple[int,int], e: int) -> Tuple[int,int]:
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q

_Bx = _xrecover(4 * _inv(5) % _q)
_By = 4 * _inv(5) % _q
_B = (_Bx, _By)

def _encodepoint(P: Tuple[int,int]) -> bytes:
    (x, y) = P
    bits = y.to_bytes(32, "little")
    bits_list = bytearray(bits)
    bits_list[31] = (bits_list[31] & 0x7F) | ((x & 1) << 7)
    return bytes(bits_list)

def _decodepoint(s: bytes) -> Tuple[int,int]:
    if len(s) != 32:
        raise ValueError("Invalid point encoding length")
    y = int.from_bytes(bytes([s[i] for i in range(32)]), "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if ((s[31] >> 7) & 1) != (x & 1):
        x = _q - x
    P = (x, y)
    # validate point
    (x, y) = P
    if (-x*x + y*y - 1 - _d*x*x*y*y) % _q != 0:
        raise ValueError("Point not on curve")
    return P

def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")

def ed25519_verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """
    Verify Ed25519 signature:
    - pubkey: 32 bytes
    - sig: 64 bytes (R||S)
    """
    if len(pubkey) != 32 or len(sig) != 64:
        return False

    R_enc = sig[:32]
    S = int.from_bytes(sig[32:], "little")
    if S >= _l:
        return False

    try:
        A = _decodepoint(pubkey)
        R = _decodepoint(R_enc)
    except Exception:
        return False

    h = _hint(R_enc + pubkey + msg) % _l

    # Check: [S]B = R + [h]A
    SB = _scalarmult(_B, S)
    hA = _scalarmult(A, h)
    R_plus_hA = _edwards(R, hA)
    return _encodepoint(SB) == _encodepoint(R_plus_hA)


# ==========================
# Verification logic
# ==========================

def compute_event_id(ev: Dict[str, Any]) -> str:
    body = dict(ev)
    body.pop("signature", None)
    # event_id must be computed over body WITHOUT signature AND without event_id itself?
    # OIP spec: event_id = SHA256(canonical(event_body_without_signature))
    # To avoid circularity, we exclude signature only; event_id should match the digest of the body
    # with event_id present only if issuer included it before hashing. That creates ambiguity.
    # Fail-closed: we enforce event_id is computed with event_id removed.
    body.pop("event_id", None)
    return sha256_hex(canonical_json(body))

def load_prev_event(chain_dir: str, prev_hash: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(chain_dir, f"{prev_hash}.json")
    if os.path.isfile(path):
        try:
            return load_json(path)
        except Exception:
            return None
    return None

def verify(ev: Dict[str, Any], oid: Dict[str, Any], prev: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    # schema checks
    ok, why = validate_oid(oid)
    if not ok:
        return "INCOMPLETE", f"OID schema: {why}"

    ok, why = validate_event(ev)
    if not ok:
        return "INCOMPLETE", f"Event schema: {why}"

    # status handling
    if oid["status"] == "REVOKED":
        return "REVOKED", "OID status is REVOKED"
    if oid["status"] != "ACTIVE":
        return "INVALID", f"OID status is not ACTIVE: {oid['status']}"

    # OID match
    if ev["oid"] != oid["oid"]:
        return "INVALID", "Event oid does not match provided OID"

    # firmware/model binding
    if ev["firmware_hash"] != oid["firmware_hash"]:
        return "INVALID", "firmware_hash mismatch (event vs OID)"

    if oid.get("model_hash") is not None:
        if ev.get("model_hash") != oid.get("model_hash"):
            return "INVALID", "model_hash mismatch (event vs OID)"

    # event_id recompute (fail-closed rule: must be computed with event_id removed)
    try:
        recomputed = compute_event_id(ev)
    except Exception as e:
        return "INVALID", f"event_id recompute failed: {e}"

    if ev["event_id"].lower() != recomputed.lower():
        return "INVALID", "event_id mismatch"

    # signature verify
    try:
        pubkey = parse_pubkey(oid["public_key"])
        sig = parse_signature(ev["signature"])
        body = dict(ev)
        body.pop("signature", None)
        body.pop("event_id", None)
        msg = canonical_json(body)
    except Exception as e:
        return "INCOMPLETE", f"Signature inputs invalid: {e}"

    if not ed25519_verify(pubkey, msg, sig):
        return "INVALID", "Invalid signature"

    # chain verification (optional)
    if prev is not None:
        # prev must validate too (basic), and link must match
        okp, whyp = validate_event(prev)
        if not okp:
            return "INCOMPLETE", f"Prev event schema: {whyp}"

        if ev["prev_event_hash"] is None:
            return "INVALID", "prev_event_hash is null but prev event provided"

        if prev["event_id"].lower() != ev["prev_event_hash"].lower():
            return "INVALID", "prev_event_hash does not match provided prev.event_id"

        # sequence monotonic
        if ev["sequence"] != int(prev["sequence"]) + 1:
            return "INVALID", "sequence is not prev.sequence + 1"

        # OID consistency (same chain)
        if prev["oid"] != ev["oid"]:
            return "INVALID", "prev event oid differs"

    return "VALID", "OK"


# ==========================
# CLI
# ==========================

EXIT = {"VALID": 0, "INVALID": 1, "REVOKED": 2, "INCOMPLETE": 3}

def cmd_verify(args: argparse.Namespace) -> int:
    try:
        ev = load_json(args.event)
        oid = load_json(args.oid)
    except Exception as e:
        print("INCOMPLETE")
        return EXIT["INCOMPLETE"]

    prev = None
    if args.prev:
        try:
            prev = load_json(args.prev)
        except Exception:
            prev = None
            print("INCOMPLETE")
            return EXIT["INCOMPLETE"]
    elif args.chain_dir:
        # If event references a prev hash, try to load it from chain dir as <hash>.json
        try:
            prev_hash = ev.get("prev_event_hash", None)
            if isinstance(prev_hash, str) and is_hex_64(prev_hash):
                prev = load_prev_event(args.chain_dir, prev_hash)
        except Exception:
            prev = None

    status, _why = verify(ev, oid, prev=prev)
    print(status)
    return EXIT[status]


def main() -> int:
    p = argparse.ArgumentParser(prog="oip_verify", description="OIP reference verifier (fail-closed).")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="Verify an OIP event against an OID (optional chain checks).")
    v.add_argument("--event", required=True, help="Path to event JSON")
    v.add_argument("--oid", required=True, help="Path to OID JSON")
    v.add_argument("--prev", required=False, help="Path to previous event JSON (optional)")
    v.add_argument("--chain-dir", required=False, help="Directory containing prev events named <event_id>.json")
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())


---


reference/emitter-cli/ per generare eventi firmati + calcolare event_id

chain/ generator + replay tool
