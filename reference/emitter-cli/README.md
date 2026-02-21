# OIP Emitter CLI (Reference)

Reference CLI to generate:
- Ed25519 keypairs
- OID (Operational Identity) objects
- Signed OIP events (AEO) with deterministic `event_id`

## Requirements
- Python 3.9+ (no external dependencies)

## Commands

### 1) Generate an Ed25519 keypair (seed + public key)
```bash
python3 oip_emit.py gen-key --out keys.json

Output format:

private_key_seed (32 bytes) in base64

public_key (32 bytes) in base64


2) Create an OID (Operational Identity Object)

python3 oip_emit.py make-oid \
  --oid OID-ROBOT-0001 \
  --public-key-base64 "<BASE64_PUBKEY>" \
  --manufacturer-id "ACME Robotics" \
  --firmware-hash "<SHA256_HEX>" \
  --model-hash "<SHA256_HEX>" \
  --out oid.json

--model-hash is optional.

3) Emit a signed OIP event

python3 oip_emit.py emit \
  --oid-json oid.json \
  --private-key-seed-base64 "<BASE64_SEED>" \
  --action-type navigation_decision \
  --risk-level R2 \
  --input-digest "<SHA256_HEX>" \
  --decision-digest "<SHA256_HEX>" \
  --state-digest "<SHA256_HEX>" \
  --chain-dir ./chain \
  --out event.json

Behavior:

If --chain-dir is provided, the emitter searches for the last event for the same oid, then sets prev_event_hash and sequence automatically (append-only).

Events are saved in --chain-dir as <event_id>.json.


Determinism Rules

Canonical JSON encoding: sorted keys, no whitespace, UTF-8.

Floats / NaN / Infinity are rejected (fail-closed).

event_id is computed over the canonical event body without event_id and signature.

The signature is over the same canonical body (without event_id and signature).


This matches the reference verifier implementation.

---

## 2) `reference/emitter-cli/oip_emit.py`
```python
#!/usr/bin/env python3
"""
OIP Emitter CLI (Reference) — pure Python, deterministic, fail-closed.

Provides:
- gen-key: Ed25519 key generation (seed + public key)
- make-oid: create an OID JSON object
- emit: create a signed OIP Action Event Object (AEO), compute event_id, save to chain dir

Design constraints:
- No external dependencies
- Deterministic canonical JSON
- Fail-closed on non-deterministic JSON inputs
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, List


# ==========================
# Deterministic JSON
# ==========================

def _reject_nondeterministic_json(x: Any, path: str = "$") -> None:
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
    _reject_nondeterministic_json(obj)
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        raw = f.read()
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"Top-level JSON must be an object: {path}")
    return obj


def write_json(path: str, obj: Dict[str, Any]) -> None:
    data = canonical_json(obj)
    with open(path, "wb") as f:
        f.write(data)
        f.write(b"\n")


# ==========================
# Ed25519 (pure python reference)
# - keygen from 32-byte seed
# - sign (deterministic)
# ==========================

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

def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")

def _encodeint(i: int) -> bytes:
    return int.to_bytes(i, 32, "little")

def _clamp_scalar(h: bytes) -> int:
    # h is sha512(seed); first 32 bytes used for scalar with clamping
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 63
    a[31] |= 64
    return _decodeint(bytes(a))

def ed25519_public_key_from_seed(seed32: bytes) -> bytes:
    h = hashlib.sha512(seed32).digest()
    a = _clamp_scalar(h)
    A = _scalarmult(_B, a)
    return _encodepoint(A)

def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")

def ed25519_sign(seed32: bytes, msg: bytes) -> bytes:
    """
    Ed25519 deterministic signing from 32-byte seed.
    Returns 64-byte signature (R || S).
    """
    h = hashlib.sha512(seed32).digest()
    a = _clamp_scalar(h)
    prefix = h[32:]  # second half
    r = _hint(prefix + msg) % _l
    R = _scalarmult(_B, r)
    R_enc = _encodepoint(R)
    A_enc = ed25519_public_key_from_seed(seed32)
    k = _hint(R_enc + A_enc + msg) % _l
    S = (r + k * a) % _l
    return R_enc + _encodeint(S)

def parse_seed(seed_str: str) -> bytes:
    """
    Accepts:
    - hex (32 bytes -> 64 hex chars)
    - base64 (32 bytes)
    """
    s = seed_str.strip()
    if len(s) == 64:
        try:
            b = bytes.fromhex(s)
            if len(b) == 32:
                return b
        except Exception:
            pass
    try:
        b = base64.b64decode(s, validate=True)
        if len(b) == 32:
            return b
    except Exception:
        pass
    raise ValueError("private_key_seed must be 32 bytes (hex64 or base64)")

def parse_pubkey(pubkey_str: str) -> bytes:
    s = pubkey_str.strip()
    if len(s) == 64:
        try:
            b = bytes.fromhex(s)
            if len(b) == 32:
                return b
        except Exception:
            pass
    try:
        b = base64.b64decode(s, validate=True)
        if len(b) == 32:
            return b
    except Exception:
        pass
    raise ValueError("public_key must be 32 bytes (hex64 or base64)")

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# ==========================
# Chain helpers
# ==========================

def list_chain_events(chain_dir: str) -> List[str]:
    if not os.path.isdir(chain_dir):
        return []
    files = []
    for name in os.listdir(chain_dir):
        if name.endswith(".json") and len(name) == 69:  # 64 hex + ".json"
            base = name[:-5]
            if is_hex_64(base):
                files.append(os.path.join(chain_dir, name))
    return files

def find_last_event_for_oid(chain_dir: str, oid_str: str) -> Optional[Dict[str, Any]]:
    """
    Scan chain directory and return the event with max sequence for this oid.
    Fail-closed: if parsing fails, skip file; if multiple with same seq, pick lexicographically highest event_id.
    """
    best = None
    best_seq = -1
    best_id = ""
    for p in list_chain_events(chain_dir):
        try:
            ev = load_json(p)
        except Exception:
            continue
        if not isinstance(ev, dict):
            continue
        if ev.get("oid") != oid_str:
            continue
        seq = ev.get("sequence")
        eid = ev.get("event_id")
        if not isinstance(seq, int) or not isinstance(eid, str):
            continue
        if seq > best_seq or (seq == best_seq and eid > best_id):
            best = ev
            best_seq = seq
            best_id = eid
    return best


# ==========================
# OIP event construction (deterministic)
# ==========================

def compute_event_id(event_body_without_event_id_and_signature: Dict[str, Any]) -> str:
    return sha256_hex(canonical_json(event_body_without_event_id_and_signature))

def sign_event_body(seed32: bytes, body: Dict[str, Any]) -> str:
    msg = canonical_json(body)
    sig = ed25519_sign(seed32, msg)
    return b64(sig)

def build_oid(args: argparse.Namespace) -> Dict[str, Any]:
    if not is_hex_64(args.firmware_hash):
        raise ValueError("firmware-hash must be sha256 hex (64 chars)")
    if args.model_hash is not None and not is_hex_64(args.model_hash):
        raise ValueError("model-hash must be sha256 hex (64 chars)")

    pk = parse_pubkey(args.public_key_base64)  # accepts base64 or hex
    oid = {
        "oid": args.oid,
        "public_key": b64(pk),  # normalize to base64 in outputs
        "manufacturer_id": args.manufacturer_id,
        "firmware_hash": args.firmware_hash.lower(),
        "model_hash": args.model_hash.lower() if args.model_hash else None,
        "created_at": args.created_at or now_iso_utc(),
        "status": "ACTIVE",
    }
    return oid

def build_event(args: argparse.Namespace, oid: Dict[str, Any], prev: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if args.risk_level not in ("R0","R1","R2","R3","R4","R5"):
        raise ValueError("risk-level must be R0..R5")
    for name, val in (
        ("input-digest", args.input_digest),
        ("decision-digest", args.decision_digest),
        ("state-digest", args.state_digest),
    ):
        if not is_hex_64(val):
            raise ValueError(f"{name} must be sha256 hex (64 chars)")

    # derive prev + sequence
    if prev is None:
        prev_hash = None
        sequence = args.sequence if args.sequence else 1
    else:
        prev_hash = prev.get("event_id")
        if not is_hex_64(prev_hash):
            raise ValueError("prev event_id invalid in chain")
        sequence = int(prev.get("sequence", 0)) + 1

    if args.sequence is not None:
        # fail-closed: if user forces sequence and it disagrees with computed chain sequence, reject
        if prev is not None and args.sequence != sequence:
            raise ValueError("provided --sequence conflicts with chain-derived sequence")
        sequence = args.sequence

    timestamp = args.timestamp or now_iso_utc()

    # event body used for event_id/signature MUST NOT include event_id/signature
    body = {
        "oid": oid["oid"],
        "timestamp": timestamp,
        "sequence": sequence,
        "prev_event_hash": prev_hash,
        "action_type": args.action_type,
        "risk_level": args.risk_level,
        "input_digest": args.input_digest.lower(),
        "decision_digest": args.decision_digest.lower(),
        "state_digest": args.state_digest.lower(),
        "firmware_hash": oid["firmware_hash"],
        "model_hash": oid.get("model_hash", None),
    }

    event_id = compute_event_id(body)

    seed32 = parse_seed(args.private_key_seed_base64)
    # normalize: ensure the seed's derived public key matches OID public key
    derived_pk = ed25519_public_key_from_seed(seed32)
    oid_pk = parse_pubkey(oid["public_key"])
    if derived_pk != oid_pk:
        raise ValueError("private key seed does not match OID public_key (fail-closed)")

    signature_b64 = sign_event_body(seed32, body)

    event = dict(body)
    event["event_id"] = event_id
    event["signature"] = signature_b64
    return event


# ==========================
# CLI commands
# ==========================

def cmd_gen_key(args: argparse.Namespace) -> int:
    seed32 = secrets.token_bytes(32)
    pub = ed25519_public_key_from_seed(seed32)
    out = {
        "private_key_seed": b64(seed32),
        "public_key": b64(pub)
    }
    if args.out:
        write_json(args.out, out)
    else:
        sys.stdout.buffer.write(canonical_json(out) + b"\n")
    return 0

def cmd_make_oid(args: argparse.Namespace) -> int:
    oid = build_oid(args)
    if args.out:
        write_json(args.out, oid)
    else:
        sys.stdout.buffer.write(canonical_json(oid) + b"\n")
    return 0

def cmd_emit(args: argparse.Namespace) -> int:
    oid = load_json(args.oid_json)

    # basic minimal checks (fail-closed)
    if oid.get("status") != "ACTIVE":
        raise ValueError("OID status must be ACTIVE to emit events")
    if not isinstance(oid.get("oid"), str):
        raise ValueError("OID.oid missing/invalid")
    if not isinstance(oid.get("public_key"), str):
        raise ValueError("OID.public_key missing/invalid")
    if not is_hex_64(oid.get("firmware_hash")):
        raise ValueError("OID.firmware_hash missing/invalid")

    prev = None
    if args.prev_event_json:
        prev = load_json(args.prev_event_json)
    elif args.chain_dir:
        prev = find_last_event_for_oid(args.chain_dir, oid["oid"])

    event = build_event(args, oid, prev)

    # output
    if args.out:
        write_json(args.out, event)
    else:
        sys.stdout.buffer.write(canonical_json(event) + b"\n")

    # chain save
    if args.chain_dir:
        os.makedirs(args.chain_dir, exist_ok=True)
        path = os.path.join(args.chain_dir, f"{event['event_id']}.json")
        # fail-closed: do not overwrite
        if os.path.exists(path):
            raise ValueError(f"Refusing to overwrite existing chain event: {path}")
        write_json(path, event)

    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="oip_emit", description="OIP reference emitter (deterministic, fail-closed).")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-key", help="Generate Ed25519 keypair (seed + public key).")
    g.add_argument("--out", required=False, help="Write keys JSON to file.")
    g.set_defaults(func=cmd_gen_key)

    m = sub.add_parser("make-oid", help="Create an OID JSON object.")
    m.add_argument("--oid", required=True, help="OID identifier (string).")
    m.add_argument("--public-key-base64", required=True, help="Ed25519 public key (base64 or hex64).")
    m.add_argument("--manufacturer-id", required=True, help="Manufacturer/vendor identifier.")
    m.add_argument("--firmware-hash", required=True, help="SHA-256 hex digest of firmware/runtime.")
    m.add_argument("--model-hash", required=False, default=None, help="SHA-256 hex digest of AI model (optional).")
    m.add_argument("--created-at", required=False, default=None, help="ISO8601 timestamp (default now UTC).")
    m.add_argument("--out", required=False, help="Write OID JSON to file.")
    m.set_defaults(func=cmd_make_oid)

    e = sub.add_parser("emit", help="Emit a signed OIP event (AEO).")
    e.add_argument("--oid-json", required=True, help="Path to OID JSON.")
    e.add_argument("--private-key-seed-base64", required=True, help="Ed25519 private key seed (base64 or hex64).")
    e.add_argument("--action-type", required=True, help="Action type (string).")
    e.add_argument("--risk-level", required=True, help="Risk level R0..R5.")
    e.add_argument("--input-digest", required=True, help="SHA-256 hex digest of input snapshot/bundle.")
    e.add_argument("--decision-digest", required=True, help="SHA-256 hex digest of decision artifact.")
    e.add_argument("--state-digest", required=True, help="SHA-256 hex digest of minimal state snapshot.")
    e.add_argument("--timestamp", required=False, default=None, help="ISO8601 timestamp (default now UTC).")
    e.add_argument("--sequence", required=False, type=int, default=None, help="Force sequence (fail-closed if conflicts).")
    e.add_argument("--prev-event-json", required=False, default=None, help="Path to previous event JSON.")
    e.add_argument("--chain-dir", required=False, default=None, help="Chain directory (auto prev lookup + save).")
    e.add_argument("--out", required=False, default=None, help="Write event JSON to file.")
    e.set_defaults(func=cmd_emit)

    args = p.parse_args()
    try:
        return args.func(args)
    except Exception as ex:
        # Fail-closed error reporting: emit to stderr; exit non-zero
        sys.stderr.write(f"ERROR: {ex}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())


---

