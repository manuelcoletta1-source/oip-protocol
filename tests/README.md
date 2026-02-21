# OIP Conformance Tests (v0.1)

This folder provides a minimal conformance suite for OIP v0.1 reference tools.

## Requirements
- Python 3.9+
- No external dependencies

## Run
From repo root:

```bash
python3 tests/run_tests.py

Expected output:

All tests PASS

Exit code 0


What is tested

VALID happy path: keygen -> OID -> emit -> verify

INVALID: event tamper after signing

INVALID: event_id mismatch

INVALID: chain break (prev hash mismatch)

INVALID: sequence mismatch

REVOKED: OID revoked

INCOMPLETE: missing fields / malformed JSON (fail-closed)

Replay prevention basis: identical event file should not overwrite chain entry


---

## 2) `tests/run_tests.py`
```python
#!/usr/bin/env python3
"""
OIP conformance runner (v0.1) — pure python, no external deps.

Runs reference emitter/verifier through subprocess, validates outcomes.

Exit:
- 0 if all tests pass
- 1 otherwise
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Any, Tuple, List

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EMIT = os.path.join(REPO_ROOT, "reference", "emitter-cli", "oip_emit.py")
VERIFY = os.path.join(REPO_ROOT, "reference", "verifier-cli", "oip_verify.py")


def run(cmd: List[str], cwd: str) -> Tuple[int, str, str]:
    p = subprocess.Popen(
        cmd, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True
    )
    out, err = p.communicate()
    return p.returncode, out.strip(), err.strip()


def read_json(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def write_json(path: str, obj: Dict[str, Any]) -> None:
    # keep it stable for tests (not necessarily canonical)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")


def assert_eq(got, exp, msg=""):
    if got != exp:
        raise AssertionError(f"{msg} expected={exp!r} got={got!r}")


def assert_true(cond, msg=""):
    if not cond:
        raise AssertionError(msg or "assert_true failed")


def test_valid_happy_path(tmp: str) -> None:
    keys = os.path.join(tmp, "keys.json")
    oid = os.path.join(tmp, "oid.json")
    event = os.path.join(tmp, "event.json")
    chain = os.path.join(tmp, "chain")

    rc, out, err = run([sys.executable, EMIT, "gen-key", "--out", keys], cwd=tmp)
    assert_eq(rc, 0, "gen-key")
    k = read_json(keys)
    assert_true("private_key_seed" in k and "public_key" in k, "keys fields missing")

    rc, out, err = run([
        sys.executable, EMIT, "make-oid",
        "--oid", "OID-ROBOT-0001",
        "--public-key-base64", k["public_key"],
        "--manufacturer-id", "ACME Robotics",
        "--firmware-hash", "e"*64,
        "--out", oid
    ], cwd=tmp)
    assert_eq(rc, 0, "make-oid")

    rc, out, err = run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "navigation_decision",
        "--risk-level", "R2",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--chain-dir", chain,
        "--out", event
    ], cwd=tmp)
    assert_eq(rc, 0, f"emit err={err}")

    rc, out, err = run([
        sys.executable, VERIFY, "verify",
        "--event", event,
        "--oid", oid,
        "--chain-dir", chain
    ], cwd=tmp)
    assert_eq(out, "VALID", f"verify should be VALID err={err}")
    assert_eq(rc, 0, "verify exit code VALID")


def test_invalid_tamper(tmp: str) -> None:
    keys = os.path.join(tmp, "keys.json")
    oid = os.path.join(tmp, "oid.json")
    event = os.path.join(tmp, "event.json")
    chain = os.path.join(tmp, "chain")

    # setup
    run([sys.executable, EMIT, "gen-key", "--out", keys], cwd=tmp)
    k = read_json(keys)
    run([
        sys.executable, EMIT, "make-oid",
        "--oid", "OID-ROBOT-0001",
        "--public-key-base64", k["public_key"],
        "--manufacturer-id", "ACME Robotics",
        "--firmware-hash", "e"*64,
        "--out", oid
    ], cwd=tmp)
    run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "navigation_decision",
        "--risk-level", "R2",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--chain-dir", chain,
        "--out", event
    ], cwd=tmp)

    ev = read_json(event)
    ev["action_type"] = "navigation_decision_TAMPERED"
    write_json(event, ev)

    rc, out, err = run([sys.executable, VERIFY, "verify", "--event", event, "--oid", oid, "--chain-dir", chain], cwd=tmp)
    assert_eq(out, "INVALID", "tampered event must be INVALID")
    assert_eq(rc, 1, "INVALID exit code")


def test_invalid_event_id_mismatch(tmp: str) -> None:
    keys = os.path.join(tmp, "keys.json")
    oid = os.path.join(tmp, "oid.json")
    event = os.path.join(tmp, "event.json")

    run([sys.executable, EMIT, "gen-key", "--out", keys], cwd=tmp)
    k = read_json(keys)
    run([
        sys.executable, EMIT, "make-oid",
        "--oid", "OID-ROBOT-0001",
        "--public-key-base64", k["public_key"],
        "--manufacturer-id", "ACME Robotics",
        "--firmware-hash", "e"*64,
        "--out", oid
    ], cwd=tmp)
    run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "navigation_decision",
        "--risk-level", "R2",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--out", event
    ], cwd=tmp)

    ev = read_json(event)
    ev["event_id"] = "a"*64
    write_json(event, ev)

    rc, out, err = run([sys.executable, VERIFY, "verify", "--event", event, "--oid", oid], cwd=tmp)
    assert_eq(out, "INVALID", "event_id mismatch must be INVALID")
    assert_eq(rc, 1, "INVALID exit code")


def test_chain_break_prev_hash(tmp: str) -> None:
    keys = os.path.join(tmp, "keys.json")
    oid = os.path.join(tmp, "oid.json")
    e1 = os.path.join(tmp, "e1.json")
    e2 = os.path.join(tmp, "e2.json")
    chain = os.path.join(tmp, "chain")

    run([sys.executable, EMIT, "gen-key", "--out", keys], cwd=tmp)
    k = read_json(keys)
    run([
        sys.executable, EMIT, "make-oid",
        "--oid", "OID-ROBOT-0001",
        "--public-key-base64", k["public_key"],
        "--manufacturer-id", "ACME Robotics",
        "--firmware-hash", "e"*64,
        "--out", oid
    ], cwd=tmp)

    # emit first and save chain
    run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "a",
        "--risk-level", "R1",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--chain-dir", chain,
        "--out", e1
    ], cwd=tmp)

    # emit second (auto links)
    run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "b",
        "--risk-level", "R1",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--chain-dir", chain,
        "--out", e2
    ], cwd=tmp)

    ev2 = read_json(e2)
    ev2["prev_event_hash"] = "f"*64
    write_json(e2, ev2)

    rc, out, err = run([sys.executable, VERIFY, "verify", "--event", e2, "--oid", oid, "--chain-dir", chain], cwd=tmp)
    assert_eq(out, "INVALID", "broken prev hash must be INVALID")
    assert_eq(rc, 1, "INVALID exit code")


def test_chain_break_sequence(tmp: str) -> None:
    keys = os.path.join(tmp, "keys.json")
    oid = os.path.join(tmp, "oid.json")
    e1 = os.path.join(tmp, "e1.json")
    e2 = os.path.join(tmp, "e2.json")
    chain = os.path.join(tmp, "chain")

    run([sys.executable, EMIT, "gen-key", "--out", keys], cwd=tmp)
    k = read_json(keys)
    run([
        sys.executable, EMIT, "make-oid",
        "--oid", "OID-ROBOT-0001",
        "--public-key-base64", k["public_key"],
        "--manufacturer-id", "ACME Robotics",
        "--firmware-hash", "e"*64,
        "--out", oid
    ], cwd=tmp)

    run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "a",
        "--risk-level", "R1",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--chain-dir", chain,
        "--out", e1
    ], cwd=tmp)

    run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "b",
        "--risk-level", "R1",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--chain-dir", chain,
        "--out", e2
    ], cwd=tmp)

    ev2 = read_json(e2)
    ev2["sequence"] = 999
    write_json(e2, ev2)

    rc, out, err = run([sys.executable, VERIFY, "verify", "--event", e2, "--oid", oid, "--chain-dir", chain], cwd=tmp)
    assert_eq(out, "INVALID", "sequence mismatch must be INVALID")
    assert_eq(rc, 1, "INVALID exit code")


def test_revoked_oid(tmp: str) -> None:
    keys = os.path.join(tmp, "keys.json")
    oid = os.path.join(tmp, "oid.json")
    event = os.path.join(tmp, "event.json")

    run([sys.executable, EMIT, "gen-key", "--out", keys], cwd=tmp)
    k = read_json(keys)
    run([
        sys.executable, EMIT, "make-oid",
        "--oid", "OID-ROBOT-0001",
        "--public-key-base64", k["public_key"],
        "--manufacturer-id", "ACME Robotics",
        "--firmware-hash", "e"*64,
        "--out", oid
    ], cwd=tmp)

    # revoke OID
    o = read_json(oid)
    o["status"] = "REVOKED"
    write_json(oid, o)

    # create an event anyway (emitter should refuse? emitter checks ACTIVE; so emit will fail.
    # We'll create a valid event first using ACTIVE OID then revoke before verification.
    o["status"] = "ACTIVE"
    write_json(oid, o)
    run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "x",
        "--risk-level", "R1",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--out", event
    ], cwd=tmp)

    o["status"] = "REVOKED"
    write_json(oid, o)

    rc, out, err = run([sys.executable, VERIFY, "verify", "--event", event, "--oid", oid], cwd=tmp)
    assert_eq(out, "REVOKED", "revoked OID must yield REVOKED")
    assert_eq(rc, 2, "REVOKED exit code")


def test_incomplete_missing_fields(tmp: str) -> None:
    oid = os.path.join(tmp, "oid.json")
    event = os.path.join(tmp, "event.json")

    write_json(oid, {"oid": "OID-ROBOT-0001"})  # missing required fields
    write_json(event, {"event_id": "a"*64})     # missing required fields

    rc, out, err = run([sys.executable, VERIFY, "verify", "--event", event, "--oid", oid], cwd=tmp)
    assert_eq(out, "INCOMPLETE", "missing fields must be INCOMPLETE")
    assert_eq(rc, 3, "INCOMPLETE exit code")


def test_emitter_no_overwrite_chain(tmp: str) -> None:
    keys = os.path.join(tmp, "keys.json")
    oid = os.path.join(tmp, "oid.json")
    event = os.path.join(tmp, "event.json")
    chain = os.path.join(tmp, "chain")

    run([sys.executable, EMIT, "gen-key", "--out", keys], cwd=tmp)
    k = read_json(keys)

    run([
        sys.executable, EMIT, "make-oid",
        "--oid", "OID-ROBOT-0001",
        "--public-key-base64", k["public_key"],
        "--manufacturer-id", "ACME Robotics",
        "--firmware-hash", "e"*64,
        "--out", oid
    ], cwd=tmp)

    rc, out, err = run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "a",
        "--risk-level", "R1",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--chain-dir", chain,
        "--timestamp", "2026-02-21T10:00:00Z",
        "--sequence", "1",
        "--out", event
    ], cwd=tmp)
    assert_eq(rc, 0, f"emit #1 err={err}")

    # re-emit identical by forcing same timestamp/sequence but will still compute same event_id,
    # hence overwrite attempt must fail-closed.
    rc, out, err = run([
        sys.executable, EMIT, "emit",
        "--oid-json", oid,
        "--private-key-seed-base64", k["private_key_seed"],
        "--action-type", "a",
        "--risk-level", "R1",
        "--input-digest", "b"*64,
        "--decision-digest", "c"*64,
        "--state-digest", "d"*64,
        "--chain-dir", chain,
        "--timestamp", "2026-02-21T10:00:00Z",
        "--sequence", "1",
        "--out", event
    ], cwd=tmp)
    assert_true(rc != 0, "second emit should fail due to overwrite refusal")
    assert_true("Refusing to overwrite" in err, "expected overwrite refusal message")


def main() -> int:
    tests = [
        ("valid_happy_path", test_valid_happy_path),
        ("invalid_tamper", test_invalid_tamper),
        ("invalid_event_id_mismatch", test_invalid_event_id_mismatch),
        ("chain_break_prev_hash", test_chain_break_prev_hash),
        ("chain_break_sequence", test_chain_break_sequence),
        ("revoked_oid", test_revoked_oid),
        ("incomplete_missing_fields", test_incomplete_missing_fields),
        ("emitter_no_overwrite_chain", test_emitter_no_overwrite_chain),
    ]

    failures = 0
    with tempfile.TemporaryDirectory(prefix="oip-tests-") as tmp:
        for name, fn in tests:
            case_dir = os.path.join(tmp, name)
            os.makedirs(case_dir, exist_ok=True)
            try:
                fn(case_dir)
                print(f"[PASS] {name}")
            except Exception as e:
                failures += 1
                print(f"[FAIL] {name}: {e}")

    if failures == 0:
        print("ALL TESTS PASSED")
        return 0
    print(f"{failures} TEST(S) FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())


---


SPEC patch: chiarire formalmente che event_id esclude event_id e signature (adesso lo applichiamo nel codice; lo standard deve dirlo esplicito)

oip_verify.py patch “strict mode” vs “compat mode” (ma possiamo restare strict)
