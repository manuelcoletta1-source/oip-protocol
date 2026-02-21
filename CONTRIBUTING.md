# Contributing to OIP

Thank you for contributing to the Operational Identity Protocol.

OIP aims to remain:
- minimal
- deterministic
- implementation-neutral
- vendor-neutral

## Contribution Principles

1. Determinism First  
   Any change MUST preserve deterministic verification.

2. Fail-Closed  
   Ambiguity must result in INVALID or INCOMPLETE, never implicit acceptance.

3. Minimalism  
   The protocol must remain small and portable.

4. Backward Compatibility  
   Changes affecting interoperability require MAJOR version increment.

---

## How to Contribute

1. Fork the repository.
2. Create a branch.
3. Add tests for any behavioral change.
4. Ensure `tests/run_tests.py` passes.
5. Open a pull request with:
   - clear problem statement
   - rationale
   - compatibility impact

---

## Proposal Categories

- Spec clarification
- Security hardening
- Interoperability improvements
- Reference implementation improvements

Large scope expansions (e.g., policy layers, registry logic, governance logic) are out of scope for OIP core.

---

## Review Process

Pull requests require:
- passing conformance tests
- deterministic behavior verification
- no introduction of non-deterministic constructs

Security-impacting changes should be disclosed responsibly before public merge.
