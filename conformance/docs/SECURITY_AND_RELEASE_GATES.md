# Security evidence and release gates

The **official test-suite package** and a **production implementation** have separate release criteria.

## 1. Suite integrity

The fixture verifier validates checksums, JSON schemas, mathematical consistency, requirement coverage, semantic test minima, and complete inventory. The runner's own negative tests ensure known broken bridges do not receive an automated pass. The repository CI checks the suite; its success does **not** certify other libraries.

Pin the official suite to an immutable trusted commit or release digest. `SHA256SUMS` detects accidental modification only, not malicious substitution.

## 2. Automated implementation checks

Each implementation provides a JSON-Lines bridge to its **real public methods**. Run `run_adapter.py --automated-only -- <adapter-command>` for automated conformance checks. Exit `0` means the automated layer passed, **not full conformance**. Mandatory, applicable conditional, and fault-injection tests (when supported) must not be silently skipped.

## 3. Independent CSPRNG review

Inspect the implementation at an exact immutable commit and confirm:

- Every production generation path obtains 12 fresh bytes from a cryptographically secure system/runtime source.
- Entropy-source failure aborts generation without predictable fallback, truncated randomness, or partial output.
- Timestamp collection and bounds are correct.
- Supported optional generation APIs preserve these requirements.

Use `schemas/security-evidence.schema.json` to record the reviewer, implementation identity and commit, suite/spec revisions, UTC review date, and evidence for **both** required checks. Evidence uses **repository-relative paths and line ranges**; no hosting provider, implementation language, or external repository URL is imposed.

The following is **illustrative structure only, not a genuine security review**:

```json
{
  "format": "pikaid-csprng-review-v1",
  "implementation_id": "example/identifier-library",
  "implementation_commit": "0123456789abcdef0123456789abcdef01234567",
  "spec_revision": "1.0.4",
  "suite_revision": "1.0.0",
  "reviewed_at_utc": "2026-11-09T08:00:00Z",
  "reviewer": "independent-reviewer",
  "checks": [
    {"id": "P-GENERATE-RNG-SOURCE", "result": "PASS", "evidence": [{"path": "src/generator.ext", "line_start": 12, "line_end": 35}]},
    {"id": "P-GENERATE-RNG-FAILURE", "result": "PASS", "evidence": [{"path": "tests/generator_test.ext", "line_start": 20, "line_end": 44}]}
  ]
}
```

Run the common runner with `--security-evidence /path/to/review.json --implementation-commit <full-40-character-commit> -- <adapter-command>`. The runner validates the evidence **record**, not whether its author's identity or assertions are genuine. Review the source locations at the pinned commit and approve the evidence through the consuming repository's protected release process.

## 4. Meaning of exit codes

| Code | Meaning |
| --- | --- |
| `0` | Automated checks passed in explicitly non-certifying mode, or a matching security evidence record was supplied. Read the structured report to distinguish. |
| `1` | Automated conformance assertion failed. |
| `2` | Fixture package, adapter protocol, or evidence record was untrustworthy. |
| `3` | Automated checks passed but required manual security evidence is outstanding (default). |

**Full certification requires more than exit `0`**: successful applicable tests, the correct pinned suite, an independently approved security review for that exact implementation commit, and a protected release gate. A sample bridge, unsigned JSON evidence record, or unreviewed CI success is insufficient. Testing cannot prove the absence of all future bugs.
