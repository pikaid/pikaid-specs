# PikaID official conformance suite

**Status: OFFICIAL | Suite revision: 1.0.0 | Specification revision: 1.0.4**

This is the **language-independent** test suite for the immutable, unversioned PikaID identifier format. The canonical specification is the repository root [`README.md`](../README.md). The test-suite version is not an identifier format version.

The included example exercises the test **protocol**, not a production library.

## Contents

- `cases/`: canonical conversions, invalid inputs, ordering, generation cases, and executable properties.
- `schemas/`: machine-readable fixture and security-evidence contracts.
- `manifest.json`, `requirements.json`: official package identity, fixture inventory, and specification traceability.
- `tools/verify_vectors.py`: checksum, schema, mathematical, and semantic fixture verification.
- `tools/verify_oracle_node.mjs`: independent BigInt cross-check of deterministic vectors.
- `tools/run_adapter.py`: common conformance runner for any language-specific bridge.
- `tools/examples/reference_bridge.py`: **test-only demonstration bridge** (not a library certification).
- `tools/tests/`: regression tests for the validators and runner, including deliberately incorrect bridges.
- `docs/`: adapter contract, protocol, requirement coverage, and security/release policy.
- `LICENSE`, `SHA256SUMS`: redistribution terms and accidental-corruption detection.

## Check the official suite itself

Requires **Python 3.11+** and **Node.js** for the independent second-language mathematical check. From `conformance/`:

```sh
python3 -m pip install -r tools/requirements.txt
python3 tools/verify_vectors.py --expect-status OFFICIAL --expect-package-revision 1.0.0 --expect-spec-revision 1.0.4
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/tests -v
node tools/verify_oracle_node.mjs
```

The repository's `.github/workflows/conformance.yml` runs these package checks in CI. `SHA256SUMS` detects accidental modification but does not authenticate a distribution; consuming projects should pin an immutable trusted commit or release digest.

## Test an implementation

Each implementation supplies a small test-only JSON-Lines adapter that **delegates to its real public library functions**. No identical public function names or production services are required across languages. Follow [`docs/ADAPTER_CONTRACT.md`](docs/ADAPTER_CONTRACT.md) and [`docs/JSONL_ADAPTER_PROTOCOL.md`](docs/JSONL_ADAPTER_PROTOCOL.md).

For illustration only, check the common runner with its demonstration bridge:

```sh
python3 tools/run_adapter.py --automated-only -- python3 tools/examples/reference_bridge.py
```

To test a real implementation, replace the command after `--` with its adapter process. The command above validates **only the runner**, not any production implementation.

The runner returns `0` when automated cases pass with explicit `--automated-only`, `1` for failed assertions, `2` for untrusted fixtures or protocol, and `3` when mandatory manual security evidence is outstanding (default). Automated success **must not** be presented as a full conformance certification. See [`docs/SECURITY_AND_RELEASE_GATES.md`](docs/SECURITY_AND_RELEASE_GATES.md).

## Scope and release rules

All mandatory cases and applicable conditional properties must pass. A conditional capability must not be hidden if the implementation exposes it. Mandatory tests, minimum trial counts, and security obligations must not be downgraded to obtain a pass.

Production CSPRNG use and failure behavior require independent source review tied to the exact implementation commit; output sampling alone cannot certify randomness security. The runner records structured, hosting-independent source locations but cannot authenticate a reviewer or attest that a review occurred. Enforce independent approval in the implementation's protected release process.

The suite may evolve without changing the immutable PikaID identifier format. Maintain a pinned suite version in each implementation's CI. A passing demonstration adapter is never a substitute for testing the actual implementation.
