# Normative requirement traceability

These local IDs map to canonical PikaID specification revision **1.0.4**, not new public API names. Counts are **fixture references**, not proof a real implementation has passed.

| Requirement | Level | Spec section | Fixture references | Verification approach |
| --- | --- | --- | ---: | --- |
| `FMT-001` | MUST | §2(1), 1 | 687 | valid_vectors, invalid_string_vectors, runtime_generation |
| `FMT-002` | MUST | §2(1-2), 1 | 684 | valid_vectors, invalid_string_vectors |
| `FMT-003` | MUST | §2(2), 3.1 | 597 | valid_vectors, round_trip_properties |
| `TS-001` | MUST | §2(3), 3.1 | 606 | valid_vectors, runtime_generation, conditional_timestamp_injection, code_review |
| `RNG-001` | MUST | §2(4), 3.1 | 4 | runtime_generation, code_review, fault_injection |
| `BIN-001` | MUST | §2(5), 3.2 | 820 | valid_vectors, invalid_binary_vectors, ordering_vectors, round_trip_properties |
| `VAL-001` | MUST | §4(1-4) | 852 | valid_vectors, invalid_string_vectors |
| `VAL-002` | MUST | §2(6), 3.2, 4 | 295 | invalid_string_vectors, invalid_binary_vectors, round_trip_properties |
| `PARSE-001` | CONDITIONAL_MUST | §4 | 598 | valid_vectors, conditional_parse |
| `ORDER-001` | MUST | §5 | 188 | ordering_vectors, round_trip_properties |
| `PRED-001` | CONDITIONAL_MAY | §4 | 1 | invalid_string_vectors, valid_vectors |
| `SHAPE-001` | CONDITIONAL_MAY | §4 | 1 | invalid_string_vectors |
| `GENT-001` | CONDITIONAL_MUST | §2 final paragraph | 11 | conditional_timestamp_injection, code_review |
| `GENB-001` | CONDITIONAL_MAY | §3.2 | 5 | runtime_generation |
| `SEC-001` | SHOULD | §6 | 0 | documentation_review |
| `IMM-001` | MUST | §9 | 5 | valid_vectors, invalid_string_vectors, invalid_binary_vectors, specification_governance_review |

## Interpretation

- Every canonical MUST/MUST NOT in the specification remains authoritative. A schema check does not prove runtime behavior.
- `RNG-001` requires both automated generation checks and independent inspection of the cryptographic source/failure path.
- `IMM-001` covers the unversioned, immutable format in §9. Version-prefixed examples are rejected, while actual specification immutability also requires maintainer review of future changes.
- `PARSE-001` and `GENT-001` are conditional obligations if the corresponding convenience APIs exist; they do not impose language-specific method names.
- `SEC-001` is guidance to consuming applications, not a library requirement to guarantee database uniqueness or authorization.
- A 7-character Base36 timestamp cannot exceed `36^7 - 1`; binary timestamps are still rejected if they exceed that cap. Randomness can overflow 96 bits despite matching 19-character Base36 shape.
- The deterministic corpus is boundary-biased and does not test statistical uniformity of production randomness.
