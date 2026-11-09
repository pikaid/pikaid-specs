# Implementation adapter contract

The canonical PikaID specification defines behavior, not common public method names. Every implementation may use idiomatic APIs. To run the official conformance suite, provide a test-only adapter implementing the [JSON-Lines protocol](JSONL_ADAPTER_PROTOCOL.md) and delegating to the real implementation.

## Mandatory behavior

- Generate canonical lowercase 26-character identifiers with a whole-second UTC Unix timestamp and 12 fresh CSPRNG bytes.
- Strictly convert canonical text to exactly 17 binary bytes and back; preserve all bits and leading zeroes.
- Reject malformed or out-of-range input without silent coercion or truncation.
- Preserve canonical text and unsigned bytewise binary ordering.
- Distinguish invalid-input rejections from unexpected internal failures.
- Do not perform substitute encoding, generation, validation, or randomness production inside the adapter to hide defects in the implementation.

The bridge advertises `generate_string`, `text_to_binary`, and `binary_to_text`. Other capabilities are conditional and may be advertised **only when the underlying implementation actually supports them**.

## Conditional behavior

If supported, the runner also checks full boolean validation, shape-only validation, parsing, UTC datetime conversion, caller-supplied timestamp generation, direct binary generation, and a public comparator. `csprng_failure_injection` is an optional *test-only* bridge capability, not a required production public API.

`parse_components` must expose the exact timestamp and 12 randomness bytes. The JSON wire protocol represents randomness as **24 lowercase hexadecimal digits**, even if the implementation uses a different in-memory representation. Claim `parse_datetime` only if a correct UTC datetime can be returned for every applicable tested value.

## Execution expectations

Test each supported runtime, configuration, and relevant conversion backend. Do not report missing mandatory operations as optional or claim an optional public feature is absent when it is actually available. Keep library-specific tests in the implementation's own repository.

The suite's self-tests in `tools/tests/` check the common verification machinery. They **do not certify any downstream library**. Full implementation conformity additionally requires independently approved CSPRNG source and failure-path evidence as described in [Security and release gates](SECURITY_AND_RELEASE_GATES.md).
