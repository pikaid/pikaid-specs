# PikaID JSON-Lines adapter protocol (v1)

**Wire contract:** each implementation supplies a one-time test-only bridge that calls its real library. No production service, cross-language public naming rule, or additional runtime dependency is mandated by PikaID itself.

## Invocation and trust model

```sh
python3 tools/run_adapter.py --automated-only -- <adapter-command> [adapter-arguments]
```

The bridge is launched by the common runner. It reads one UTF-8 JSON object per line on stdin, writes exactly one JSON object per request to stdout (flushed), and writes diagnostic logs only to stderr. It must not compute alternate PikaID results that hide defects in the library under test.

The runner accepts a process command only after `--` and applies a per-response timeout. Unknown or missing required capabilities, malformed responses, timeouts and missing fixtures fail.

## Capability negotiation

```json
{"request_id":1,"operation":"hello","arguments":{}}
```

```json
{"request_id":1,"ok":true,"value":{"protocol_version":1,"capabilities":["generate_string","text_to_binary","binary_to_text"]}}
```

**Required adapter operations:** `generate_string`, `text_to_binary`, `binary_to_text`.

**Optional operations:** `boolean_validation`, `format_only_validation`, `parse_components`, `parse_datetime`, `generate_with_timestamp`, `generate_binary`, `generate_binary_with_timestamp`, `public_compare`, `csprng_failure_injection`.

`parse_datetime` is a capability claim about the `parse_components` result, **not** a separate operation. If advertised, `parse_components` must also be advertised and every successful parsing result must include `datetime_utc`. If not offered, datetime testing is `not_applicable`. An adapter that returns a datetime anyway must make it correct.

`csprng_failure_injection` is a test-only capability; if advertised it enables `inject_fault`. Never add a mandatory public API solely for this testing hook.

## Operations

| Operation | Arguments | `value` on success |
| --- | --- | --- |
| `generate_string` | `{}` | exact 26-character canonical ID |
| `text_to_binary` | `{"text":string}` | 34 lowercase hex digits, representing precisely 17 bytes |
| `binary_to_text` | `{"binary_hex":string}` | canonical 26-character ID |
| `boolean_validation` | `{"text":string}` | true or false (full numeric validation) |
| `format_only_validation` | `{"text":string}` | true or false (length/alphabet only) |
| `parse_components` | `{"text":string}` | `{"timestamp_seconds":integer,"randomness_hex":string}` plus `datetime_utc` only when supported |
| `generate_with_timestamp` | `{"timestamp_seconds":integer}` | canonical ID |
| `generate_binary` | `{}` | 34 lowercase hex digits |
| `generate_binary_with_timestamp` | `{"timestamp_seconds":integer}` | 34 lowercase hex digits |
| `public_compare` | `{"a":string,"b":string}` | signed comparison integer |
| `inject_fault` (only if advertised) | `{"fault":"csprng_failure","active":boolean}` | echo of fault and active state |

The `parse_components.randomness_hex` wire value is **always exactly 24 lowercase hex digits**. The implementation's *in-memory* parser may use 12 raw bytes or an integer of arbitrary precision, but the bridge converts that result to exact hexadecimal without loss. Timestamps are integer seconds (at most 78,364,164,095), safely representable in JavaScript's integer range; never send 96-bit randomness as JSON numbers.

When `datetime_utc` is returned, it is an ISO-8601 UTC string such as `2023-11-14T22:13:20Z`. It must represent the identical decoded timestamp, not a local timezone interpretation. Dates outside the source runtime's representable range must not be silently modified; if an API cannot return datetimes for all legal timestamps, do not claim `parse_datetime` and use lossless integer parsing.

## Success and failure envelopes

Successful operation:

```json
{"request_id":2,"ok":true,"value":"0000000000000000000000000000000000"}
```

Correct rejection of an invalid argument:

```json
{"request_id":3,"ok":false,"error":{"category":"invalid_input","message":"invalid 17-byte binary length"}}
```

The **error object must contain exactly `category` and `message`**, and `message` must be nonempty. Stable categories:

| Category | Meaning | Counts as correct rejection of invalid fixture? |
| --- | --- | --- |
| `invalid_input` | Explicit input validation rejection, range/length/alphabet | **Yes** |
| `entropy_unavailable` | Injected/actual CSPRNG failure while generating | No; expected only under fault injection |
| `internal_error` | Unexpected exception, crash, failing dependency | **No** |
| `unsupported_operation` | Operation not implemented or not mapped by bridge | **No** |

Catch only documented validation errors as `invalid_input`. Do **not** convert all exceptions to `invalid_input`: an implementation that crashes on malformed input must fail its strict rejection tests. A CSPRNG failure must not be hidden as input validation or weak random fallback.

The response `request_id` must be an integer equal to the request ID (not a boolean, float, or string). Replies with extra envelope keys, duplicate JSON keys, incorrect ID, malformed JSON or unknown categories are invalid.

## Fault injection

If `csprng_failure_injection` is advertised, the bridge accepts `inject_fault` for `csprng_failure`, and while active **every advertised generation path** must return `entropy_unavailable` without producing an ID. Deactivate the fault and verify generation recovers. The runner checks that the injection is actually honored. Source-level review is still required; a test-only stub does not prove the production code uses a CSPRNG.

## Exit codes and evidence

| Code | Meaning |
| ---: | --- |
| `0` | Automated checks passed with explicit `--automated-only`, OR matching manual evidence was supplied and recorded; see report status to distinguish. |
| `1` | At least one automated requirement failed. |
| `2` | Package, evidence, or adapter protocol could not be trusted. |
| `3` | Automated checks passed but mandatory human security evidence is outstanding (default). |

The runner **never** authenticates an evidence author's identity: a structurally valid record is not a signature. A consuming project's protected release workflow must independently approve evidence against the exact source commit. Without human review the package reports `AUTOMATED_PASS_AUDIT_REQUIRED` and returns `3`.

For actual implementations:

```sh
python3 tools/run_adapter.py --security-evidence /path/to/reviewed-evidence.json \
  --implementation-commit 0123456789abcdef0123456789abcdef01234567 \
  --report-json /path/to/conformance-result.json -- <adapter-command> [adapter-arguments]
```

The sample commit and paths are illustrative. A security evidence record must match `schemas/security-evidence.schema.json`, the suite/spec revisions and the exact implementation commit. Source locations are repository-relative paths and line ranges, not hosting-provider URLs. The JSON report distinguishes automated success, evidence record, and what remains unverified. Do not commit output reports or use the demo bridge to certify production code. See `SECURITY_AND_RELEASE_GATES.md`.
