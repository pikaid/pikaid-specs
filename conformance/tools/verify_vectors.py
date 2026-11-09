#!/usr/bin/env python3
"""Fail-closed, independent structural and semantic validation for PikaID fixtures.

This tool validates the fixture *package*, not the behavior of a language library.

Two layers are deliberately separated:

* **Integrity.** Checksums, schemas, referential integrity, mathematical
  consistency, and semantic invariants of the fixture suites. This layer accepts
  any internally consistent package identity, so a published package does not
  require editing the verifier.
* **Release policy.** An explicit expectation supplied by a release workflow
  (``--expect-status``, ``--expect-package-revision``). Nothing here is a
  signature; see ``SHA256SUMS`` for that limitation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
except ImportError as exc:
    raise SystemExit('MISSING DEPENDENCY: install tools/requirements.txt (jsonschema).') from exc

ROOT = Path(__file__).resolve().parents[1]
ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz'
MAX_TIMESTAMP = 36 ** 7 - 1
MAX_RANDOMNESS = 2 ** 96 - 1
EXPECTED_SUITES = ('valid', 'invalid-string', 'invalid-binary', 'ordering', 'generation', 'properties')

IDENTIFIER_FORMAT = 'immutable_unversioned'

PUBLISHED_STATUS = 'OFFICIAL'
PACKAGE_REVISION = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')
SPEC_REVISION = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')

# These are the *wire-adapter* operations, not required public API symbols.
# The manifest, protocol, verifier and runtime must agree on this vocabulary.
MANDATORY_CAPABILITIES = frozenset({'generate_string', 'text_to_binary', 'binary_to_text'})
OPTIONAL_CAPABILITIES = frozenset({
    'boolean_validation', 'format_only_validation', 'parse_components',
    'parse_datetime', 'generate_with_timestamp', 'generate_binary',
    'generate_binary_with_timestamp', 'public_compare', 'csprng_failure_injection',
})

# Preserve the immutable format's normative traceability even when a fixture
# editor can update SHA256SUMS. New specification revisions require review of
# this registry; silently deleting requirements is never an acceptable edit.
REQUIRED_NORMATIVE_IDS = frozenset({
    'FMT-001', 'FMT-002', 'FMT-003', 'TS-001', 'RNG-001', 'BIN-001',
    'VAL-001', 'VAL-002', 'ORDER-001', 'IMM-001',
})

# Execution floors. Recorded here so that editing a fixture cannot silently
# remove the statistical or security coverage the suite advertises.
MIN_CURRENT_ITERATIONS = 32
MIN_FIXED_TIMESTAMP_ITERATIONS = 8
MIN_PROPERTY_TRIALS = 32
# A generation run must yield at least this many distinct 96-bit randomness
# values. Statistical freshness cannot prove CSPRNG quality, so this is a floor
# against degenerate/constant randomness, not a security proof.
MIN_GENERATION_DISTINCT_SAMPLES = 64

GENERATION_EXPECTED = {
    'current_string': {'canonical_valid_id_timestamp_between_clock_bounds'},
    'caller_supplied_string': {'canonical_valid_id_with_exact_timestamp', 'reject'},
    'current_binary': {'canonical_valid_binary_timestamp_between_clock_bounds'},
    'caller_supplied_binary': {'canonical_valid_binary_with_exact_timestamp', 'reject'},
}

# Property strategies executed trial-by-trial by tools/run_adapter.py.
STRATEGY_CAPABILITY = {
    'caller_supplied_timestamp': 'generate_with_timestamp',
    'direct_binary_generation': 'generate_binary',
    'parse_components': 'parse_components',
    'parse_utc_datetime': 'parse_datetime',
    'boolean_validation': 'boolean_validation',
    'shape_only_validation': 'format_only_validation',
}
TRIAL_STRATEGIES = frozenset({
    'roundtrip_text_binary',
    'roundtrip_binary_text',
    'timestamp_ordering',
    'same_second_ordering',
    'current_time_generation',
}) | frozenset(STRATEGY_CAPABILITY)
# Strategies satisfied by executing an existing corpus exhaustively; they must
# not advertise an independent trial budget they do not run.
CORPUS_STRATEGIES = frozenset({'strict_invalid_string', 'strict_invalid_binary'})
# Obligations that can only be discharged by documented manual evidence.
AUDIT_STRATEGIES = frozenset({'csprng_review', 'csprng_failure_injection'})
KNOWN_STRATEGIES = TRIAL_STRATEGIES | CORPUS_STRATEGIES | AUDIT_STRATEGIES

MANDATORY_STRATEGIES = frozenset({
    'roundtrip_text_binary', 'roundtrip_binary_text', 'timestamp_ordering',
    'same_second_ordering', 'current_time_generation',
    'strict_invalid_string', 'strict_invalid_binary',
})

# More specific than a generic 32-trial floor: the formerly advertised 512/256
# executions must never be downgraded by editing a fixture and recomputing hashes.
PROPERTY_TRIAL_FLOORS = {
    'roundtrip_text_binary': 512, 'roundtrip_binary_text': 512,
    'timestamp_ordering': 512, 'same_second_ordering': 256,
    'current_time_generation': 64,
    'caller_supplied_timestamp': 64, 'direct_binary_generation': 64,
    'parse_components': 32, 'parse_utc_datetime': 32,
    'boolean_validation': 32, 'shape_only_validation': 32,
}

# Files that are operating-system metadata, never fixture sources. They are
# excluded from checksum coverage but reported, so a shipped junk file is
# visible rather than silently tolerated.
NON_SOURCE_NAMES = frozenset({'.DS_Store', 'Thumbs.db', 'desktop.ini'})


class FixtureError(ValueError):
    """A fixture, schema, or package-integrity validation failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FixtureError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON property: {key}')
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=reject_duplicates)
    except (UnicodeError, json.JSONDecodeError, OSError) as exc:
        raise FixtureError(f'cannot parse {path}: {exc}') from exc


def to_base36(number: int) -> str:
    require(type(number) is int and number >= 0, 'base36 input must be nonnegative integer')
    if number == 0:
        return '0'
    digits = []
    while number > 0:
        number, remainder = divmod(number, 36)
        digits.append(ALPHABET[remainder])
    return ''.join(reversed(digits))


def strict_text_to_binary(value: str) -> bytes:
    if not isinstance(value, str) or len(value) != 26 or not value.isascii():
        raise FixtureError('bad string length or non-ASCII string')
    if any(c not in ALPHABET for c in value):
        raise FixtureError('string contains characters outside lowercase Base36')
    timestamp = int(value[:7], 36)
    randomness = int(value[7:], 36)
    if timestamp > MAX_TIMESTAMP or randomness > MAX_RANDOMNESS:
        raise FixtureError('string component out of representable range')
    return timestamp.to_bytes(5, byteorder='big') + randomness.to_bytes(12, byteorder='big')


def strict_binary_to_text(data: bytes) -> str:
    if not isinstance(data, bytes) or len(data) != 17:
        raise FixtureError('binary length must be exactly 17 bytes')
    timestamp = int.from_bytes(data[:5], 'big', signed=False)
    if timestamp > MAX_TIMESTAMP:
        raise FixtureError('binary timestamp exceeds 7-char Base36 range')
    randomness = int.from_bytes(data[5:], 'big', signed=False)
    return to_base36(timestamp).rjust(7, '0') + to_base36(randomness).rjust(19, '0')


def is_well_formed(value: str) -> bool:
    return isinstance(value, str) and len(value) == 26 and value.isascii() and all(c in ALPHABET for c in value)


def cmp(a: Any, b: Any) -> int:
    return (a > b) - (a < b)


def check_checksums(root: Path) -> tuple[int, list[str]]:
    """Verify every declared digest and that no source file escapes coverage.

    Returns the number of checksummed files and the sorted list of ignored
    operating-system metadata paths.
    """
    checksum_file = root / 'SHA256SUMS'
    require(checksum_file.is_file(), 'missing SHA256SUMS')
    declared = {}
    for line in checksum_file.read_text(encoding='utf8').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([a-zA-Z0-9_./-]+)', line)
        require(match is not None, f'malformed SHA256SUMS line: {line!r}')
        digest, relative = match.groups()
        require(relative not in declared and relative != 'SHA256SUMS', f'duplicate/unexpected checksum: {relative}')
        require(not relative.startswith('/') and '..' not in Path(relative).parts, 'unsafe checksum path')
        path = root / relative
        require(path.is_file(), f'missing checksum target: {relative}')
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        require(got == digest, f'checksum mismatch: {relative}')
        declared[relative] = digest
    shipped = [p.relative_to(root).as_posix() for p in root.rglob('*')
               if p.is_file() and p.name != 'SHA256SUMS' and '__pycache__' not in p.parts
               and p.suffix not in ('.pyc', '.pyo')]
    ignored = sorted(rel for rel in shipped if Path(rel).name in NON_SOURCE_NAMES)
    present = {rel for rel in shipped if Path(rel).name not in NON_SOURCE_NAMES}
    require(set(declared) == present,
            f'checksum coverage mismatch missing={sorted(present - set(declared))}, '
            f'unexpected={sorted(set(declared) - present)}')
    require(not any(rel in declared for rel in ignored), 'operating-system metadata must never be checksummed')
    return len(declared), ignored


def check_schema(data: Any, schema: Any, path: str) -> None:
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(data))
    if errors:
        top = sorted(errors, key=lambda e: (str(list(e.absolute_path)), e.message))[0]
        raise FixtureError(f'{path}: schema invalid at {list(top.absolute_path)}: {top.message}')


def check_package_identity(manifest: dict[str, Any], expect_status: str | None = None,
                           expect_package_revision: str | None = None,
                           expect_spec_revision: str | None = None) -> None:
    """Validate package identity for internal consistency, then any explicit expectation.

    The suite is an official stable package. Release CI pins the exact suite and
    specification revisions by explicit arguments; no moving tag is trusted.
    """
    status = manifest['status']
    revision = manifest['package_revision']
    require(status == PUBLISHED_STATUS, f'package must have official status {PUBLISHED_STATUS!r}')
    require(PACKAGE_REVISION.match(revision) is not None, f'malformed package revision: {revision!r}')
    require(manifest['identifier_format'] == IDENTIFIER_FORMAT, 'format versioning is not allowed')
    require(SPEC_REVISION.fullmatch(manifest['spec_revision']) is not None,
            f'malformed specification revision: {manifest["spec_revision"]!r}')
    if expect_status is not None:
        require(status == expect_status, f'package status {status!r} does not match expected {expect_status!r}')
    if expect_package_revision is not None:
        require(revision == expect_package_revision,
                f'package revision {revision!r} does not match expected {expect_package_revision!r}')
    if expect_spec_revision is not None:
        require(manifest['spec_revision'] == expect_spec_revision,
                f'spec revision {manifest["spec_revision"]!r} does not match expected {expect_spec_revision!r}')


def check_generation_semantics(cases: list[dict[str, Any]]) -> None:
    """Reject a generation corpus whose semantics were weakened, not re-encoded."""
    mandatory_modes = {'current_string'}
    modes = Counter()
    shapes = set()
    for case in cases:
        case_id = case['id']
        mode = case['mode']
        expected = case['expected']
        scope = case['scope']
        is_current = mode.startswith('current_')
        require(mode in GENERATION_EXPECTED, f'{case_id}: unknown generation mode {mode!r}')
        require(expected in GENERATION_EXPECTED[mode], f'{case_id}: unexpected expectation {expected!r} for mode {mode}')
        require((case['timestamp_seconds'] is None) == is_current, f'{case_id}: incorrect timestamp mode')
        if expected == 'reject':
            require(not is_current, f'{case_id}: a current-time scenario cannot be an out-of-range rejection')
            require(case['timestamp_seconds'] < 0 or case['timestamp_seconds'] > MAX_TIMESTAMP,
                    f'{case_id}: reject is not out-of-range')
            require(case['iteration_count'] == 1, f'{case_id}: a rejection scenario must not repeat')
        elif is_current:
            require(case['iteration_count'] >= MIN_CURRENT_ITERATIONS,
                    f'{case_id}: current-time scenario needs at least {MIN_CURRENT_ITERATIONS} fresh samples')
        else:
            require(0 <= case['timestamp_seconds'] <= MAX_TIMESTAMP, f'{case_id}: accepted timestamp out-of-range')
            require(case['iteration_count'] >= MIN_FIXED_TIMESTAMP_ITERATIONS,
                    f'{case_id}: fixed-timestamp scenario needs at least {MIN_FIXED_TIMESTAMP_ITERATIONS} fresh samples')
        if scope == 'mandatory':
            require(mode in mandatory_modes, f'{case_id}: unexpected mandatory optional API')
        shape = (mode, case['timestamp_seconds'], expected)
        require(shape not in shapes, f'{case_id}: duplicate generation scenario {shape}')
        shapes.add(shape)
        modes[mode] += 1
    require(set(modes) == set(GENERATION_EXPECTED),
            f'generation modes missing: {sorted(set(GENERATION_EXPECTED) - set(modes))}')
    require({c['mode'] for c in cases if c['scope'] == 'mandatory'} == mandatory_modes,
            'mandatory generation mode missing')
    for mode in ('caller_supplied_string', 'caller_supplied_binary'):
        require(any(c['mode'] == mode and c['expected'] == 'reject' for c in cases),
                f'{mode}: missing out-of-range rejection scenario')
    require(any(c['mode'] == 'current_string' and c['iteration_count'] >= MIN_CURRENT_ITERATIONS for c in cases),
            'missing mandatory freshness sample scenario')
    # A mandatory-only adapter executes exactly the mandatory scenarios, so the
    # mandatory corpus alone must be able to satisfy the runner's freshness floor.
    mandatory_samples = sum(c['iteration_count'] for c in cases
                            if c['scope'] == 'mandatory' and c['expected'] != 'reject')
    require(mandatory_samples >= MIN_GENERATION_DISTINCT_SAMPLES,
            f'mandatory generation corpus yields only {mandatory_samples} fresh samples, '
            f'below the {MIN_GENERATION_DISTINCT_SAMPLES}-sample freshness floor')


def check_property_semantics(cases: list[dict[str, Any]]) -> None:
    """Reject a property registry that was downgraded, duplicated or underpowered."""
    seen = set()
    for case in cases:
        case_id = case['id']
        strategy = case['strategy']
        scope = case['scope']
        trials = case['minimum_trials']
        require(strategy in KNOWN_STRATEGIES, f'{case_id}: unknown property strategy {strategy!r}')
        expected_scope = ('audit' if strategy in AUDIT_STRATEGIES
                          else 'mandatory' if strategy in MANDATORY_STRATEGIES else 'conditional')
        require(scope == expected_scope,
                f'{case_id}: strategy {strategy!r} requires {expected_scope!r} scope, not {scope!r}')
        require((scope, strategy) not in seen, f'{case_id}: duplicate property scope/strategy {scope}/{strategy}')
        seen.add((scope, strategy))
        if scope == 'audit':
            require(strategy in AUDIT_STRATEGIES,
                    f'{case_id}: a runtime strategy cannot be downgraded to unresolvable audit scope')
            require(trials == 0, f'{case_id}: an audit obligation must not claim execution trials')
            require(len(case['assertion'].strip()) >= 60, f'{case_id}: audit obligation needs a substantive assertion')
        else:
            require(strategy not in AUDIT_STRATEGIES,
                    f'{case_id}: a manual security audit obligation cannot be claimed as automated')
            if strategy in TRIAL_STRATEGIES:
                floor = PROPERTY_TRIAL_FLOORS[strategy]
                require(trials >= floor,
                        f'{case_id}: runtime strategy needs at least {floor} executed trials')
            elif strategy in CORPUS_STRATEGIES:
                require(trials == 0,
                        f'{case_id}: corpus strategy is executed by its own suite and must not advertise trials')
    strategies = {c['strategy'] for c in cases}
    require(len(strategies) == len(cases), 'duplicate property strategy')
    require(strategies == KNOWN_STRATEGIES,
            f'property strategy inventory mismatch: missing={sorted(KNOWN_STRATEGIES-strategies)}, '
            f'extra={sorted(strategies-KNOWN_STRATEGIES)}')
    require(all((c['scope'] == 'audit') == (c['strategy'] in AUDIT_STRATEGIES) for c in cases),
            'audit scope and audit strategy disagree')


def verify_root(root: Path = ROOT, *, expect_status: str | None = None,
                expect_package_revision: str | None = None,
                expect_spec_revision: str | None = None) -> dict[str, Any]:
    checksummed, ignored = check_checksums(root)
    manifest = load_json(root / 'manifest.json')
    check_schema(manifest, load_json(root / 'schemas/manifest.schema.json'), 'manifest.json')
    check_package_identity(manifest, expect_status=expect_status,
                           expect_package_revision=expect_package_revision,
                           expect_spec_revision=expect_spec_revision)
    require(set(manifest['mandatory_capabilities']) == MANDATORY_CAPABILITIES,
            'manifest mandatory capabilities differ from wire-adapter contract')
    require(set(manifest['conditional_capabilities']) == OPTIONAL_CAPABILITIES,
            'manifest conditional capabilities differ from wire-adapter contract')
    require(len(manifest['fixtures']) == len(EXPECTED_SUITES), 'unexpected suite inventory count')
    registry = load_json(root / manifest['requirements_path'])
    check_schema(registry, load_json(root / manifest['requirements_schema']), 'requirements.json')
    require(registry['spec_revision'] == manifest['spec_revision'], 'requirement registry revision mismatch')
    require(len(registry['requirements']) == len({r['id'] for r in registry['requirements']}), 'duplicate requirement ID')
    requirements = {r['id'] for r in registry['requirements']}
    required_ids = {r['id'] for r in registry['requirements'] if r['level'] == 'MUST'}
    require(REQUIRED_NORMATIVE_IDS <= required_ids,
            f'canonical MUST requirements removed: {sorted(REQUIRED_NORMATIVE_IDS - required_ids)}')
    conditional_ids = {r['id'] for r in registry['requirements'] if r['level'] == 'CONDITIONAL_MUST'}
    seen_case_ids = set()
    refs_used = Counter()
    suites = {}
    for entry, kind in zip(manifest['fixtures'], EXPECTED_SUITES):
        require(entry['path'] == f'cases/{kind}.json', f'unexpected suite path for {kind}')
        require(entry['schema'] == f'schemas/{kind}.schema.json', f'unexpected schema path for {kind}')
        content = load_json(root / entry['path'])
        schema = load_json(root / entry['schema'])
        check_schema(content, schema, entry['path'])
        require(content['suite'] == kind, f'suite kind mismatch: {kind}')
        require(len(content['cases']) == entry['cases'], f'manifest count mismatch: {kind}')
        for case in content['cases']:
            case_id = case['id']
            require(case_id not in seen_case_ids, f'duplicate case ID: {case_id}')
            seen_case_ids.add(case_id)
            for ref in case['requirement_refs']:
                require(ref in requirements, f'{case_id}: unknown requirement ref: {ref}')
                refs_used[ref] += 1
        suites[kind] = content['cases']

    require(all(refs_used[id] for id in required_ids),
            f'uncovered MUST requirements: {sorted(id for id in required_ids if not refs_used[id])}')
    require(all(refs_used[id] for id in conditional_ids),
            f'uncovered CONDITIONAL_MUST requirements: {sorted(id for id in conditional_ids if not refs_used[id])}')
    require(required_ids <= set(refs_used), 'uncovered mandatory requirements')

    valid_by_id = {}
    for case in suites['valid']:
        name = case['id']
        textual = case['pikaid']
        binary = bytes.fromhex(case['binary_hex'])
        entropy = bytes.fromhex(case['randomness_hex'])
        ts = case['timestamp_seconds']
        require(len(entropy) == 12 and len(binary) == 17, f'{name}: wrong byte sizes')
        require(binary[:5] == ts.to_bytes(5, 'big'), f'{name}: timestamp bytes do not match')
        require(binary[5:] == entropy, f'{name}: binary entropy bytes do not match')
        require(textual == to_base36(ts).rjust(7, '0') + to_base36(int.from_bytes(entropy, 'big')).rjust(19, '0'),
                f'{name}: incorrect Base36 encoding')
        require(strict_text_to_binary(textual) == binary, f'{name}: text decoding mismatch')
        require(strict_binary_to_text(binary) == textual, f'{name}: binary encoding mismatch')
        valid_by_id[name] = case
    ids = [case['pikaid'] for case in suites['valid']]
    require(len(set(ids)) == len(ids), 'valid-string corpus contains duplicate canonical identifiers')

    for case in suites['invalid-string']:
        name = case['id']
        shape = is_well_formed(case['input'])
        require(shape == case['expected']['format_only_if_supported'], f'{name}: incorrect shape expectation')
        try:
            strict_text_to_binary(case['input'])
        except FixtureError:
            pass
        else:
            raise FixtureError(f'{name}: supposedly invalid string is actually valid')
        if case['reason'] == 'randomness_overflow':
            require(shape and int(case['input'][7:], 36) > MAX_RANDOMNESS, f'{name}: wrong overflow classification')
        if case['reason'] == 'length':
            require(len(case['input']) != 26, f'{name}: wrong length classification')
        if case['reason'] == 'invalid_alphabet':
            require(not shape, f'{name}: invalid alphabet classification with valid shape')

    invalid_inputs = [case['input'] for case in suites['invalid-string']]
    require(len(set(invalid_inputs)) == len(invalid_inputs),
            'invalid-string corpus contains duplicate inputs')
    alphabet_seen = set().union(*(set(value) for value in invalid_inputs))
    missing_uppercase = sorted(set('ABCDEFGHIJKLMNOPQRSTUVWXYZ') - alphabet_seen)
    require(not missing_uppercase,
            f'invalid-string corpus is missing uppercase letters: {missing_uppercase}')
    forbidden_ascii = set(map(chr, range(128))) - set(ALPHABET)
    require(forbidden_ascii <= alphabet_seen,
            f'invalid-string corpus missing forbidden ASCII: '
            f'{sorted(ord(ch) for ch in forbidden_ascii-alphabet_seen)}')
    unicode_examples = {'é', '０', '𝟘', '١', '\u0301', '\u200b', '\u00a0'}
    require(unicode_examples <= alphabet_seen,
            'invalid-string corpus missing representative noncanonical Unicode classes')

    for case in suites['invalid-binary']:
        name = case['id']
        blob = bytes.fromhex(case['input_hex'])
        try:
            strict_binary_to_text(blob)
        except FixtureError:
            pass
        else:
            raise FixtureError(f'{name}: supposedly invalid binary is actually valid')
        if case['reason'] == 'binary_length':
            require(len(blob) != 17, f'{name}: wrong binary length classification')
        if case['reason'] == 'timestamp_overflow':
            require(len(blob) == 17 and int.from_bytes(blob[:5], 'big') > MAX_TIMESTAMP,
                    f'{name}: wrong timestamp overflow classification')

    for case in suites['ordering']:
        name = case['id']
        a = case['a_pikaid']; b = case['b_pikaid']
        a_binary = bytes.fromhex(case['a_binary_hex']); b_binary = bytes.fromhex(case['b_binary_hex'])
        require(strict_text_to_binary(a) == a_binary and strict_text_to_binary(b) == b_binary,
                f'{name}: mismatched text/binary pair')
        text_result = cmp(a.encode('ascii'), b.encode('ascii'))
        byte_result = cmp(a_binary, b_binary)
        require(text_result == byte_result == case['expected_compare'], f'{name}: comparison mismatch')
        ta = int.from_bytes(a_binary[:5], 'big'); tb = int.from_bytes(b_binary[:5], 'big')
        if ta != tb:
            require(text_result == cmp(ta, tb), f'{name}: chronological ordering mismatch')

    check_generation_semantics(suites['generation'])
    check_property_semantics(suites['properties'])

    result: dict[str, Any] = {kind: len(cases) for kind, cases in suites.items()}
    result['_checksummed_files'] = checksummed
    result['_ignored_non_source'] = ignored
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Verify the PikaID fixture package (not an implementation).')
    parser.add_argument('--expect-status', default=None,
                        help='release workflow expectation, for example RELEASED')
    parser.add_argument('--expect-package-revision', default=None,
                        help='release workflow expectation, for example 1.0.0')
    parser.add_argument('--expect-spec-revision', default=None,
                        help='release workflow expectation, for example 1.0.4')
    args = parser.parse_args(argv)
    try:
        counts = verify_root(expect_status=args.expect_status,
                             expect_package_revision=args.expect_package_revision,
                             expect_spec_revision=args.expect_spec_revision)
    except (FixtureError, ValueError, TypeError, KeyError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    print('PASS: fixture integrity, schema and mathematical consistency verified')
    for kind in EXPECTED_SUITES:
        print(f'  {kind}: {counts[kind]} cases')
    print(f'  checksummed files: {counts["_checksummed_files"]}')
    if counts['_ignored_non_source']:
        print(f'NOTE: ignored non-source OS metadata (not checksummed, must not ship): '
              f'{counts["_ignored_non_source"]}')
    print('NOTE: no language implementation has been tested by this command')
    print('NOTE: this is not a conformance certification and not a signature')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
