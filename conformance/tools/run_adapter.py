#!/usr/bin/env python3
"""Run the shared PikaID conformance suite against a JSON-Lines adapter process.

No PikaID implementation is embedded here. The executable after `--` is the
language-specific bridge, which must call that language's actual library.

Exit codes:

* ``0``  every automated check passed **and** ``--automated-only`` was given.
* ``1``  at least one automated check failed.
* ``2``  the fixture package or the adapter protocol could not be trusted.
* ``3``  every automated check passed, but manual security-audit obligations
         are outstanding (the default, and never a conformance certification).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from verify_vectors import (
    CORPUS_STRATEGIES,
    KNOWN_STRATEGIES,
    MAX_TIMESTAMP,
    MANDATORY_CAPABILITIES,
    MIN_GENERATION_DISTINCT_SAMPLES,
    MIN_PROPERTY_TRIALS,
    OPTIONAL_CAPABILITIES,
    ROOT,
    STRATEGY_CAPABILITY,
)
from verify_vectors import (
    FixtureError,
    check_schema,
    cmp,
    is_well_formed,
    load_json,
    strict_binary_to_text,
    strict_text_to_binary,
    verify_root,
)

MANDATORY = MANDATORY_CAPABILITIES
OPTIONAL = OPTIONAL_CAPABILITIES
ALL = MANDATORY | OPTIONAL
INJECTION_OPERATION = 'inject_fault'
INJECTION_FAULT = 'csprng_failure'

EXIT_AUTOMATED_ONLY_PASS = 0
EXIT_AUTOMATED_FAIL = 1
EXIT_UNTRUSTED = 2
EXIT_AUDIT_REQUIRED = 3

STATUS_FAIL = 'FAIL'
STATUS_AUDIT_REQUIRED = 'AUTOMATED_PASS_AUDIT_REQUIRED'
STATUS_AUDIT_NOT_PERFORMED = 'AUTOMATED_PASS_AUDIT_NOT_PERFORMED'
STATUS_AUTOMATED_PASS = 'AUTOMATED_PASS'
STATUS_EVIDENCE_RECORDED = 'AUTOMATED_PASS_WITH_REVIEW_EVIDENCE'

CERTIFICATION_STATEMENT = (
    'Passing the automated suite does not prove CSPRNG quality or the absence of bugs; '
    'human review of the actual production code and its failure path is required. '
    'A supplied review document is not an authenticated cryptographic signature.'
)


def verify_security_evidence(path: Path, implementation_commit: str,
                             manifest: dict[str, Any]) -> dict[str, Any]:
    """Validate a reviewed, pinned evidence RECORD, not the truth of its claims.

    A protected consuming repository must review/approve the record separately.
    The runner cannot authenticate its author or inspect arbitrary source trees.
    """
    document = load_json(path)
    check_schema(document, load_json(ROOT / 'schemas/security-evidence.schema.json'), str(path))
    if document['implementation_commit'] != implementation_commit:
        raise FixtureError('security evidence commit differs from tested implementation commit')
    if document['spec_revision'] != manifest['spec_revision']:
        raise FixtureError('security evidence specification revision mismatch')
    if document['suite_revision'] != manifest['package_revision']:
        raise FixtureError('security evidence suite revision mismatch')
    ids = [check['id'] for check in document['checks']]
    if set(ids) != {'P-GENERATE-RNG-SOURCE', 'P-GENERATE-RNG-FAILURE'} or len(set(ids)) != 2:
        raise FixtureError('security evidence is missing an independent mandatory check')
    if document['reviewer'].casefold().strip() in {'unknown', 'todo', 'pending', 'n/a'}:
        raise FixtureError('security evidence must identify a real reviewer')
    try:
        datetime.strptime(document['reviewed_at_utc'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as exc:
        raise FixtureError('security evidence has invalid UTC review timestamp') from exc
    # The enclosing record pins every relative source location to the exact
    # implementation commit; no hosting provider or URL format is required.
    for check in document['checks']:
        locations = set()
        for ref in check['evidence']:
            relative = ref['path']
            if relative in ('.', '..') or any(part in ('', '.', '..') for part in relative.split('/')):
                raise FixtureError('security evidence must use clean repository-relative source paths')
            if ref['line_end'] < ref['line_start']:
                raise FixtureError('security evidence line_end precedes line_start')
            key = (relative, ref['line_start'], ref['line_end'])
            if key in locations:
                raise FixtureError('duplicate source location in security evidence')
            locations.add(key)
    return document


class BridgeFailure(Exception):
    pass


class ProtocolError(BridgeFailure):
    """Untrustworthy bridge transport/envelope, distinct from a failed assertion."""


class AdapterRejected(BridgeFailure):
    pass


class EntropyUnavailable(BridgeFailure):
    """The test adapter reported failure of its cryptographic entropy source."""


class Bridge:
    def __init__(self, command: list[str], timeout: float):
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=None, bufsize=0)
        self.timeout = timeout
        self.serial = 0
        self.buffer = b''
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.proc.stdout, selectors.EVENT_READ)
        self.capabilities = set()
        try:
            hello = self.request('hello', {})
            if type(hello) is not dict or hello.get('protocol_version') != 1:
                raise ProtocolError('hello must return protocol_version=1')
            caps = hello.get('capabilities')
            if type(caps) is not list or not all(type(c) is str for c in caps) or len(caps) != len(set(caps)):
                raise ProtocolError('hello must return distinct string capabilities')
            self.capabilities = set(caps)
            if not MANDATORY <= self.capabilities:
                raise ProtocolError(f'missing mandatory capabilities: {sorted(MANDATORY-self.capabilities)}')
            if self.capabilities - ALL:
                raise ProtocolError(f'unknown advertised capabilities: {sorted(self.capabilities-ALL)}')
            if 'parse_datetime' in self.capabilities and 'parse_components' not in self.capabilities:
                raise ProtocolError('parse_datetime requires the parse_components operation')
        except BaseException:
            self.close()
            raise

    def _read_line(self) -> bytes:
        while b'\n' not in self.buffer:
            if self.proc.poll() is not None:
                raise ProtocolError(f'adapter terminated (exit {self.proc.returncode})')
            events = self.selector.select(timeout=self.timeout)
            if not events:
                raise ProtocolError(f'adapter response exceeded {self.timeout}s timeout')
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                raise ProtocolError('adapter closed stdout without a response')
            self.buffer += chunk
            if len(self.buffer) > 1_048_576:
                raise ProtocolError('adapter output exceeded 1 MiB line limit')
        line, self.buffer = self.buffer.split(b'\n',1)
        return line

    def request(self, operation: str, arguments: dict[str, Any]) -> Any:
        self.serial += 1
        request_id = self.serial
        request = {'request_id':request_id, 'operation':operation, 'arguments':arguments}
        try:
            self.proc.stdin.write((json.dumps(request, separators=(',',':'),ensure_ascii=False)+'\n').encode('utf8'))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ProtocolError(f'cannot write to adapter: {exc}') from exc
        raw = self._read_line()
        try:
            from verify_vectors import reject_duplicates
            reply = json.loads(raw.decode('utf8'),object_pairs_hook=reject_duplicates)
        except (UnicodeError, ValueError) as exc:
            raise ProtocolError(f'non-JSON/duplicate-key adapter response: {raw[:160]!r}') from exc
        if (type(reply) is not dict or type(reply.get('request_id')) is not int
                or reply['request_id'] != request_id or type(reply.get('ok')) is not bool):
            raise ProtocolError(f'invalid response envelope for request_id={request_id}')
        if reply['ok'] is True:
            if set(reply) != {'request_id','ok','value'}:
                raise ProtocolError('successful response must contain only request_id, ok, value')
            return reply['value']
        if set(reply) != {'request_id','ok','error'} or type(reply['error']) is not dict:
            raise ProtocolError('rejected response must contain request_id, ok, and structured error')
        error = reply['error']
        categories = {'invalid_input', 'entropy_unavailable', 'internal_error', 'unsupported_operation'}
        if (set(error) != {'category', 'message'} or type(error.get('category')) is not str
                or error['category'] not in categories or type(error.get('message')) is not str
                or not error['message']):
            raise ProtocolError('error must contain known semantic category and nonempty message')
        if error['category'] == 'invalid_input':
            raise AdapterRejected(error['message'])
        if error['category'] == 'entropy_unavailable':
            raise EntropyUnavailable(error['message'])
        raise (ProtocolError if error["category"] == "unsupported_operation" else BridgeFailure)(
            f'adapter {error["category"]}: {error["message"]}')

    def close(self):
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.proc.kill(); self.proc.wait(timeout=2)
        finally:
            self.selector.close()
            if self.proc.stdin:self.proc.stdin.close()
            if self.proc.stdout:self.proc.stdout.close()


def enforce(condition: bool, message: str):
    if not condition:raise BridgeFailure(message)


def strict_hex(value: Any, number_bytes: int) -> bytes:
    enforce(type(value) is str and re.fullmatch(r'[0-9a-f]*', value) is not None and len(value)==number_bytes*2,
            f'expected exactly {number_bytes} bytes of lowercase hex')
    return bytes.fromhex(value)


def verify_production_value(bridge: Bridge, text: Any, expected_timestamp: int|None = None) -> bytes:
    enforce(type(text) is str, 'generated ID must be a string')
    reference_binary = strict_text_to_binary(text)
    if expected_timestamp is not None:
        enforce(int.from_bytes(reference_binary[:5],'big') == expected_timestamp, 'generated timestamp does not match requested timestamp')
    actual_binary = strict_hex(bridge.request('text_to_binary', {'text': text}), 17)
    enforce(actual_binary==reference_binary, 'generated text_to_binary mismatch')
    enforce(bridge.request('binary_to_text', {'binary_hex':actual_binary.hex()}) == text,'generated binary_to_text mismatch')
    return reference_binary


COUNTER_RUN = 8

def is_counter_like(entropies: list[bytes]) -> bool:
    """Detect a monotonically stepped PRNG (constant delta over consecutive calls)."""
    numbers = [int.from_bytes(entropy, 'big') for entropy in entropies]
    previous_delta = None
    run = 1
    for first, second in zip(numbers, numbers[1:]):
        delta = second - first
        if delta == previous_delta and delta != 0:
            run += 1
        else:
            run = 1
        previous_delta = delta if delta != 0 else None
        if run >= COUNTER_RUN:
            return True
    return False


def is_degenerate(entropy: bytes) -> bool:
    """Reject randomness that betrays a constant, stuck, or single-byte source."""
    return entropy == bytes(12) or entropy == b'\xff'*12 or len(set(entropy)) == 1


def sample_binary(label: str, index: int) -> bytes:
    """Deterministic, reproducible 17-byte sample: valid timestamp plus 12 bytes."""
    digest = hashlib.sha256(f'pikaid-property:{label}:{index}'.encode()).digest()
    timestamp = int.from_bytes(digest[:8], 'big') % (MAX_TIMESTAMP + 1)
    return timestamp.to_bytes(5, 'big') + digest[8:20]


class SuiteRunner:
    def __init__(self,bridge: Bridge, max_errors: int):
        self.bridge=bridge
        self.max_errors=max_errors
        self.errors=[]
        self.counts={kind:{'passed':0,'failed':0,'not_applicable':0} for kind in ('valid','invalid-string','invalid-binary','ordering','generation','properties')}
        self.manual_audits=[]
        self.datasets={kind:load_json(ROOT/f'cases/{kind}.json')['cases'] for kind in self.counts}
        self.capabilities=bridge.capabilities
        self._recorded=set()
        self.entropy_samples: list[tuple[str,int,bytes]] = []
        self.executed_trials: dict[str,int] = {}
        self.generation_summary: dict[str,Any] = {}

    def exercise(self,suite:str,name:str,fn):
        enforce(name not in self._recorded,f'case re-executed twice: {name}')
        self._recorded.add(name)
        try:
            fn()
            self.counts[suite]['passed'] += 1
        except ProtocolError:
            raise
        except Exception as exc:
            self.counts[suite]['failed'] += 1
            self.errors.append(f'{suite}/{name}: {type(exc).__name__}: {exc}')
            if len(self.errors)>=self.max_errors:
                raise BridgeFailure(f'reached max errors ({self.max_errors})')

    def not_applicable(self,suite,name):
        enforce(name not in self._recorded,f'case recorded twice: {name}')
        self._recorded.add(name)
        self.counts[suite]['not_applicable']+=1

    def required(self,name,args):return self.bridge.request(name,args)

    # -- generation freshness (GEN-001) ------------------------------------

    def record_entropy(self, case_id: str, iteration: int, binary: bytes) -> None:
        entropy = binary[5:]
        enforce(len(entropy) == 12, f'{case_id}: generated randomness is not 12 bytes')
        enforce(not is_degenerate(entropy),
                f'{case_id}: degenerate randomness {entropy.hex()} indicates a broken CSPRNG')
        self.entropy_samples.append((case_id, iteration, entropy))

    def check_generation_freshness(self) -> None:
        entropies = [entropy for _, _, entropy in self.entropy_samples]
        enforce(len(entropies) >= MIN_GENERATION_DISTINCT_SAMPLES,
                f'only {len(entropies)} generated identifiers were observed; '
                f'the freshness floor is {MIN_GENERATION_DISTINCT_SAMPLES}')
        counts = Counter(entropies)
        duplicated = sorted(entropy.hex() for entropy, count in counts.items() if count > 1)
        enforce(not duplicated,
                f'generation reused 96-bit randomness ({len(duplicated)} duplicated values, '
                f'first: {duplicated[:4]})')
        enforce(len(counts) >= MIN_GENERATION_DISTINCT_SAMPLES,
                f'only {len(counts)} distinct randomness values; floor is {MIN_GENERATION_DISTINCT_SAMPLES}')
        grouped: dict[str, list[bytes]] = {}
        for case_id, _, entropy in self.entropy_samples:
            grouped.setdefault(case_id, []).append(entropy)
        for case_id, values in grouped.items():
            enforce(not is_counter_like(values),
                    f'{case_id}: generated randomness advances by a constant delta, '
                    'indicating a counter or stepped PRNG instead of a CSPRNG')
        self.generation_summary = {
            'samples': len(entropies),
            'distinct': len(counts),
            'minimum_required': MIN_GENERATION_DISTINCT_SAMPLES,
            'duplicate_values': 0,
        }

    # -- suites ------------------------------------------------------------

    def valid(self):
        for c in self.datasets['valid']:
            def check(c=c):
                expected = bytes.fromhex(c['binary_hex'])
                actual = strict_hex(self.required('text_to_binary',{'text':c['pikaid']}),17)
                enforce(actual == expected, 'text_to_binary differs from official binary vector')
                text = self.required('binary_to_text',{'binary_hex':c['binary_hex']})
                enforce(text == c['pikaid'], 'binary_to_text differs from official text vector')
                if 'boolean_validation' in self.capabilities:
                    is_valid = self.required('boolean_validation',{'text':c['pikaid']})
                    enforce(type(is_valid) is bool and is_valid, 'boolean_validation rejected valid vector')
                if 'format_only_validation' in self.capabilities:
                    wf = self.required('format_only_validation',{'text':c['pikaid']})
                    enforce(type(wf) is bool and wf, 'format_only_validation rejected valid vector')
                if 'parse_components' in self.capabilities:
                    parsed = self.required('parse_components',{'text':c['pikaid']})
                    enforce(type(parsed) is dict, 'parse_components must return object')
                    ts=parsed.get('timestamp_seconds'); entropy=parsed.get('randomness_hex')
                    enforce(type(ts) is int and ts==c['timestamp_seconds'],'parsed timestamp mismatch')
                    enforce(type(entropy) is str and entropy==c['randomness_hex'],'parsed randomness mismatch')
                    if 'parse_datetime' in self.capabilities:
                        enforce('datetime_utc' in parsed, 'advertised parse_datetime but no datetime_utc was returned')
                    if 'datetime_utc' in parsed:
                        enforce(parsed['datetime_utc']==datetime.fromtimestamp(ts,timezone.utc).isoformat().replace('+00:00','Z'),'parser optional datetime_utc mismatch')
            self.exercise('valid',c['id'],check)

    def invalid_string(self):
        for c in self.datasets['invalid-string']:
            def check(c=c):
                try:self.required('text_to_binary',{'text':c['input']})
                except AdapterRejected:pass
                else:raise BridgeFailure('invalid text was accepted by strict conversion')
                if 'boolean_validation' in self.capabilities:
                    v=self.required('boolean_validation',{'text':c['input']})
                    enforce(type(v) is bool and v is False,'invalid string boolean validation was not false')
                if 'format_only_validation' in self.capabilities:
                    v=self.required('format_only_validation',{'text':c['input']})
                    enforce(type(v) is bool and v is c['expected']['format_only_if_supported'],'shape-only validation disagrees with fixture')
                if 'parse_components' in self.capabilities:
                    try:self.required('parse_components',{'text':c['input']})
                    except AdapterRejected:pass
                    else:raise BridgeFailure('parser accepted invalid text')
            self.exercise('invalid-string',c['id'],check)

    def invalid_binary(self):
        for c in self.datasets['invalid-binary']:
            def check(c=c):
                try:self.required('binary_to_text',{'binary_hex':c['input_hex']})
                except AdapterRejected:pass
                else:raise BridgeFailure('invalid binary was accepted')
            self.exercise('invalid-binary',c['id'],check)

    def ordering(self):
        for c in self.datasets['ordering']:
            def check(c=c):
                a=self.required('binary_to_text',{'binary_hex':c['a_binary_hex']})
                b=self.required('binary_to_text',{'binary_hex':c['b_binary_hex']})
                enforce((a,b)==(c['a_pikaid'],c['b_pikaid']),'binary-to-text ordering fixture mismatch')
                a_bin=strict_hex(self.required('text_to_binary',{'text':a}),17)
                b_bin=strict_hex(self.required('text_to_binary',{'text':b}),17)
                result=cmp(a.encode('ascii'),b.encode('ascii'))
                enforce(result==cmp(a_bin,b_bin)==c['expected_compare'],'cross-format comparison mismatch')
                if 'public_compare' in self.capabilities:
                    v=self.required('public_compare',{'a':a,'b':b})
                    enforce(type(v) is int and cmp(v,0)==result,'public comparator disagrees with bytewise order')
            self.exercise('ordering',c['id'],check)

    def generation(self):
        cap_by_mode={'current_string':'generate_string','current_binary':'generate_binary','caller_supplied_string':'generate_with_timestamp','caller_supplied_binary':'generate_binary_with_timestamp'}
        for c in self.datasets['generation']:
            operation=cap_by_mode[c['mode']]
            if operation not in self.capabilities:
                enforce(c['scope']=='conditional',f'mandatory generation mode absent: {operation}')
                self.not_applicable('generation',c['id'])
                continue
            def check(c=c,op=operation):
                for n in range(c['iteration_count']):
                    before=int(datetime.now(timezone.utc).timestamp())
                    args={} if c['timestamp_seconds'] is None else {'timestamp_seconds':c['timestamp_seconds']}
                    if c['expected']=='reject':
                        try:self.required(op,args)
                        except AdapterRejected:continue
                        raise BridgeFailure(f'out-of-range generation accepted {c["timestamp_seconds"]}')
                    got=self.required(op,args)
                    after=int(datetime.now(timezone.utc).timestamp())
                    if op in ('generate_string','generate_with_timestamp'):
                        binary=verify_production_value(self.bridge,got,c['timestamp_seconds'])
                    else:
                        binary=strict_hex(got,17)
                        text=self.required('binary_to_text',{'binary_hex':got})
                        enforce(strict_text_to_binary(text)==binary,'generated binary does not decode consistently')
                        enforce(self.required('text_to_binary',{'text':text})==got,'generated binary roundtrip differs')
                        if c['timestamp_seconds'] is not None:
                            enforce(int.from_bytes(binary[:5],'big')==c['timestamp_seconds'],'binary generated timestamp mismatch')
                    if c['timestamp_seconds'] is None:
                        ts=int.from_bytes(binary[:5],'big')
                        # Allow an explicit one-second scheduling boundary tolerance only;
                        # external clock jumps require environment-specific investigation.
                        enforce(before-1 <= ts <= after+1, f'generated UTC second {ts} differs from call bounds {before}..{after}')
                    self.record_entropy(c['id'], n, binary)
            self.exercise('generation',c['id'],check)

    # -- property trials (RUN-001) ----------------------------------------

    def trials_current_time_generation(self, trials: int) -> int:
        executed = 0
        for idx in range(trials):
            before = int(datetime.now(timezone.utc).timestamp())
            got = self.required('generate_string', {})
            after = int(datetime.now(timezone.utc).timestamp())
            binary = verify_production_value(self.bridge, got)
            timestamp = int.from_bytes(binary[:5], 'big')
            enforce(before - 1 <= timestamp <= after + 1,
                    f'current-time generation {timestamp} differs from call bounds {before}..{after}')
            self.record_entropy('P-GENERATE-STRING', idx, binary)
            executed += 1
        return executed

    def trials_caller_supplied_timestamp(self, trials: int) -> int:
        executed = 0
        for idx in range(trials):
            timestamp = int.from_bytes(
                hashlib.sha256(f'pikaid-property:caller-ts:{idx}'.encode()).digest()[:8], 'big'
            ) % (MAX_TIMESTAMP + 1)
            got = self.required('generate_with_timestamp', {'timestamp_seconds': timestamp})
            binary = verify_production_value(self.bridge, got, timestamp)
            self.record_entropy('P-GENERATE-FIXED-TS', idx, binary)
            executed += 1
        return executed

    def trials_direct_binary_generation(self, trials: int) -> int:
        executed = 0
        for idx in range(trials):
            got = self.required('generate_binary', {})
            binary = strict_hex(got, 17)
            text = self.required('binary_to_text', {'binary_hex': got})
            enforce(strict_text_to_binary(text) == binary, 'direct binary generation does not decode consistently')
            enforce(self.required('text_to_binary', {'text': text}) == got, 'direct binary generation roundtrip differs')
            self.record_entropy('P-GENERATE-BINARY-DIRECT', idx, binary)
            executed += 1
        return executed

    def trials_parse_components(self, trials: int) -> int:
        valid = self.datasets['valid']
        executed = 0
        for idx in range(trials):
            case = valid[idx % len(valid)]
            parsed = self.required('parse_components', {'text': case['pikaid']})
            enforce(type(parsed) is dict, 'parse_components must return an object')
            enforce(type(parsed.get('timestamp_seconds')) is int, 'parsed timestamp must be an integer')
            enforce(parsed['timestamp_seconds'] == case['timestamp_seconds'], 'parsed timestamp mismatch')
            enforce(type(parsed.get('randomness_hex')) is str, 'parsed randomness must be a hex string')
            enforce(parsed['randomness_hex'] == case['randomness_hex'], 'parsed randomness mismatch')
            executed += 1
        return executed

    def trials_parse_utc_datetime(self, trials: int) -> int:
        valid = self.datasets['valid']
        executed = 0
        for idx in range(trials):
            case = valid[idx % len(valid)]
            parsed = self.required('parse_components', {'text': case['pikaid']})
            enforce(type(parsed) is dict and 'datetime_utc' in parsed,
                    'parse_utc_datetime strategy advertised but no datetime_utc was returned')
            expected = datetime.fromtimestamp(case['timestamp_seconds'], timezone.utc).isoformat().replace('+00:00', 'Z')
            enforce(parsed['datetime_utc'] == expected,
                    f'parser datetime {parsed["datetime_utc"]!r} is not the exact UTC second {expected!r}')
            executed += 1
        return executed

    def trials_boolean_validation(self, trials: int) -> int:
        valid = self.datasets['valid']
        invalid = self.datasets['invalid-string']
        executed = 0
        for idx in range(trials):
            if idx % 2 == 0:
                case = valid[(idx // 2) % len(valid)]
                value = self.required('boolean_validation', {'text': case['pikaid']})
                enforce(type(value) is bool and value is True,
                        f'boolean_validation rejected a valid identifier {case["id"]}')
            else:
                case = invalid[(idx // 2) % len(invalid)]
                value = self.required('boolean_validation', {'text': case['input']})
                enforce(type(value) is bool and value is False,
                        f'boolean_validation accepted an invalid identifier {case["id"]}')
            executed += 1
        return executed

    def trials_shape_only_validation(self, trials: int) -> int:
        valid = self.datasets['valid']
        shape_only = [c for c in self.datasets['invalid-string'] if c['expected']['format_only_if_supported']]
        malformed = [c for c in self.datasets['invalid-string'] if not c['expected']['format_only_if_supported']]
        enforce(shape_only and malformed, 'invalid-string corpus lost its shape split')
        executed = 0
        for idx in range(trials):
            branch = idx % 3
            if branch == 0:
                case = valid[(idx // 3) % len(valid)]
                value = self.required('format_only_validation', {'text': case['pikaid']})
                enforce(type(value) is bool and value is True,
                        f'format_only_validation rejected a well-formed identifier {case["id"]}')
            elif branch == 1:
                case = shape_only[(idx // 3) % len(shape_only)]
                value = self.required('format_only_validation', {'text': case['input']})
                enforce(type(value) is bool and value is True,
                        f'format_only_validation rejected a shape-valid string {case["id"]}')
            else:
                case = malformed[(idx // 3) % len(malformed)]
                value = self.required('format_only_validation', {'text': case['input']})
                enforce(type(value) is bool and value is False,
                        f'format_only_validation accepted a malformed string {case["id"]}')
            executed += 1
        return executed

    def injection_trials(self) -> int:
        """Force the CSPRNG to fail and require generation to fail closed (GEN-001)."""
        operations = ['generate_string']
        for capability, operation in (
            ('generate_binary', 'generate_binary'),
            ('generate_with_timestamp', 'generate_with_timestamp'),
            ('generate_binary_with_timestamp', 'generate_binary_with_timestamp'),
        ):
            if capability in self.capabilities:
                operations.append(operation)
        cycles = 0
        for operation in operations:
            args = {'timestamp_seconds': 0} if operation.endswith('with_timestamp') else {}
            try:
                self.required(INJECTION_OPERATION, {'fault': INJECTION_FAULT, 'active': True})
            except AdapterRejected as exc:
                raise BridgeFailure(f'inject_fault was rejected although advertised: {exc}') from exc
            try:
                try:
                    self.required(operation, args)
                except EntropyUnavailable:
                    pass
                except AdapterRejected as exc:
                    raise BridgeFailure(
                        f'{operation} incorrectly rejected a CSPRNG failure as invalid_input: {exc}'
                    ) from exc
                else:
                    raise BridgeFailure(f'{operation} accepted or incorrectly rejected a CSPRNG failure instead of failing closed')
            finally:
                self.required(INJECTION_OPERATION, {'fault': INJECTION_FAULT, 'active': False})
            recovered = self.required(operation, args)
            if operation in ('generate_string', 'generate_with_timestamp'):
                verify_production_value(self.bridge, recovered, 0 if operation.endswith('with_timestamp') else None)
            else:
                strict_hex(recovered, 17)
            cycles += 1
        return cycles

    def properties(self):
        conditional_trials = {
            'caller_supplied_timestamp': self.trials_caller_supplied_timestamp,
            'direct_binary_generation': self.trials_direct_binary_generation,
            'parse_components': self.trials_parse_components,
            'parse_utc_datetime': self.trials_parse_utc_datetime,
            'boolean_validation': self.trials_boolean_validation,
            'shape_only_validation': self.trials_shape_only_validation,
        }
        corpus_source = {
            'strict_invalid_string': 'invalid-string',
            'strict_invalid_binary': 'invalid-binary',
        }
        for c in self.datasets['properties']:
            strategy = c['strategy']
            enforce(strategy in KNOWN_STRATEGIES, f'unknown property strategy {strategy}')
            if c['scope'] == 'audit':
                self.manual_audits.append({
                    'id': c['id'],
                    'strategy': strategy,
                    'status': 'MANUAL_EVIDENCE_REQUIRED',
                    'assertion': c['assertion'],
                })
                if strategy == 'csprng_failure_injection' and 'csprng_failure_injection' in self.capabilities:
                    def check_audit(c=c):
                        cycles = self.injection_trials()
                        self.executed_trials[c['id']] = cycles
                        enforce(cycles >= 1, 'no generation path was exercised under fault injection')
                    self.exercise('properties', c['id'], check_audit)
                else:
                    if strategy == 'csprng_failure_injection':
                        self.manual_audits[-1]['automated_note'] = (
                            'adapter does not advertise csprng_failure_injection; '
                            'this obligation can only be discharged by manual evidence')
                    self.not_applicable('properties', c['id'])
                continue
            if strategy == 'current_time_generation':
                def check_current_time(c=c):
                    executed = self.trials_current_time_generation(c['minimum_trials'])
                    self.executed_trials[c['id']] = executed
                    enforce(executed == c['minimum_trials'],
                            f'{c["id"]}: executed {executed} trials, advertised {c["minimum_trials"]}')
                    enforce(executed >= MIN_PROPERTY_TRIALS,
                            f'{c["id"]}: executed {executed} trials, below the '
                            f'{MIN_PROPERTY_TRIALS}-trial floor')
                self.exercise('properties', c['id'], check_current_time)
            elif strategy in ('roundtrip_text_binary', 'roundtrip_binary_text'):
                def check_roundtrip(c=c):
                    executed = 0
                    for idx in range(c['minimum_trials']):
                        binary = sample_binary(c['strategy'], idx)
                        text = strict_binary_to_text(binary)
                        if c['strategy'] == 'roundtrip_text_binary':
                            got_bin = strict_hex(self.required('text_to_binary', {'text': text}), 17)
                            enforce(got_bin == binary, 'roundtrip property text_to_binary mismatch')
                            enforce(self.required('binary_to_text', {'binary_hex': got_bin.hex()}) == text,
                                    'roundtrip property text mismatch')
                        else:
                            got_text = self.required('binary_to_text', {'binary_hex': binary.hex()})
                            enforce(got_text == text, 'roundtrip property binary_to_text mismatch')
                            enforce(strict_hex(self.required('text_to_binary', {'text': got_text}), 17) == binary,
                                    'roundtrip property binary mismatch')
                        executed += 1
                    self.executed_trials[c['id']] = executed
                    enforce(executed == c['minimum_trials'],
                            f'{c["id"]}: executed {executed} trials, advertised {c["minimum_trials"]}')
                self.exercise('properties', c['id'], check_roundtrip)
            elif strategy in ('timestamp_ordering', 'same_second_ordering'):
                def check_ordering(c=c):
                    executed = 0
                    for idx in range(c['minimum_trials']):
                        ts1 = int.from_bytes(hashlib.sha256(f'order-ts-{idx}'.encode()).digest()[:8], 'big') % (MAX_TIMESTAMP + 1)
                        ts2 = (ts1 + 1) % (MAX_TIMESTAMP + 1) if c['strategy'] == 'timestamp_ordering' else ts1
                        a = ts1.to_bytes(5, 'big') + hashlib.sha256(f'order-a-{idx}'.encode()).digest()[:12]
                        b = ts2.to_bytes(5, 'big') + hashlib.sha256(f'order-b-{idx}'.encode()).digest()[:12]
                        sa = self.required('binary_to_text', {'binary_hex': a.hex()})
                        sb = self.required('binary_to_text', {'binary_hex': b.hex()})
                        enforce(strict_text_to_binary(sa) == a and strict_text_to_binary(sb) == b,
                                'ordering property binary/text mismatch')
                        enforce(cmp(sa.encode('ascii'), sb.encode('ascii')) == cmp(a, b),
                                'ordering property different comparator results')
                        if 'public_compare' in self.capabilities:
                            pub = self.required('public_compare', {'a': sa, 'b': sb})
                            enforce(type(pub) is int and cmp(pub, 0) == cmp(a, b),
                                    'ordering property public comparator mismatch')
                        executed += 1
                    self.executed_trials[c['id']] = executed
                    enforce(executed == c['minimum_trials'],
                            f'{c["id"]}: executed {executed} trials, advertised {c["minimum_trials"]}')
                self.exercise('properties', c['id'], check_ordering)
            elif strategy in CORPUS_STRATEGIES:
                source = corpus_source[strategy]
                def check_corpus(c=c, source=source):
                    self.executed_trials[c['id']] = 0
                    enforce(c['minimum_trials'] == 0,
                            f'{c["id"]}: corpus strategy must not advertise independent trials')
                    enforce(self.counts[source]['failed'] == 0 and self.counts[source]['passed'] > 0,
                            f'corresponding mandatory suite {source} did not pass')
                self.exercise('properties', c['id'], check_corpus)
            else:
                capability = STRATEGY_CAPABILITY[strategy]
                if capability not in self.capabilities:
                    self.not_applicable('properties', c['id'])
                    continue
                trial = conditional_trials[strategy]
                def check_conditional(c=c, trial=trial):
                    executed = trial(c['minimum_trials'])
                    self.executed_trials[c['id']] = executed
                    enforce(executed == c['minimum_trials'],
                            f'{c["id"]}: executed {executed} trials, advertised {c["minimum_trials"]}')
                    enforce(executed >= MIN_PROPERTY_TRIALS,
                            f'{c["id"]}: executed {executed} trials, below the '
                            f'{MIN_PROPERTY_TRIALS}-trial floor')
                self.exercise('properties', c['id'], check_conditional)

    def execute(self):
        self.valid(); self.invalid_string(); self.invalid_binary(); self.ordering(); self.generation(); self.properties()
        expected={kind:len(cases) for kind,cases in self.datasets.items()}
        for kind, total in expected.items():
            observed=sum(self.counts[kind].values())
            enforce(observed==total,f'{kind}: cases unaccounted: {observed} != {total}')
        for kind in ('valid','invalid-string','invalid-binary','ordering'):
            enforce(self.counts[kind]['passed']>0 and self.counts[kind]['not_applicable']==0,
                    f'mandatory suite missing or skipped: {kind}')
        enforce(self.counts['generation']['passed']>=1, 'mandatory generation scenario not executed')
        try:
            self.check_generation_freshness()
        except BridgeFailure as exc:
            self.errors.append(f'generation/FRESHNESS: {type(exc).__name__}: {exc}')
        for case in self.datasets['properties']:
            if case['scope'] != 'conditional' or not case['minimum_trials']:
                continue
            executed = self.executed_trials.get(case['id'])
            if executed is None:
                # The optional capability (or an optional sub-feature such as a
                # UTC datetime) is absent; the case was registered as
                # not-applicable rather than silently passed.
                continue
            enforce(executed == case['minimum_trials'],
                    f'{case["id"]}: advertised {case["minimum_trials"]} trials, executed {executed}')


def main(argv: list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--max-errors',type=int,default=30)
    parser.add_argument('--request-timeout-seconds',type=float,default=10)
    parser.add_argument('--report-json',type=Path,default=None)
    parser.add_argument('--automated-only',action='store_true',
                        help='exit 0 when every automated check passes, without claiming that the '
                             'outstanding manual security audits were satisfied')
    parser.add_argument('--security-evidence', type=Path, default=None,
                        help='implementation-specific, reviewed CSPRNG evidence document (see schema)')
    parser.add_argument('--implementation-commit', default=None,
                        help='exact 40-character Git commit SHA of the implementation under test')
    parser.add_argument('command',nargs=argparse.REMAINDER,help='-- adapter executable and its arguments')
    args=parser.parse_args(argv)
    if args.command and args.command[0]=='--':args.command=args.command[1:]
    if not args.command:parser.error('pass the language adapter after --')
    if args.max_errors<1 or args.request_timeout_seconds<=0:parser.error('max-errors and timeout must be positive')
    if args.automated_only and args.security_evidence:
        parser.error('--automated-only cannot be combined with --security-evidence')
    if bool(args.security_evidence) != bool(args.implementation_commit):
        parser.error('--security-evidence and --implementation-commit are both required')
    if args.implementation_commit and not re.fullmatch(r'[0-9a-f]{40}', args.implementation_commit):
        parser.error('--implementation-commit must be a complete lowercase 40-digit Git SHA')
    try:
        verify_root(ROOT)
        manifest = load_json(ROOT / 'manifest.json')
        evidence = (verify_security_evidence(args.security_evidence, args.implementation_commit, manifest)
                    if args.security_evidence else None)
    except Exception as exc:
        print(f'FAIL: fixtures cannot be trusted: {exc}',file=sys.stderr)
        return EXIT_UNTRUSTED
    try:
        bridge=Bridge(args.command,args.request_timeout_seconds)
    except Exception as exc:
        print(f'FAIL: adapter protocol unavailable: {exc}',file=sys.stderr)
        return EXIT_UNTRUSTED
    runner=SuiteRunner(bridge,args.max_errors)
    fatal=None
    protocol_failed=False
    try:runner.execute()
    except ProtocolError as exc:
        fatal=f'{type(exc).__name__}: {exc}'
        protocol_failed=True
    except Exception as exc:fatal=f'{type(exc).__name__}: {exc}'
    finally:bridge.close()
    if evidence:
        for audit in runner.manual_audits:
            audit['status'] = 'EVIDENCE_RECORDED_EXTERNAL_APPROVAL_REQUIRED'
    automated_failed = bool(fatal or runner.errors or any(s['failed'] for s in runner.counts.values()))
    outstanding = ([] if evidence else [audit['id'] for audit in runner.manual_audits])
    if protocol_failed:
        status, code = 'UNTRUSTED_PROTOCOL', EXIT_UNTRUSTED
    elif automated_failed:
        status, code = STATUS_FAIL, EXIT_AUTOMATED_FAIL
    elif outstanding:
        if args.automated_only:
            status, code = STATUS_AUDIT_NOT_PERFORMED, EXIT_AUTOMATED_ONLY_PASS
        else:
            status, code = STATUS_AUDIT_REQUIRED, EXIT_AUDIT_REQUIRED
    elif evidence:
        status, code = STATUS_EVIDENCE_RECORDED, EXIT_AUTOMATED_ONLY_PASS
    else:
        status, code = STATUS_AUTOMATED_PASS, EXIT_AUTOMATED_ONLY_PASS
    report={
        'status':status,
        'exit_code':code,
        'certification': ('REVIEW_EVIDENCE_RECORDED_EXTERNAL_APPROVAL_REQUIRED' if evidence
                          else 'NOT_A_CONFORMANCE_CERTIFICATION'),
        'security_evidence': ({'implementation_id': evidence['implementation_id'],
                              'implementation_commit': evidence['implementation_commit'],
                              'reviewer': evidence['reviewer'],
                              'reviewed_at_utc': evidence['reviewed_at_utc'],
                              'authenticated_by_runner': False} if evidence else None),
        'automated_passed':not automated_failed,
        'automated_only':args.automated_only,
        'outstanding_audits':outstanding,
        'audits':runner.manual_audits,
        'capabilities':sorted(bridge.capabilities),
        'counts':runner.counts,
        'executed_trials':runner.executed_trials,
        'generation_freshness':runner.generation_summary,
        'errors':runner.errors,
        'fatal':fatal,
        'statement':CERTIFICATION_STATEMENT,
    }
    if args.report_json:
        args.report_json.parent.mkdir(parents=True,exist_ok=True)
        args.report_json.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
    if automated_failed:
        print(f'{STATUS_FAIL}: shared fixture conformance against provided adapter')
    elif outstanding and not args.automated_only:
        print(f'{STATUS_AUDIT_REQUIRED}: every automated check passed, but manual security-audit '
              'obligations are outstanding. This is NOT a conformance certification.')
    elif outstanding:
        print(f'{STATUS_AUDIT_NOT_PERFORMED}: automated checks passed; the manual security audits were '
              'deliberately not performed by this run (--automated-only). This is NOT a conformance '
              'certification.')
    elif evidence:
        print(f'{STATUS_EVIDENCE_RECORDED}: automated checks passed, and matching human review '
              'evidence was recorded. External approval of reviewer authenticity is REQUIRED.')
    else:
        print(f'{STATUS_AUTOMATED_PASS}: every automated check passed and no audit obligation is registered')
    print(f'  exit code: {code}')
    for suite,count in runner.counts.items():print(f'  {suite}: {count}')
    print(f'  generation freshness: {runner.generation_summary}')
    for case_id, executed in sorted(runner.executed_trials.items()):
        print(f'  property trials: {case_id}: {executed}')
    for line in runner.errors[:args.max_errors]:print(f'  FAIL: {line}',file=sys.stderr)
    if fatal:print(f'  FATAL: {fatal}',file=sys.stderr)
    if outstanding:
        print(f'  OUTSTANDING AUDITS: {", ".join(outstanding)}')
    for audit in runner.manual_audits:print(f'  AUDIT REQUIRED: {audit["id"]}')
    return code

if __name__=='__main__':raise SystemExit(main())
