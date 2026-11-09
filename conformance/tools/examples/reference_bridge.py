#!/usr/bin/env python3
"""DEMONSTRATION BRIDGE ONLY. Not a PikaID product implementation.

Useful for testing the JSONL transport and shared runner. Real language bridges
MUST call their actual library, never this Python reference implementation.

Environment knobs used by the runner's own negative tests:

* ``PIKAID_EXAMPLE_MINIMAL=1``        advertise only the mandatory capabilities.
* ``PIKAID_EXAMPLE_MISSING_REQUIRED=1`` omit a mandatory capability.
* ``PIKAID_EXAMPLE_MUTANT=1``          deliberately accept one invalid string.
* ``PIKAID_EXAMPLE_CONSTANT_RNG=1``    reuse one 96-bit randomness value.
* ``PIKAID_EXAMPLE_DEGENERATE_RNG=1``  emit all-zero 96-bit randomness.
* ``PIKAID_EXAMPLE_COUNTER_RNG=1``     emit an incrementing 96-bit counter.
* ``PIKAID_EXAMPLE_INJECTION_IGNORED=1`` advertise fault injection but ignore it.
* ``PIKAID_EXAMPLE_CRASH_INVALID=1``   crash internally on one invalid text input.
* ``PIKAID_EXAMPLE_MISSING_DATETIME=1`` claim datetime but omit the result.
* ``PIKAID_EXAMPLE_NO_DATETIME=1``    expose only integer-based parsing.
* ``PIKAID_EXAMPLE_WRONG_FAULT_CATEGORY=1`` report a validation error for RNG failure.
* ``PIKAID_EXAMPLE_BAD_REQUEST_ID=1`` send a boolean request ID in hello.
* ``PIKAID_EXAMPLE_BAD_ERROR_FORMAT=1`` send a legacy string error on bad input.
"""
from __future__ import annotations
import json
import os
import secrets
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from verify_vectors import strict_text_to_binary, strict_binary_to_text, MAX_TIMESTAMP, FixtureError

CAPS=['generate_string','text_to_binary','binary_to_text','boolean_validation','format_only_validation','parse_components','parse_datetime','generate_with_timestamp','generate_binary','generate_binary_with_timestamp','public_compare','csprng_failure_injection']

# Mutable adapter state for the optional fault-injection capability.
STATE={'csprng_failure':False}
CONSTANT_RANDOMNESS=bytes.fromhex('00112233445566778899aabb')
COUNTER_STATE=[0]

class EntropyFailure(Exception):
    """Raised only when the production entropy source is unavailable."""


def randomness() -> bytes:
    if STATE['csprng_failure']:
        if os.environ.get('PIKAID_EXAMPLE_WRONG_FAULT_CATEGORY')=='1':
            raise FixtureError('RNG source failure mislabeled as validation')
        raise EntropyFailure('CSPRNG failure injected')
    if os.environ.get('PIKAID_EXAMPLE_DEGENERATE_RNG')=='1':
        return bytes(12)
    if os.environ.get('PIKAID_EXAMPLE_CONSTANT_RNG')=='1':
        return CONSTANT_RANDOMNESS
    if os.environ.get('PIKAID_EXAMPLE_COUNTER_RNG')=='1':
        COUNTER_STATE[0]+=1
        return COUNTER_STATE[0].to_bytes(12,'big')
    return secrets.token_bytes(12)


def op(name, a):
    if name=='hello':
        capabilities=CAPS
        if os.environ.get('PIKAID_EXAMPLE_MINIMAL')=='1':capabilities=CAPS[:3]
        if os.environ.get('PIKAID_EXAMPLE_MISSING_REQUIRED')=='1':capabilities=CAPS[:2]
        if os.environ.get('PIKAID_EXAMPLE_NO_DATETIME')=='1':
            capabilities=[c for c in capabilities if c!='parse_datetime']
        return {'protocol_version':1,'capabilities':capabilities}
    if name=='inject_fault':
        fault=a.get('fault')
        active=a.get('active')
        if fault!='csprng_failure' or type(active) is not bool:
            raise FixtureError('unsupported fault injection request')
        if os.environ.get('PIKAID_EXAMPLE_INJECTION_IGNORED')!='1':
            STATE[fault]=active
        return {'fault':fault,'active':active}
    if name=='text_to_binary':
        if os.environ.get('PIKAID_EXAMPLE_CRASH_INVALID')=='1' and a['text']=='0000000'+'z'*19:
            raise RuntimeError('unexpected internal decoder crash')
        if os.environ.get('PIKAID_EXAMPLE_MUTANT')=='1' and a['text']=='0000000'+'z'*19:
            return '00'*17 # A deliberate invalid acceptance, used to test the shared runner's failure gate.
        return strict_text_to_binary(a['text']).hex()
    if name=='binary_to_text':return strict_binary_to_text(bytes.fromhex(a['binary_hex']))
    if name=='boolean_validation':
        try:strict_text_to_binary(a['text']);return True
        except FixtureError:return False
    if name=='format_only_validation':
        from verify_vectors import is_well_formed
        return is_well_formed(a['text'])
    if name=='parse_components':
        binary=strict_text_to_binary(a['text'])
        from datetime import datetime, timezone
        ts=int.from_bytes(binary[:5],'big')
        result={'timestamp_seconds':ts,'randomness_hex':binary[5:].hex()}
        if (os.environ.get('PIKAID_EXAMPLE_NO_DATETIME')!='1'
                and os.environ.get('PIKAID_EXAMPLE_MISSING_DATETIME')!='1'):
            result['datetime_utc']=datetime.fromtimestamp(ts,timezone.utc).isoformat().replace('+00:00','Z')
        return result
    if name=='public_compare':
        strict_text_to_binary(a['a']);strict_text_to_binary(a['b'])
        return (a['a']>a['b'])-(a['a']<a['b'])
    if name in ('generate_string','generate_binary','generate_with_timestamp','generate_binary_with_timestamp'):
        ts=a.get('timestamp_seconds',int(time.time()))
        if type(ts) is not int or ts<0 or ts>MAX_TIMESTAMP:raise FixtureError('invalid timestamp')
        binary=ts.to_bytes(5,'big')+randomness()
        return binary.hex() if name in ('generate_binary','generate_binary_with_timestamp') else strict_binary_to_text(binary)
    raise NotImplementedError(f'unknown operation: {name}')


for line in sys.stdin:
    try:
        req=json.loads(line)
        value=op(req['operation'],req['arguments'])
        reply={'request_id':req['request_id'],'ok':True,'value':value}
    except EntropyFailure as exc:
        reply={'request_id':req.get('request_id'),'ok':False,
               'error':{'category':'entropy_unavailable','message':str(exc)}}
    except FixtureError as exc:
        reply={'request_id':req.get('request_id'),'ok':False,
               'error':{'category':'invalid_input','message':str(exc)}}
    except NotImplementedError as exc:
        reply={'request_id':req.get('request_id'),'ok':False,
               'error':{'category':'unsupported_operation','message':str(exc)}}
    except Exception as exc:
        reply={'request_id':req.get('request_id'),'ok':False,
               'error':{'category':'internal_error','message':str(exc)}}
    if os.environ.get('PIKAID_EXAMPLE_BAD_REQUEST_ID')=='1' and req.get('operation')=='hello':
        reply['request_id']=True
    if (os.environ.get('PIKAID_EXAMPLE_BAD_ERROR_FORMAT')=='1'
            and req.get('operation')=='text_to_binary' and not reply.get('ok')):
        reply['error']='legacy unstructured error'
    sys.stdout.write(json.dumps(reply,separators=(',',':'))+'\n')
    sys.stdout.flush()
