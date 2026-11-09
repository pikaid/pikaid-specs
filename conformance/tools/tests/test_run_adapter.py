"""End-to-end tests for the shared runner and its fail-closed behavior.

The demonstration bridge checks the transport and runner, not a production
identifier implementation.
"""
from __future__ import annotations
import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RUNNER=ROOT/'tools'/'run_adapter.py'
BRIDGE=ROOT/'tools'/'examples'/'reference_bridge.py'

class RunnerIntegrationTests(unittest.TestCase):
    def run_demo(self, *args, **extra_env):
        env=os.environ.copy()
        env.update(extra_env)
        env['PYTHONDONTWRITEBYTECODE']='1'
        return subprocess.run([sys.executable,str(RUNNER),'--max-errors','1',*args,'--',sys.executable,str(BRIDGE)],env=env,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=180)

    def test_reference_transport_passes_but_requires_audit(self):
        result=self.run_demo()
        self.assertEqual(3,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('AUTOMATED_PASS_AUDIT_REQUIRED',result.stdout)
        self.assertIn('AUDIT REQUIRED',result.stdout)
        self.assertIn('NOT a conformance certification',result.stdout)

    def test_automated_only_opt_in_is_explicitly_not_a_certification(self):
        result=self.run_demo('--automated-only')
        self.assertEqual(0,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('AUTOMATED_PASS_AUDIT_NOT_PERFORMED',result.stdout)
        self.assertIn('NOT a conformance certification',result.stdout)
        self.assertIn('AUDIT REQUIRED',result.stdout)

    def test_constant_randomness_is_caught(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_CONSTANT_RNG='1')
        self.assertEqual(1,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('generation/FRESHNESS',result.stderr)
        self.assertIn('reused 96-bit randomness',result.stderr)

    def test_degenerate_randomness_is_caught(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_DEGENERATE_RNG='1')
        self.assertEqual(1,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('degenerate randomness',result.stderr)

    def test_counter_randomness_is_caught(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_COUNTER_RNG='1')
        self.assertEqual(1,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('constant delta',result.stderr)

    def test_advertised_fault_injection_must_fail_closed(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_INJECTION_IGNORED='1')
        self.assertEqual(1,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('accepted or incorrectly rejected a CSPRNG failure',result.stderr)

    def test_internal_error_must_not_count_as_invalid_input_rejection(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_CRASH_INVALID='1')
        self.assertEqual(1,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('adapter internal_error',result.stderr)

    def test_old_unstructured_error_envelope_is_untrusted(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_BAD_ERROR_FORMAT='1')
        self.assertEqual(2,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('structured error',result.stderr)

    def test_response_id_must_be_a_real_integer_not_boolean(self):
        result=self.run_demo(PIKAID_EXAMPLE_BAD_REQUEST_ID='1')
        self.assertEqual(2,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('response envelope',result.stderr)

    def test_rng_failure_cannot_be_mislabeled_as_input_validation(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_WRONG_FAULT_CATEGORY='1')
        self.assertEqual(1,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('incorrectly rejected a CSPRNG failure',result.stderr)

    def test_claimed_datetime_must_be_returned(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_MISSING_DATETIME='1')
        self.assertEqual(1,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('advertised parse_datetime but no datetime_utc',result.stderr)

    def test_integer_only_parser_is_allowed_without_utc_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            report=Path(tmp)/'report.json'
            result=self.run_demo('--automated-only','--report-json',str(report),
                                 PIKAID_EXAMPLE_NO_DATETIME='1')
            self.assertEqual(0,result.returncode,result.stdout+'\n'+result.stderr)
            info=json.loads(report.read_text())
            self.assertNotIn('P-PARSE-UTC',info['executed_trials'])
            # One human CSPRNG audit is always not-applicable to the automated
            # runner, and the optional datetime property is also not-applicable.
            self.assertEqual(2,info['counts']['properties']['not_applicable'])

    @staticmethod
    def make_security_evidence(path,commit='a'*40):
        doc={'format':'pikaid-csprng-review-v1',
             'implementation_id':'example/identifier-library',
             'implementation_commit':commit,
             'spec_revision':'1.0.4','suite_revision':'1.0.0',
             'reviewed_at_utc':'2026-11-09T08:00:00Z',
             'reviewer':'independent-security-reviewer',
             'checks':[
                 {'id':'P-GENERATE-RNG-SOURCE','result':'PASS',
                  'evidence':[{'path':'src/generator.ext','line_start':10,'line_end':24}]},
                 {'id':'P-GENERATE-RNG-FAILURE','result':'PASS',
                  'evidence':[{'path':'tests/generator_test.ext','line_start':50,'line_end':80}]},
             ]}
        path.write_text(json.dumps(doc),encoding='utf8')
        return doc

    def test_review_evidence_must_match_exact_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)/'review.json'
            self.make_security_evidence(evidence)
            result=self.run_demo('--security-evidence',str(evidence),'--implementation-commit','b'*40)
            self.assertEqual(2,result.returncode,result.stdout+'\n'+result.stderr)
            self.assertIn('evidence commit differs',result.stderr)

    def test_review_evidence_fails_closed_if_a_check_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)/'review.json'
            doc=self.make_security_evidence(evidence)
            doc['checks']=doc['checks'][:1]
            evidence.write_text(json.dumps(doc),encoding='utf8')
            result=self.run_demo('--security-evidence',str(evidence),'--implementation-commit','a'*40)
            self.assertEqual(2,result.returncode,result.stdout+'\n'+result.stderr)

    def test_review_evidence_rejects_external_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)/'review.json'
            doc=self.make_security_evidence(evidence)
            doc['checks'][0]['evidence'][0]['path']='https://example.invalid/file'
            evidence.write_text(json.dumps(doc),encoding='utf8')
            result=self.run_demo('--security-evidence',str(evidence),'--implementation-commit','a'*40)
            self.assertEqual(2,result.returncode,result.stdout+'\n'+result.stderr)
            self.assertIn('schema invalid',result.stderr)

    def test_review_evidence_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)/'review.json'
            doc=self.make_security_evidence(evidence)
            doc['checks'][0]['evidence'][0]['path']='../outside/source.ext'
            evidence.write_text(json.dumps(doc),encoding='utf8')
            result=self.run_demo('--security-evidence',str(evidence),'--implementation-commit','a'*40)
            self.assertEqual(2,result.returncode,result.stdout+'\n'+result.stderr)
            self.assertIn('schema invalid',result.stderr)

    def test_review_evidence_rejects_reversed_line_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)/'review.json'
            doc=self.make_security_evidence(evidence)
            doc['checks'][0]['evidence'][0]['line_end']=1
            evidence.write_text(json.dumps(doc),encoding='utf8')
            result=self.run_demo('--security-evidence',str(evidence),'--implementation-commit','a'*40)
            self.assertEqual(2,result.returncode,result.stdout+'\n'+result.stderr)
            self.assertIn('line_end precedes line_start',result.stderr)

    def test_review_evidence_recorded_but_not_authenticity_certification(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)/'review.json'
            report=Path(tmp)/'report.json'
            self.make_security_evidence(evidence)
            result=self.run_demo('--security-evidence',str(evidence),
                                 '--implementation-commit','a'*40,
                                 '--report-json',str(report))
            self.assertEqual(0,result.returncode,result.stdout+'\n'+result.stderr)
            info=json.loads(report.read_text())
            self.assertEqual('AUTOMATED_PASS_WITH_REVIEW_EVIDENCE',info['status'])
            self.assertFalse(info['security_evidence']['authenticated_by_runner'])
            self.assertEqual([],info['outstanding_audits'])

    def test_mutation_is_caught(self):
        result=self.run_demo(PIKAID_EXAMPLE_MUTANT='1')
        self.assertEqual(1,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('invalid text was accepted',result.stderr)

    def test_missing_mandatory_capability_is_caught(self):
        result=self.run_demo(PIKAID_EXAMPLE_MISSING_REQUIRED='1')
        self.assertEqual(2,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('missing mandatory capabilities',result.stderr)

    def test_optional_capabilities_can_be_absent(self):
        result=self.run_demo('--automated-only',PIKAID_EXAMPLE_MINIMAL='1')
        self.assertEqual(0,result.returncode,result.stdout+'\n'+result.stderr)
        self.assertIn('not_applicable',result.stdout)

    def test_report_records_executed_trial_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report=Path(tmp)/'report.json'
            result=self.run_demo('--automated-only','--report-json',str(report))
            self.assertEqual(0,result.returncode,result.stdout+'\n'+result.stderr)
            data=json.loads(report.read_text())
            self.assertEqual('NOT_A_CONFORMANCE_CERTIFICATION',data['certification'])
            self.assertEqual(0,data['exit_code'])
            self.assertIn('P-PARSE-COMPONENTS',data['executed_trials'])
            self.assertEqual(32,data['executed_trials']['P-PARSE-COMPONENTS'])
            self.assertGreaterEqual(data['generation_freshness']['distinct'],64)


if __name__=='__main__':unittest.main()
