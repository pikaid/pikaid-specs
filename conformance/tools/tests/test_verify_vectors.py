"""Mutation tests for the independent PikaID fixture validator."""
from __future__ import annotations
import json
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_vectors import MAX_TIMESTAMP, MAX_RANDOMNESS, NON_SOURCE_NAMES, FixtureError, ROOT, is_well_formed, strict_binary_to_text, strict_text_to_binary, to_base36, verify_root


def regenerate_checksums(dest: Path) -> None:
    entries = []
    for path in dest.rglob('*'):
        if not path.is_file() or path.name == 'SHA256SUMS':
            continue
        if '__pycache__' in path.parts or path.suffix in ('.pyc', '.pyo'):
            continue
        if path.name in NON_SOURCE_NAMES:
            continue
        entries.append((path.relative_to(dest).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    lines = [f'{digest}  {relative}' for relative, digest in sorted(entries)]
    (dest / 'SHA256SUMS').write_text('\n'.join(lines) + '\n', encoding='utf8')


def mutated_bundle(mutate) -> tempfile.TemporaryDirectory:
    """Copy the package, apply ``mutate(dest)``, and re-sign the checksums.

    Re-signing simulates an attacker (or an accidental editor) who can update
    hashes: semantic hardening must still reject the weakened package.
    """
    holder = tempfile.TemporaryDirectory()
    dest = Path(holder.name) / 'bundle'
    shutil.copytree(ROOT, dest)
    mutate(dest)
    regenerate_checksums(dest)
    return holder


def mutated_bundle_no_resign(mutate) -> tempfile.TemporaryDirectory:
    """Copy the package and mutate it without touching SHA256SUMS."""
    holder = tempfile.TemporaryDirectory()
    dest = Path(holder.name) / 'bundle'
    shutil.copytree(ROOT, dest)
    mutate(dest)
    return holder


class FixtureValidatorTests(unittest.TestCase):
    def test_full_bundle(self):
        counts=verify_root()
        self.assertGreater(counts['valid'], 500)
        self.assertGreater(counts['invalid-string'], 100)
        self.assertGreater(counts['invalid-binary'], 25)
        self.assertGreater(counts['ordering'], 150)

    def test_mandatory_property_cannot_be_downgraded_to_conditional(self):
        def mutate(dest):
            f=dest/'cases'/'properties.json'
            data=json.loads(f.read_text())
            data['cases'][0]['scope']='conditional'
            f.write_text(json.dumps(data,indent=2)+'\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError,'requires .mandatory. scope'):
                verify_root(Path(tmp)/'bundle')

    def test_512_trial_floor_cannot_be_downgraded_to_32(self):
        def mutate(dest):
            f=dest/'cases'/'properties.json'
            data=json.loads(f.read_text())
            data['cases'][0]['minimum_trials']=32
            f.write_text(json.dumps(data,indent=2)+'\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError,'at least 512 executed trials'):
                verify_root(Path(tmp)/'bundle')

    def test_manifest_capabilities_must_match_protocol_vocabulary(self):
        def mutate(dest):
            f=dest/'manifest.json'
            data=json.loads(f.read_text())
            data['mandatory_capabilities']=['generate_string','strict_string_to_binary','binary_to_text']
            f.write_text(json.dumps(data,indent=2)+'\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError,'manifest mandatory capabilities differ'):
                verify_root(Path(tmp)/'bundle')

    def test_valid_corpus_duplicate_rejected(self):
        def mutate(dest):
            f=dest/'cases'/'valid.json'
            data=json.loads(f.read_text())
            case=dict(data['cases'][0]);case['id']='V-NEW-DUPLICATE'
            data['cases'].append(case)
            f.write_text(json.dumps(data,indent=2)+'\n')
            mf=dest/'manifest.json'
            manifest=json.loads(mf.read_text())
            manifest['fixtures'][0]['cases']=len(data['cases'])
            mf.write_text(json.dumps(manifest,indent=2)+'\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError,'duplicate canonical identifiers'):
                verify_root(Path(tmp)/'bundle')

    def test_zero_and_maximum(self):
        self.assertEqual('0'*26, strict_binary_to_text(bytes(17)))
        upper=MAX_TIMESTAMP.to_bytes(5,'big') + b'\xff'*12
        self.assertEqual('zzzzzzz7oiylpimjg5u2ca1ypr', strict_binary_to_text(upper))
        self.assertEqual(upper, strict_text_to_binary('zzzzzzz7oiylpimjg5u2ca1ypr'))

    def test_randomness_overflow_fails_despite_valid_shape(self):
        value='0000000' + to_base36(MAX_RANDOMNESS+1).rjust(19,'0')
        self.assertTrue(is_well_formed(value))
        with self.assertRaises(FixtureError): strict_text_to_binary(value)

    def test_binary_timestamp_overflow(self):
        value=(MAX_TIMESTAMP+1).to_bytes(5,'big')+bytes(12)
        with self.assertRaises(FixtureError):strict_binary_to_text(value)

    def test_binary_wrong_sizes(self):
        for n in [0,1,16,18,128]:
            with self.subTest(n=n), self.assertRaises(FixtureError): strict_binary_to_text(bytes(n))

    def test_string_rejection(self):
        for value in ['A'+'0'*25, 'é'+'0'*25, '0'*25, '0'*27, '0'*26+'\n', '0'*10+'\x00'+'0'*15]:
            with self.subTest(input=repr(value)), self.assertRaises(FixtureError): strict_text_to_binary(value)

    def test_no_silent_unicode_normalization(self):
        self.assertFalse(is_well_formed('0'*12+'𝟘'+'0'*13))
        self.assertFalse(is_well_formed('0'*12+'０'+'0'*13))

    def test_lexical_digit_carries(self):
        self.assertEqual('10', to_base36(36))
        self.assertEqual('100', to_base36(1296))
        self.assertEqual('zzzzzzz', to_base36(MAX_TIMESTAMP))

    def test_duplicate_json_properties_are_rejected(self):
        from verify_vectors import reject_duplicates
        with self.assertRaises(FixtureError):
            json.loads('{"suite":"valid","suite":"invalid"}',object_pairs_hook=reject_duplicates)

    def test_semantic_mismatch_rejected_even_with_updated_checksums(self):
        # Hashes alone are insufficient; the independent mathematical oracle must reject edits.
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'bundle'
            shutil.copytree(ROOT,dest)
            fixture=dest/'cases'/'valid.json'
            data=json.loads(fixture.read_text())
            data['cases'][0]['pikaid']='0000000'+'0'*18+'1'
            fixture.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
            checksum=dest/'SHA256SUMS'
            entries=[]
            for line in checksum.read_text().splitlines():
                digest, rel=line.split('  ',1)
                if rel=='cases/valid.json':digest=hashlib.sha256(fixture.read_bytes()).hexdigest()
                entries.append(digest+'  '+rel)
            checksum.write_text('\n'.join(entries)+'\n')
            with self.assertRaisesRegex(FixtureError,'incorrect Base36 encoding'):
                verify_root(dest)

    def test_integrity_rejects_tampered_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'bundle'
            shutil.copytree(ROOT,dest)
            fixture=dest/'cases'/'valid.json'
            fixture.write_bytes(fixture.read_bytes().replace(b'V-SPEC-ZERO', b'V-SPEC-FAKE',1))
            with self.assertRaisesRegex(FixtureError,'checksum mismatch'): verify_root(dest)

    # -- AUD-001: operating-system metadata ------------------------------

    def test_uppercase_alphabet_coverage_enforced(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'invalid-string.json'
            data = json.loads(fixture.read_text())
            data['cases'] = [case for case in data['cases']
                             if not any(letter == 'Q' for letter in case['input'])]
            fixture.write_text(json.dumps(data, indent=2) + '\n')
            manifest = json.loads((dest / 'manifest.json').read_text())
            for entry in manifest['fixtures']:
                if entry['path'] == 'cases/invalid-string.json':
                    entry['cases'] = len(data['cases'])
            (dest / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'missing uppercase letters'):
                verify_root(Path(tmp) / 'bundle')

    def test_os_metadata_is_ignored_but_reported(self):
        def mutate(dest):
            (dest / '.DS_Store').write_bytes(b'junk')
            (dest / 'tools' / '.DS_Store').write_bytes(b'junk')
        with mutated_bundle(mutate) as tmp:
            counts = verify_root(Path(tmp) / 'bundle')
            self.assertEqual(['.DS_Store', 'tools/.DS_Store'], counts['_ignored_non_source'])

    def test_checksummed_os_metadata_is_rejected(self):
        def mutate(dest):
            (dest / '.DS_Store').write_bytes(b'junk')
            with (dest / 'SHA256SUMS').open('a', encoding='utf8') as handle:
                handle.write(hashlib.sha256(b'junk').hexdigest() + '  .DS_Store\n')
        with mutated_bundle_no_resign(mutate) as tmp:
            with self.assertRaises(FixtureError):
                verify_root(Path(tmp) / 'bundle')

    # -- FIX-001: weakened generation/property corpora -------------------

    def test_weakened_generation_trial_count_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'generation.json'
            data = json.loads(fixture.read_text())
            for case in data['cases']:
                if case['id'] == 'G-CURRENT-STRING':
                    case['iteration_count'] = 1
            fixture.write_text(json.dumps(data, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'at least 32 fresh samples'):
                verify_root(Path(tmp) / 'bundle')

    def test_generation_corpus_below_freshness_floor_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'generation.json'
            data = json.loads(fixture.read_text())
            for case in data['cases']:
                if case['id'] == 'G-CURRENT-STRING':
                    # Still above the per-scenario floor but below the aggregate
                    # mandatory freshness floor a minimal adapter needs.
                    case['iteration_count'] = 40
            fixture.write_text(json.dumps(data, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'freshness floor'):
                verify_root(Path(tmp) / 'bundle')

    def test_flipped_generation_expectation_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'generation.json'
            data = json.loads(fixture.read_text())
            for case in data['cases']:
                if case['id'] == 'G-TIMESTAMP-BELOW':
                    case['expected'] = 'canonical_valid_id_with_exact_timestamp'
            fixture.write_text(json.dumps(data, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'accepted timestamp out-of-range|reject is not out-of-range'):
                verify_root(Path(tmp) / 'bundle')

    def test_duplicate_generation_scenario_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'generation.json'
            data = json.loads(fixture.read_text())
            for case in data['cases']:
                if case['id'] == 'G-TIMESTAMP-ONE':
                    case['timestamp_seconds'] = 0
            fixture.write_text(json.dumps(data, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'duplicate generation scenario'):
                verify_root(Path(tmp) / 'bundle')

    def test_dropped_generation_reject_coverage_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'generation.json'
            data = json.loads(fixture.read_text())
            data['cases'] = [c for c in data['cases']
                             if not (c['mode'] == 'caller_supplied_binary' and c['expected'] == 'reject')]
            fixture.write_text(json.dumps(data, indent=2) + '\n')
            manifest = dest / 'manifest.json'
            document = json.loads(manifest.read_text())
            for entry in document['fixtures']:
                if entry['path'] == 'cases/generation.json':
                    entry['cases'] = len(data['cases'])
            manifest.write_text(json.dumps(document, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'missing out-of-range rejection scenario'):
                verify_root(Path(tmp) / 'bundle')

    def test_weakened_property_trial_count_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'properties.json'
            data = json.loads(fixture.read_text())
            for case in data['cases']:
                if case['id'] == 'P-PARSE-COMPONENTS':
                    case['minimum_trials'] = 1
            fixture.write_text(json.dumps(data, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'needs at least 32 executed trials'):
                verify_root(Path(tmp) / 'bundle')

    def test_runtime_property_downgraded_to_audit_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'properties.json'
            data = json.loads(fixture.read_text())
            for case in data['cases']:
                if case['id'] == 'P-PARSE-COMPONENTS':
                    case['scope'] = 'audit'
                    case['minimum_trials'] = 0
            fixture.write_text(json.dumps(data, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'requires .conditional. scope'):
                verify_root(Path(tmp) / 'bundle')

    def test_audit_obligation_claimed_as_automated_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'properties.json'
            data = json.loads(fixture.read_text())
            for case in data['cases']:
                if case['id'] == 'P-GENERATE-RNG-SOURCE':
                    case['scope'] = 'mandatory'
                    case['minimum_trials'] = 32
            fixture.write_text(json.dumps(data, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'requires .audit. scope'):
                verify_root(Path(tmp) / 'bundle')

    def test_duplicate_property_strategy_rejected(self):
        def mutate(dest):
            fixture = dest / 'cases' / 'properties.json'
            data = json.loads(fixture.read_text())
            for case in data['cases']:
                if case['id'] == 'P-BOOL-VALIDATION':
                    case['strategy'] = 'parse_components'
            fixture.write_text(json.dumps(data, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'duplicate property'):
                verify_root(Path(tmp) / 'bundle')

    # -- GATE-002: release policy is separate from integrity -------------

    def test_official_package_passes_integrity(self):
        def mutate(dest):
            manifest = dest / 'manifest.json'
            document = json.loads(manifest.read_text())
            document['status'] = 'OFFICIAL'
            document['package_revision'] = '1.0.0'
            manifest.write_text(json.dumps(document, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            verify_root(Path(tmp) / 'bundle')
            with self.assertRaisesRegex(FixtureError, 'does not match expected'):
                verify_root(Path(tmp) / 'bundle', expect_status='UNRELEASED')

    def test_nonstable_revision_with_released_status_rejected(self):
        def mutate(dest):
            manifest = dest / 'manifest.json'
            document = json.loads(manifest.read_text())
            document['package_revision'] = '1.0.0-unstable'
            manifest.write_text(json.dumps(document, indent=2) + '\n')
        with mutated_bundle(mutate) as tmp:
            with self.assertRaisesRegex(FixtureError, 'schema invalid|malformed package revision'):
                verify_root(Path(tmp) / 'bundle')

    def test_release_policy_expectations_are_enforced(self):
        with self.assertRaisesRegex(FixtureError, 'does not match expected'):
            verify_root(expect_package_revision='9.9.9')
        with self.assertRaisesRegex(FixtureError, 'does not match expected'):
            verify_root(expect_spec_revision='0.0.1')
        verify_root(expect_status='OFFICIAL', expect_package_revision='1.0.0',
                    expect_spec_revision='1.0.4')


if __name__ == '__main__': unittest.main()
