import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import premerge as control
import security_gate as gate

HEAD, BASE, MERGE = 'a' * 40, 'b' * 40, 'c' * 40
ENV = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'pull_request',
       'GITHUB_REPOSITORY': 'noelnovo/WalletTracker', 'GITHUB_REPOSITORY_ID': '909094292',
       'GITHUB_BASE_REF': 'dev', 'GITHUB_RUN_ID': '42', 'GITHUB_TOKEN': 'synthetic-only'}


def event():
    return {'number': 7, 'repository': {'id': 909094292}, 'pull_request': {
        'head': {'sha': HEAD}, 'base': {'sha': BASE, 'ref': 'dev', 'repo': {'id': 909094292}}}}


def archive(entries):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as bundle:
        for path, value in entries:
            bundle.writestr(path, value)
    return data.getvalue()


GOOD = [('build/reports/cyclonedx/bom.json', '{"bomFormat":"CycloneDX","components":[{}]}'),
        ('app/build/tmp/kotlin-classes/debug/Example.class', b'bytecode-data')]


class AndroidAdapterTests(unittest.TestCase):
    def test_jacoco_report_root_is_accepted_but_entities_are_rejected(self):
        report = 'app/build/reports/jacoco/jacocoTestReport/jacocoTestReport.xml'
        with tempfile.TemporaryDirectory() as directory:
            control.unpack_android(archive(GOOD + [(report, '<?xml version="1.0"?><report name="app"/>')]),
                                   Path(directory), coverage_report=report)
        for raw in ['<?xml version="1.0"?><unrelated/>',
                    '<?xml version="1.0"?><!DOCTYPE report [<!ENTITY x "y">]><report/>']:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(RuntimeError):
                control.unpack_android(archive(GOOD + [(report, raw)]), Path(directory), coverage_report=report)

    def test_profile_is_scoped_and_reuses_existing_instance(self):
        profile, expected = control.identity(event(), ENV)
        self.assertEqual(profile['adapter'], 'android')
        self.assertEqual(profile['instance'], 'instance-005')
        self.assertEqual(expected['event'], 'pull_request')
        self.assertEqual(profile['status_prefix'], 'security/sonarqube-dtrack-')
        self.assertEqual(profile['analysis_group'], 'wallettracker-security-analysis')

    def test_push_is_exact_and_protected_without_granting_web_push(self):
        env = dict(ENV, GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_SHA=HEAD)
        payload = {'repository': {'id': 909094292}, 'after': HEAD}
        profile, expected = control.identity(payload, env)
        self.assertEqual(expected['target'], 'main')
        self.assertTrue(gate.trusted_identity(dict(profile, provider='github-reusable'), env))
        for value in [dict(payload, deleted=True), dict(payload, after=BASE)]:
            with self.assertRaises(RuntimeError):control.identity(value, env)
        for value in [{'commit': {'sha': BASE}, 'protected': True}, {'commit': {'sha': HEAD}, 'protected': False}]:
            with patch.object(control, 'api', return_value=value), self.assertRaises(RuntimeError):
                control.candidate(profile, expected)
        with patch.object(control, 'api', return_value={'commit': {'sha': HEAD}, 'protected': True}):
            self.assertEqual(control.candidate(profile, expected), HEAD)
        with self.assertRaises(RuntimeError):
            control.identity({'repository': {'id': 864547743}, 'after': HEAD},
                dict(env, GITHUB_REPOSITORY='noelnovo/nn-PortFolio', GITHUB_REPOSITORY_ID='864547743'))

    def test_required_status_preserves_context_and_does_not_run_on_push(self):
        profile, expected = control.identity(event(), ENV)
        with patch.dict(os.environ, ENV), patch.object(control, 'api') as api:
            control.publish(profile, expected, 'pending')
            args = api.call_args.args
            self.assertEqual(args[1], '/statuses/' + HEAD)
            self.assertEqual(args[2]['context'], 'security/sonarqube-dtrack-dev')
            self.assertEqual(args[2]['state'], 'pending')
            api.reset_mock()
            control.publish(profile, dict(expected, event='push'), 'success')
            api.assert_not_called()

    def test_classes_and_bom_are_scanner_data_not_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control.unpack_android(archive(GOOD), root)
            self.assertTrue(json.loads((root / 'bom.json').read_text())['components'])
            cls = root / GOOD[1][0]
            self.assertEqual(cls.stat().st_mode & 0o777, 0o600)

    def test_invalid_missing_duplicate_or_executable_android_input_rejected(self):
        bad = [GOOD[:1], GOOD[1:], GOOD + [GOOD[1]], GOOD + [('ci/script.py', 'bad')],
               GOOD + [('../bad', 'bad')], [('build/reports/cyclonedx/bom.json', '{}'), GOOD[1]]]
        for entries in bad:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory, self.assertRaises(RuntimeError):
                control.unpack_android(archive(entries), Path(directory))
        link = zipfile.ZipInfo('app/build/tmp/kotlin-classes/debug/link.class')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(RuntimeError):
            control.unpack_android(archive(GOOD + [(link, '/etc/passwd')]), Path(directory))

    def test_no_success_status_after_gate_error_or_stale_candidate(self):
        profile, expected = control.identity(event(), ENV)
        for final in [BASE, MERGE]:
            with tempfile.TemporaryDirectory() as directory, \
                 patch.dict(os.environ, dict(ENV, SECURITY_BUILD_RESULT='success', SECURITY_CANDIDATE=MERGE)), \
                 patch.object(control, 'controller'), patch.object(control, 'candidate', side_effect=[MERGE, final]), \
                 patch.object(control, 'artifact', return_value=archive(GOOD)), patch.object(control, 'download', return_value=b'data'), \
                 patch.object(control, 'unpack_source'), patch.object(control.security_gate, 'ROOT'), \
                 patch.object(control.security_gate, 'scan') as scan, patch.object(control, 'publish') as publish:
                if final == MERGE:
                    scan.side_effect = RuntimeError('SonarQube quality gate failed; publication blocked')
                with self.assertRaises(RuntimeError):control.evaluate(profile, expected)
                publish.assert_not_called()


if __name__ == '__main__':unittest.main()
