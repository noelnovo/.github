"""Credential-free regression tests for security boundaries and hard failures."""
import importlib.util
import contextlib
import io
import json
import pathlib
import tempfile
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('security_gate', pathlib.Path(__file__).with_name('security_gate.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class SecurityTests(unittest.TestCase):
    def test_reusable_identity_is_bound_to_registered_caller(self):
        cfg = {'provider': 'github-reusable', 'repository': 'owner/repo', 'repository_id': '42', 'targets': ['main']}
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'pull_request',
               'GITHUB_REPOSITORY': 'owner/repo', 'GITHUB_REPOSITORY_ID': '42', 'GITHUB_BASE_REF': 'main'}
        self.assertTrue(gate.trusted_identity(cfg, env))
        for key, value in [('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REPOSITORY_ID', '99'), ('GITHUB_BASE_REF', 'other')]:
            self.assertFalse(gate.trusted_identity(cfg, dict(env, **{key: value})))
    def test_scanner_keeps_token_out_of_arguments_and_output(self):
        creds = {'SONAR_TOKEN': 'synthetic-credential', 'SONAR_HOST_URL': 'https://sonar.example.test',
                 'SONAR_PROJECT_KEY': 'android'}
        result = subprocess.CompletedProcess([], 0, stdout=b'Analysis report uploaded', stderr=b'')
        output = io.StringIO()
        with patch.object(gate.subprocess, 'run', return_value=result) as run, contextlib.redirect_stdout(output):
            self.assertTrue(gate.sonar(creds))
        args = run.call_args.args[0]
        self.assertIn('--entrypoint', args)
        self.assertEqual(args[args.index('--entrypoint') + 1], 'sonar-scanner')
        self.assertNotIn(creds['SONAR_TOKEN'], ' '.join(args))
        self.assertEqual(run.call_args.kwargs['env']['SONAR_TOKEN'], creds['SONAR_TOKEN'])
        self.assertEqual(run.call_args.kwargs['timeout'], 600)
        self.assertNotIn(creds['SONAR_TOKEN'], output.getvalue())
        self.assertTrue(json.loads(output.getvalue())['analysis_submitted'])

    def test_scanner_failure_emits_only_fixed_categories(self):
        creds = {'SONAR_TOKEN': 'synthetic-credential', 'SONAR_HOST_URL': 'https://sonar.example.test',
                 'SONAR_PROJECT_KEY': 'android'}
        result = subprocess.CompletedProcess([], 125, stdout=b'',
            stderr=b'toomanyrequests: synthetic-credential untrusted scanner details')
        output = io.StringIO()
        with patch.object(gate.subprocess, 'run', return_value=result), contextlib.redirect_stdout(output):
            self.assertFalse(gate.sonar(creds))
        diagnostic = json.loads(output.getvalue())
        self.assertEqual(diagnostic['scanner_exit_code'], 125)
        self.assertTrue(diagnostic['scanner_failure_categories']['registry_rate_limited'])
        self.assertNotIn('synthetic-credential', output.getvalue())
        self.assertNotIn('untrusted scanner details', output.getvalue())

    def test_https_required(self):
        for url in ['http://example.test', 'https://user:password@example.test']:
            with self.assertRaises(RuntimeError):
                gate.request(url)

    def test_github_identity(self):
        cfg = {'provider': 'github', 'repository': 'owner/repo', 'branches': ['dev'], 'workflow': 'validation.yml'}
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'owner/repo',
            'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/dev',
            'GITHUB_WORKFLOW_REF': 'owner/repo/.github/workflows/validation.yml@refs/heads/dev'}
        self.assertTrue(gate.trusted_identity(cfg, env))
        for field, value in [('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REF', 'refs/heads/feature'),
                             ('GITHUB_REPOSITORY', 'attacker/repo'), ('GITHUB_WORKFLOW_REF', 'unexpected')]:
            self.assertFalse(gate.trusted_identity(cfg, dict(env, **{field: value})))

    def test_premerge_identity_is_a_separate_trusted_target_workflow(self):
        cfg = {'provider': 'github', 'repository': 'owner/repo', 'branches': ['dev'],
               'workflow': 'premerge-security.yml', 'event': 'pull_request_target'}
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'owner/repo',
               'GITHUB_EVENT_NAME': 'pull_request_target', 'GITHUB_REF': 'refs/heads/dev',
               'GITHUB_WORKFLOW_REF': 'owner/repo/.github/workflows/premerge-security.yml@refs/heads/dev'}
        self.assertTrue(gate.trusted_identity(cfg, env))
        self.assertFalse(gate.trusted_identity(cfg, dict(env, GITHUB_EVENT_NAME='pull_request')))
        self.assertFalse(gate.trusted_identity(cfg, dict(env, GITHUB_WORKFLOW_REF='owner/repo/.github/workflows/validation.yml@refs/pull/7/merge')))

    def test_gitlab_identity(self):
        cfg = {'provider': 'gitlab', 'repository': 'downops/prompt-gateway', 'project_id': '10', 'branches': ['main']}
        env = {'GITLAB_CI': 'true', 'CI_PROJECT_PATH': cfg['repository'], 'CI_PROJECT_ID': '10',
            'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'main', 'CI_COMMIT_REF_PROTECTED': 'true'}
        self.assertTrue(gate.trusted_identity(cfg, env))
        for field, value in [('CI_PIPELINE_SOURCE', 'merge_request_event'), ('CI_COMMIT_REF_PROTECTED', 'false'),
                             ('CI_PROJECT_ID', '1'), ('CI_COMMIT_BRANCH', 'feature')]:
            self.assertFalse(gate.trusted_identity(cfg, dict(env, **{field: value})))

    def dt_responses(self, findings=None, policy=0, state=False):
        return [{'token': '00000000-0000-0000-0000-000000000001'}, {'processing': state},
                findings or [], {'policyViolationsFail': policy}]

    def run_dt(self, responses):
        creds = {'DT_URL': 'https://dt.example.test', 'DT_API_KEY': 'synthetic',
                 'DT_PROJECT_UUID': '00000000-0000-0000-0000-000000000002'}
        with patch.object(gate, 'request', side_effect=responses):
            return gate.dependency_track(creds, b'{}', wait=lambda _: None)

    def test_clean_pass(self):
        self.assertTrue(self.run_dt(self.dt_responses()))

    def test_high_and_critical_are_reported_for_sonar_to_evaluate(self):
        for severity in ['HIGH', 'CRITICAL']:
            self.assertTrue(self.run_dt(self.dt_responses([{'vulnerability': {'severity': severity}}])))

    def test_policy_counts_do_not_override_the_sonar_gate_threshold(self):
        self.assertTrue(self.run_dt(self.dt_responses(policy=1)))

    def test_invalid_processing_fails(self):
        with self.assertRaises(RuntimeError):
            self.run_dt(self.dt_responses(state=None))

    def test_missing_metrics_fail(self):
        with self.assertRaises(RuntimeError):
            self.run_dt(self.dt_responses(policy=None))

    def test_pagination(self):
        page = [{'vulnerability': {'severity': 'LOW'}}] * 100
        responses = self.dt_responses()[:2] + [page, [{'vulnerability': {'severity': 'HIGH'}}], {'policyViolationsFail': 0}]
        self.assertTrue(self.run_dt(responses))

    def test_plugin_settings_are_synchronized_from_vault_in_https_bodies(self):
        settings = {'SONAR_SETTINGS_TOKEN': 'synthetic-settings-token',
            'SONAR_HOST_URL': 'https://sonar.example.test', 'SONAR_PROJECT_KEY': 'android'}
        reader = {'DT_URL': 'https://dt.example.test', 'DT_PROJECT_UUID': 'project',
                  'DT_API_KEY': 'synthetic-read-only-key'}
        expected = [{'metric': 'new_dependencytrack_fixed_medium', 'op': 'GT', 'error': '2'}]
        responses = [{}, {}, {}, {'qualityGate': {'name': 'Configured by owner'}}, {'conditions': expected}]
        with patch.object(gate, 'request', side_effect=responses) as request:
            self.assertEqual(gate.synchronize_plugin(settings, reader), expected)
        calls = request.call_args_list
        self.assertEqual(calls[2].args[2], {'component': 'android',
            'key': 'sonar.dependencytrack.api.key', 'value': 'synthetic-read-only-key'})
        for call in calls[:3]:
            self.assertTrue(call.kwargs['form'])
            self.assertNotIn('synthetic-read-only-key', call.args[0])
            self.assertNotIn('synthetic-settings-token', call.args[0])

    def test_missing_dependency_conditions_fail_closed(self):
        settings = {'SONAR_SETTINGS_TOKEN': 'synthetic', 'SONAR_HOST_URL': 'https://sonar.example.test',
                    'SONAR_PROJECT_KEY': 'android'}
        reader = {'DT_URL': 'https://dt.example.test', 'DT_PROJECT_UUID': 'project', 'DT_API_KEY': 'synthetic'}
        with patch.object(gate, 'request', side_effect=[{}, {}, {}, {'qualityGate': {'name': 'Sonar way'}}, {'conditions': []}]):
            with self.assertRaises(RuntimeError):
                gate.synchronize_plugin(settings, reader)

    def verify_plugin(self, conditions, status='OK', task_project='android', expected=None):
        settings = {'SONAR_SETTINGS_TOKEN': 'synthetic', 'SONAR_HOST_URL': 'https://sonar.example.test',
                    'SONAR_PROJECT_KEY': 'android'}
        if expected is None:
            expected = [{'metric': 'new_dependencytrack_fixed_medium', 'op': 'GT', 'error': '2'}]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / '.scannerwork').mkdir()
            (root / '.scannerwork/report-task.txt').write_text('ceTaskId=exact-task\n')
            responses = [{'task': {'status': 'SUCCESS', 'componentKey': task_project, 'analysisId': 'exact-analysis'}},
                         {'projectStatus': {'status': status, 'conditions': conditions}}]
            with patch.object(gate, 'ROOT', root), patch.object(gate, 'request', side_effect=responses) as request:
                result = gate.verify_plugin_gate(settings, expected)
                self.assertIn('analysisId=exact-analysis', request.call_args.args[0])
                return result

    def test_configured_plugin_metric_can_fail_sonar_gate(self):
        condition = {'metricKey': 'new_dependencytrack_fixed_medium', 'comparator': 'GT',
                     'actualValue': '3', 'errorThreshold': '2', 'status': 'ERROR'}
        self.assertFalse(self.verify_plugin([condition], 'ERROR'))
        condition.update(actualValue='1', status='OK')
        self.assertTrue(self.verify_plugin([condition]))

    def test_missing_or_changed_plugin_measure_fails_closed(self):
        for conditions in [[], [{'metricKey': 'new_dependencytrack_fixed_medium', 'comparator': 'GT',
                'actualValue': '0', 'errorThreshold': '999', 'status': 'OK'}]]:
            with self.assertRaises(RuntimeError):
                self.verify_plugin(conditions)

    def test_other_project_cannot_supply_plugin_evidence(self):
        with self.assertRaises(RuntimeError):
            self.verify_plugin([], task_project='another-project')

    def test_redirects_refused(self):
        self.assertIsNone(gate.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_analysis_timeout_fails(self):
        responses = [{'token': '00000000-0000-0000-0000-000000000001'}] + [{'processing': True}] * 120
        with self.assertRaises(RuntimeError):
            self.run_dt(responses)

    def test_reuse_rejects_wrong_source_or_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'security-image.tar').write_bytes(b'synthetic-image')
            for receipt in [{'revision': 'other', 'sha256': gate.file_hash(root / 'security-image.tar')},
                            {'revision': 'current', 'sha256': 'wrong'}]:
                (root / 'security-image.json').write_text(json.dumps(receipt))
                with patch.object(gate, 'ROOT', root), patch.object(gate.subprocess, 'check_output', return_value='current\n'), patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaises(RuntimeError):
                        gate.reuse()
                    run.assert_not_called()

    def test_reuse_checks_loaded_image_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'security-image.tar').write_bytes(b'synthetic-image')
            receipt = {'revision': 'current', 'sha256': gate.file_hash(root / 'security-image.tar'), 'image_id': 'expected'}
            (root / 'security-image.json').write_text(json.dumps(receipt))
            image = [{'Id': 'unexpected', 'Config': {'Labels': {'org.opencontainers.image.revision': 'current'}}}]
            with patch.object(gate, 'ROOT', root), patch.object(gate.subprocess, 'check_output', side_effect=['current\n', json.dumps(image).encode()]), patch.object(gate.subprocess, 'run'):
                with self.assertRaises(RuntimeError):
                    gate.reuse()


if __name__ == '__main__':
    unittest.main()
