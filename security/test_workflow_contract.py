from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CODE_PIN = 'e254078ff2ae582aa42842bc0f1017519cce8579'


class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/dependency-track-scan.yml').read_text()

    def test_one_canonical_security_entrypoint(self):
        self.assertFalse((ROOT / '.github/workflows/sonar-dtrack-pr.yml').exists())
        self.assertIn('workflow_call:', self.workflow)
        self.assertNotIn('VAULT_TOKEN:', self.workflow)
        self.assertNotIn('DT_API_KEY:', self.workflow)

    def test_unified_entrypoint_preserves_shared_serialization(self):
        self.assertIn("format('sonar-dtrack-analysis-{0}', github.repository_id)", self.workflow)
        self.assertIn('needs.candidate.outputs.analysis_group', self.workflow)
        self.assertIn('group: reusable-security-${{ github.repository_id }}-${{ github.event.pull_request.number || github.ref }}', self.workflow)
        self.assertEqual(self.workflow.count('queue: max'), 2)

    def test_control_pin_is_literal_not_caller_controlled(self):
        self.assertEqual(self.workflow.count('ref: ' + CODE_PIN), 2)
        self.assertEqual(self.workflow.count('SECURITY_CONTROL_SHA: ' + CODE_PIN), 2)
        self.assertNotIn('inputs.', self.workflow)
        self.assertIn('repository: noelnovo/.github', self.workflow)

    def test_untrusted_builder_has_no_scanner_or_oidc_credentials(self):
        build = self.workflow.split('\n  build:\n', 1)[1].split('\n  quality-gate:\n', 1)[0]
        self.assertNotIn('id-token:', build)
        self.assertNotRegex(build, r'\$\{\{\s*secrets\.')
        self.assertNotIn('docker login', build)
        self.assertIn('contents: read', build)

    def test_visible_gate_cannot_silently_skip_failed_producer(self):
        gate = self.workflow.split('\n  quality-gate:\n', 1)[1]
        self.assertIn('name: SonarQube + Dependency-Track (${{ github.base_ref || github.ref_name }})', gate)
        self.assertIn('if: always()', gate)
        self.assertIn('SECURITY_BUILD_RESULT: ${{ needs.build.result }}', gate)
        self.assertIn('queue: max', gate)
        self.assertNotIn('docker build', gate)
        self.assertNotIn('continue-on-error', gate)

    def test_android_setup_and_push_reuse_are_only_in_credential_free_build(self):
        build = self.workflow.split('\n  build:\n', 1)[1].split('\n  quality-gate:\n', 1)[0]
        gate = self.workflow.split('\n  quality-gate:\n', 1)[1]
        self.assertIn('testDebugUnitTest cyclonedxBom', build)
        self.assertIn('security-input-${{ needs.candidate.outputs.candidate }}', build)
        self.assertNotIn('statuses: write', build)
        for value in ['sdkmanager', 'gradlew', 'setup-java', 'download-artifact']:
            self.assertNotIn(value, gate)

    def test_coverage_is_exported_in_builder_and_scanned_as_data_only(self):
        build = self.workflow.split('\n  build:\n', 1)[1].split('\n  quality-gate:\n', 1)[0]
        gate = self.workflow.split('\n  quality-gate:\n', 1)[1]
        self.assertIn('--target security-coverage --output type=local,dest=coverage', build)
        self.assertIn('coverage/lcov.info', build)
        for value in ['npm ', 'node --test', 'docker build', 'npx ', 'c8 ']:
            self.assertNotIn(value, gate)


if __name__ == '__main__':
    unittest.main()
