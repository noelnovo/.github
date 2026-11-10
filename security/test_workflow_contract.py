from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CODE_PIN = '932d5c69b89b8111a513bb45c97aa7726dc470b8'


class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/sonar-dtrack-pr.yml').read_text()

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
        self.assertIn('name: SonarQube + Dependency-Track (${{ github.base_ref }})', gate)
        self.assertIn('if: always()', gate)
        self.assertIn('SECURITY_BUILD_RESULT: ${{ needs.build.result }}', gate)
        self.assertIn('queue: max', gate)
        self.assertNotIn('docker build', gate)
        self.assertNotIn('continue-on-error', gate)


if __name__ == '__main__':
    unittest.main()
