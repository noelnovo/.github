"""Read the actual wrapper override, not the unused application CI stub."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_CODE_PIN = '669c88c24c87de0bc4d110f652edd7a5c17da4e9'


def block(body, key):
    match = re.search(r'(?ms)^  ' + re.escape(key) + r':([^\n]*)\n(.*?)(?=^  [A-Za-z_][A-Za-z0-9_-]*:|\Z)', body)
    if not match:raise AssertionError('missing actual deploy field: ' + key)
    return match[1].strip(), match[2]


class PromptDeployContractTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / 'gitlab/prompt-gateway.yml').read_text()
        self.prefix, self.body = self.source.split('\ndeploy:\n', 1)
        self.fixture = json.loads((ROOT / 'security/fixtures/prompt_legacy_deploy.json').read_text())
        _, before = block(self.body, 'before_script')
        self.bootstrap = '\n'.join(line[6:] for line in before.splitlines() if line.startswith('      ')) + '\n'
        _, script = block(self.body, 'script')
        self.script = [line.strip()[2:] for line in script.splitlines() if line.strip().startswith('- ')]

    def test_actual_frozen_include_and_other_wrapper_jobs_unchanged(self):
        # The preparation-only comment belongs to the new override, not the prefix.
        prefix = self.prefix.split('\n# PREPARATION ONLY:', 1)[0]
        self.assertEqual(hashlib.sha256(prefix.encode()).hexdigest(), self.fixture['wrapper_before_sha256'])
        self.assertIn('ref: ' + self.fixture['ref'], self.prefix)
        self.assertIn('needs: [security]', self.prefix)
        scanner = (ROOT / 'gitlab/dependency-track-scan.yml').read_text()
        override = self.source.split('\n.security-control:\n', 1)[1]
        self.assertIn('SECURITY_CONTROL_SHA: 55e51eba0db3851786f8928f6eafde1ac2b232fb', override)
        self.assertNotIn('VAULT_GITOPS_ID_TOKEN', scanner)

    def test_effective_deploy_replaces_legacy_commands_and_tooling(self):
        effective = dict(self.fixture['deploy'])
        _, image = block(self.body, 'image')
        self.assertIn('name: python:3.12-alpine', image)
        effective.update(image={'name': 'python:3.12-alpine', 'entrypoint': ['']},
                         before_script=[self.bootstrap], script=self.script)
        self.assertNotEqual(effective['before_script'], self.fixture['deploy']['before_script'])
        self.assertNotEqual(effective['script'], self.fixture['deploy']['script'])
        self.assertEqual(effective['script'], ['python3 -I -u "$PROMPT_DEPLOY_CONTROL_DIR/security/prompt_deploy.py"'])
        self.assertIn('GIT_STRATEGY: none', block(self.body, 'variables')[1])
        self.assertEqual(block(self.body, 'services')[0], '[]')
        self.assertIn('artifacts: false', block(self.body, 'needs')[1])
        self.assertNotIn('GITOPS_PUSH_TOKEN}@', self.body)
        self.assertNotIn('sed ', self.body)

    def test_job_specific_audience_and_rules_exclude_MR_and_renew(self):
        tokens = block(self.body, 'id_tokens')[1]
        self.assertIn('VAULT_GITOPS_ID_TOKEN:', tokens)
        self.assertIn('aud: https://vault.downops.win/prompt-gitops', tokens)
        rules = block(self.body, 'rules')[1]
        self.assertIn('$VAULT_RENEW_ONLY == "1"', rules)
        self.assertIn('when: never', rules)
        self.assertIn('$CI_PIPELINE_SOURCE == "push"', rules)
        self.assertIn('$CI_COMMIT_BRANCH == "main"', rules)
        self.assertIn('$CI_COMMIT_REF_PROTECTED == "true"', rules)
        self.assertNotIn('merge_request_event', rules)
        self.assertEqual(block(self.body, 'only')[0], 'null')
        self.assertEqual(block(self.body, 'except')[0], 'null')

    def test_bootstrap_is_valid_shell_and_drops_legacy_before_tools(self):
        result = subprocess.run(['/bin/sh', '-n'], input=self.bootstrap.encode(), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertLess(self.bootstrap.index('unset GITOPS_PUSH_TOKEN'), self.bootstrap.index('apk add'))
        self.assertIn('https://github.com/noelnovo/.github.git "$PROMPT_DEPLOY_CODE"', self.bootstrap)
        self.assertIn('checkout -q --detach FETCH_HEAD', self.bootstrap)
        self.assertIn('rev-parse HEAD)', self.bootstrap)
        self.assertNotIn('CI_PROJECT_DIR', self.bootstrap)
        self.assertNotIn('CI_JOB_TOKEN', self.bootstrap)

    def test_unresolved_pin_blocks_activation_before_network(self):
        # Parent resolves the literal only after committing reviewed helper C2.
        self.assertIn('PROMPT_DEPLOY_CODE: ' + DEPLOY_CODE_PIN + '\n', block(self.body, 'variables')[1])
        guard = self.bootstrap.split('      apk add', 1)[0] if '      apk add' in self.bootstrap else self.bootstrap.split('apk add', 1)[0]
        env = {'PATH': '/usr/bin:/bin', 'PROMPT_DEPLOY_CODE': 'REVIEWED_C2_SHA_REQUIRED'}
        result = subprocess.run(['/bin/sh', '-c', guard], env=env, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        env['PROMPT_DEPLOY_CODE'] = 'a' * 40
        result = subprocess.run(['/bin/sh', '-c', guard], env=env, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
