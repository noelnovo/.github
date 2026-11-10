import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import gitlab_gate as subject


class GitLabGateTests(unittest.TestCase):
    def env(self):
        return {'CI_PROJECT_ID': '10', 'CI_PROJECT_PATH': 'downops/prompt-gateway',
                'CI_PIPELINE_SOURCE': 'merge_request_event', 'CI_PIPELINE_ID': '9',
                'CI_COMMIT_SHA': 'a' * 40, 'CI_MERGE_REQUEST_SOURCE_PROJECT_ID': '10',
                'CI_MERGE_REQUEST_TARGET_BRANCH_NAME': 'main', 'CI_MERGE_REQUEST_IID': '2'}

    def test_registered_mr(self):
        self.assertEqual(subject.profile(self.env())['instance'], 'instance-004')

    def test_reject_other_project(self):
        env = self.env(); env['CI_PROJECT_ID'] = '31'
        with self.assertRaises(RuntimeError):subject.profile(env)

    def test_reject_external_pipeline(self):
        env = self.env(); env['CI_PIPELINE_SOURCE'] = 'api'
        with self.assertRaises(RuntimeError):subject.profile(env)

    def test_unprotected_push_denied(self):
        env = self.env(); env['CI_PIPELINE_SOURCE'] = 'push'
        with self.assertRaises(RuntimeError):subject.profile(env)

    def test_candidate_exact_fast_forward(self):
        env = self.env(); cfg = subject.profile(env)
        mr = {'state': 'opened', 'sha': 'a'*40, 'target_branch': 'main', 'target_project_id': 10}
        with patch.dict(os.environ, env, clear=True), patch.object(subject, 'api', return_value=mr), \
             patch.object(subject, 'command', side_effect=['a'*40, 'b'*40+' refs/heads/main', '', '']):
            result = subject.candidate(cfg, Path('/source'))
        self.assertEqual(result['base'], 'b'*40)

    def test_changed_mr_rejected(self):
        env = self.env(); cfg = subject.profile(env)
        mr = {'state': 'opened', 'sha': 'c'*40, 'target_branch': 'main', 'target_project_id': 10}
        with patch.dict(os.environ, env, clear=True), patch.object(subject, 'api', return_value=mr), \
             patch.object(subject, 'command', return_value='a'*40):
            with self.assertRaises(RuntimeError):subject.candidate(cfg, Path('/source'))

    def test_empty_bom_rejected(self):
        with self.assertRaises(RuntimeError):subject.validate_bom(b'{"bomFormat":"CycloneDX","components":[]}')

    def test_oversized_bom_rejected(self):
        with self.assertRaises(RuntimeError):subject.validate_bom(b'x'*(16*1024*1024+1))

    def test_artifact_pipeline_mismatch_before_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out = root/'security-output'; out.mkdir()
            raw = b'{"bomFormat":"CycloneDX","components":[{"name":"example"}]}'
            (out/'bom.json').write_bytes(raw)
            (out/'receipt.json').write_text('{}')
            with patch.object(subject, 'candidate', return_value={'pipeline':'9'}), \
                 patch.object(subject, 'credentials') as login:
                with self.assertRaises(RuntimeError):subject.evaluate({}, root)
                login.assert_not_called()


if __name__ == '__main__':unittest.main()
