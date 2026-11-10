import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import premerge as control

HEAD, BASE, CANDIDATE = 'a' * 40, 'b' * 40, 'c' * 40
ENV = {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REPOSITORY': 'noelnovo/nn-PortFolio',
       'GITHUB_REPOSITORY_ID': '864547743', 'GITHUB_RUN_ID': '12', 'GITHUB_RUN_ATTEMPT': '1',
       'GITHUB_TOKEN': 'synthetic'}


def event():
    return {'number': 7, 'repository': {'id': 864547743}, 'pull_request': {
        'head': {'sha': HEAD}, 'base': {'sha': BASE, 'ref': 'main', 'repo': {'id': 864547743}}}}


def current():
    return {'state': 'open', 'head': {'sha': HEAD}, 'base': {'sha': BASE, 'ref': 'main',
        'repo': {'id': 864547743}}, 'mergeable': True, 'merge_commit_sha': CANDIDATE}


def source(name, kind=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        member = tarfile.TarInfo(name)
        if kind:
            member.type = kind
            member.linkname = '/etc/passwd'
            archive.addfile(member)
        else:
            member.size = 4
            archive.addfile(member, io.BytesIO(b'data'))
    return buffer.getvalue()


def bom_zip(name='bom.json', content=None, link=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        info = zipfile.ZipInfo(name)
        if link:
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, content or '{"bomFormat":"CycloneDX","components":[{}]}')
    return buffer.getvalue()


class ReusableSecurityTests(unittest.TestCase):
    def test_registered_caller_is_selected_not_caller_inputs(self):
        profile, expected = control.identity(event(), ENV)
        self.assertEqual(profile['instance'], 'instance-002')
        self.assertEqual(expected['target'], 'main')
        for key, value in [('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REPOSITORY_ID', '1'),
                           ('GITHUB_REPOSITORY', 'attacker/repo')]:
            with self.assertRaises(RuntimeError):
                control.identity(event(), dict(ENV, **{key: value}))

    def test_exact_merge_candidate_parents(self):
        profile, expected = control.identity(event(), ENV)
        for parent, passed in [(HEAD, True), ('d' * 40, False)]:
            with patch.object(control, 'api', side_effect=[current(), {'parents': [{'sha': BASE}, {'sha': parent}]}]):
                if passed:self.assertEqual(control.candidate(profile, expected), CANDIDATE)
                else:
                    with self.assertRaises(RuntimeError):control.candidate(profile, expected)

    def test_changed_source_or_target_refuses_analysis(self):
        profile, expected = control.identity(event(), ENV)
        for field in ['head', 'base']:
            value = current()
            value[field]['sha'] = 'd' * 40
            with patch.object(control, 'api', return_value=value), self.assertRaises(RuntimeError):
                control.candidate(profile, expected)

    def test_skipped_or_failed_producer_does_not_read_vault(self):
        profile, expected = control.identity(event(), ENV)
        for state in ['skipped', 'failure', 'cancelled', '']:
            with patch.dict(os.environ, dict(ENV, SECURITY_BUILD_RESULT=state), clear=True), patch.object(control.security_gate, 'scan') as scan:
                with self.assertRaises(RuntimeError):control.evaluate(profile, expected)
                scan.assert_not_called()

    def test_unsafe_paths_links_and_devices_rejected(self):
        for name in ['../bad', '/absolute', 'folder/../../bad', 'bad\\path']:
            with self.assertRaises(RuntimeError):control.safe_path(name)
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE]:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(RuntimeError):
                control.unpack_source(source('repo/source.py', kind), Path(directory))

    def test_source_scanner_config_is_ignored(self):
        for name in ['repo/sonar-project.properties', 'repo/bom.json', 'repo/.scannerwork/report-task.txt']:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                control.unpack_source(source(name), root)
                self.assertFalse(any(f.is_file() for f in root.rglob('*')))

    def test_source_is_nonexecutable_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control.unpack_source(source('repo/ci/malicious.py'), root)
            self.assertEqual((root / 'ci/malicious.py').stat().st_mode & 0o777, 0o600)

    def test_only_resolved_bom_is_accepted_from_artifact(self):
        for name, content, link in [('ci/premerge.py', None, False), ('../bom.json', None, False),
                                    ('bom.json', None, True), ('bom.json', '{"components":[]}', False)]:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(RuntimeError):
                control.unpack_bom(bom_zip(name, content, link), Path(directory))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control.unpack_bom(bom_zip(), root)
            self.assertTrue((root / 'bom.json').is_file())

    def test_cross_host_github_token_forwarding_rejected(self):
        with self.assertRaises(RuntimeError):control.download('https://example.test', token='synthetic')

    def test_same_run_digest_evidence_required(self):
        profile, _ = control.identity(event(), ENV)
        item = {'id': 5, 'name': 'security-bom-' + CANDIDATE + '-1', 'expired': False,
                'workflow_run': {'id': 12}, 'digest': 'sha256:' + '0' * 64}
        with patch.dict(os.environ, ENV, clear=True), patch.object(control, 'api', return_value={'artifacts': [item]}), patch.object(control, 'download', return_value=b'different'), self.assertRaises(RuntimeError):
            control.artifact(profile, CANDIDATE)

    def test_privileged_worker_never_builds_source(self):
        profile, expected = control.identity(event(), ENV)
        with patch.dict(os.environ, dict(ENV, SECURITY_BUILD_RESULT='success', SECURITY_CANDIDATE=CANDIDATE), clear=True), \
             patch.object(control, 'controller'), patch.object(control, 'candidate', side_effect=[CANDIDATE, CANDIDATE]), \
             patch.object(control, 'artifact', return_value=b'data'), patch.object(control, 'download', return_value=b'data'), \
             patch.object(control, 'unpack_source'), patch.object(control, 'unpack_bom'), \
             patch.object(control.security_gate, 'ROOT'), patch.object(control.security_gate, 'scan') as scan, \
             patch.object(control.security_gate, 'prepare') as prepare:
            control.evaluate(profile, expected)
            scan.assert_called_once()
            prepare.assert_not_called()
