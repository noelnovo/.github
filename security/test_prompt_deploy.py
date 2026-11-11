"""Synthetic/offline tests. No real JWT verification, Vault, registry or Git push."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import prompt_deploy as s

HEAD = 'a' * 40
OTHER = 'b' * 40
PASSWORD = 'synthetic-vault-only-write-password'
LEASE = 'unit-only-service-lease-not-an-auth-token'
DESIRED = s.IMAGE + ':1.5.0-aaaaaaaa'
OLD = ('spec:\n  image: ' + s.IMAGE + ':1.5.0-400216f5\n').encode()


def environment(**updates):
    env = {'CI_PROJECT_ID': '10', 'CI_PROJECT_PATH': 'downops/prompt-gateway',
           'CI_PROJECT_NAMESPACE_ID': '4', 'CI_PROJECT_NAMESPACE': 'downops',
           'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'main',
           'CI_COMMIT_REF_NAME': 'main', 'CI_COMMIT_REF_PROTECTED': 'true',
           'CI_COMMIT_SHA': HEAD, 'CI_COMMIT_SHORT_SHA': HEAD[:8], 'CI_PIPELINE_ID': '1031'}
    claims = {'project_id': '10', 'project_path': 'downops/prompt-gateway',
              'namespace_id': '4', 'namespace_path': 'downops', 'pipeline_source': 'push',
              'ref_type': 'branch', 'ref': 'main', 'ref_path': 'refs/heads/main',
              'ref_protected': 'true', 'aud': s.AUDIENCE}
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    env['VAULT_GITOPS_ID_TOKEN'] = 'e30.' + encoded + '.synthetic-not-a-signature'
    env.update(updates)
    return env


class FakeVault:
    def __init__(self, fail=None, revoke_fail=False, record=None, authority=None):
        self.fail, self.revoke_fail = fail, revoke_fail
        self.record = {'GITOPS_PUSH_TOKEN': PASSWORD} if record is None else record
        self.authority = authority
        self.calls = []

    def login(self, jwt):
        self.calls.append('login')
        if self.fail == 'login':raise s.Failure('vault_login_failed')
        return self.authority or {'client_token': LEASE, 'policies': [s.ROLE],
                                  'token_type': 'service', 'lease_duration': 300}

    def read(self, token):
        self.calls.append('read')
        if self.fail == 'read':raise s.Failure('vault_read_failed')
        return self.record

    def revoke(self, token):
        self.calls.append('revoke')
        if self.revoke_fail:raise s.Failure('vault_revoke_failed')


class FakeRepo:
    def __init__(self, content=OLD, pushes=(True,), stale=False, raw_version=b'1.5.0\n'):
        self.content, self.pushes, self.stale, self.raw_version = content, iter(pushes), stale, raw_version
        self.commits = []; self.push_calls = []; self.guards = 0

    def prepare(self, source):pass
    def current(self):return HEAD
    def source_guard(self, source, current, desired):
        self.guards += 1
        if self.stale:raise s.Failure('stale_application_source')
    def blob(self, revision, path):return self.raw_version if path == 'VERSION' else self.content
    def commit(self, parent, content, tag, pipeline):
        self.commits.append((parent, content, tag, pipeline));return OTHER
    def push(self, commit):
        self.push_calls.append(commit);return next(self.pushes)


class PromptDeployTests(unittest.TestCase):
    def test_exact_protected_context(self):
        env = environment();self.assertEqual(s.context(env, env['VAULT_GITOPS_ID_TOKEN']), s.Context(HEAD, '1031'))

    def test_MR_unprotected_wrong_project_namespace_and_short_SHA_fail(self):
        for update in [{'CI_PIPELINE_SOURCE': 'merge_request_event'}, {'CI_COMMIT_REF_PROTECTED': 'false'},
                       {'CI_PROJECT_ID': '1'}, {'CI_PROJECT_NAMESPACE_ID': '99'},
                       {'CI_COMMIT_SHORT_SHA': 'bad'}, {'CI_COMMIT_TAG': 'v1.5.0'}]:
            env = environment(**update)
            with self.subTest(update=update), self.assertRaises(s.Failure):s.context(env, env['VAULT_GITOPS_ID_TOKEN'])

    def test_wrong_audience_and_signed_context_fail(self):
        for key, value in [('aud', 'https://vault.int.downops.win'), ('ref_protected', 'false'),
                           ('namespace_id', '99'), ('ref_path', 'refs/heads/other')]:
            env = environment();parts = env['VAULT_GITOPS_ID_TOKEN'].split('.')
            claims = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
            claims[key] = value
            parts[1] = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
            with self.subTest(key=key), self.assertRaises(s.Failure):s.context(env, '.'.join(parts))

    def test_missing_and_malformed_OIDC_fail(self):
        for jwt in ['', 'not-a-token', 'e30.bad.signature']:
            with self.subTest(jwt=jwt), self.assertRaises(s.Failure):s.context(environment(), jwt)

    def test_canonical_replacement_and_sidecar_preservation(self):
        raw = OLD + b'  image: other/sidecar:stable\n'
        updated, already = s.rewrite(raw, DESIRED)
        self.assertFalse(already);self.assertEqual(updated, raw.replace((s.IMAGE + ':1.5.0-400216f5').encode(), DESIRED.encode()))

    def test_quotes_comments_and_CRLF_preserved(self):
        raw = ('  image: "' + s.IMAGE + ':1.5.0-400216f5" # owned\r\n').encode()
        self.assertEqual(s.rewrite(raw, DESIRED)[0], ('  image: "' + DESIRED + '" # owned\r\n').encode())

    def test_zero_legacy_unknown_missing_targets_fail(self):
        for raw in [b'image: 10.2.0.101:5000/downops/prompt-gateway:1.5.0-400216f5\n',
                    b'image: other/repository:old\n', b'kind: Deployment\n']:
            with self.subTest(raw=raw), self.assertRaisesRegex(s.Failure, 'canonical_target_count'):s.rewrite(raw, DESIRED)

    def test_duplicates_fail_even_when_one_is_already_desired(self):
        raw = OLD + ('image: ' + DESIRED + '\n').encode()
        with self.assertRaisesRegex(s.Failure, 'canonical_target_count'):s.rewrite(raw, DESIRED)

    def test_malformed_and_unsafe_tags_fail(self):
        for value in ['', 'latest', '1.5.0-', '1.5.0-400216f5 extra', '1.5.0-400216f5;bad']:
            with self.subTest(value=value), self.assertRaises(s.Failure):s.rewrite(('image: ' + s.IMAGE + ':' + value + '\n').encode(), DESIRED)
        with self.assertRaises(s.Failure):s.rewrite(('image: "' + s.IMAGE + ':1.5.0-400216f5\n').encode(), DESIRED)
        with self.assertRaises(s.Failure):s.rewrite(OLD, s.IMAGE + ':latest')

    def test_version_validation(self):
        self.assertEqual(s.version(b'1.5.0\n'), '1.5.0')
        for raw in [b'', b'1.05.0', b'1.5', b'1.5.0\nextra', b'1.5.0;bad', b'1.5.0+build', b'x' * 65, b'\xff']:
            with self.subTest(raw=raw), self.assertRaises(s.Failure):s.version(raw)

    def test_already_desired_does_not_commit_or_push(self):
        repo = FakeRepo(('image: ' + DESIRED + '\n').encode())
        result = s.publish(repo, s.Context(HEAD, '1031'))
        self.assertTrue(result['already_desired']);self.assertFalse(repo.commits);self.assertFalse(repo.push_calls)

    def test_wrong_target_never_becomes_no_diff_success(self):
        repo = FakeRepo(b'image: wrong/repository:old\n')
        with self.assertRaises(s.Failure):s.publish(repo, s.Context(HEAD, '1031'))
        self.assertFalse(repo.commits);self.assertFalse(repo.push_calls)

    def test_valid_writeback_and_retry(self):
        repo = FakeRepo(pushes=(False, True));result = s.publish(repo, s.Context(HEAD, '1031'))
        self.assertTrue(result['gitops_updated']);self.assertEqual(result['attempts'], 2)
        self.assertEqual(repo.guards, 2);self.assertEqual(len(repo.push_calls), 2)
        self.assertIn(DESIRED.encode(), repo.commits[-1][1])

    def test_push_retries_are_bounded_and_stale_guard_runs_first(self):
        repo = FakeRepo(pushes=(False, False, False))
        with self.assertRaisesRegex(s.Failure, 'git_push_retries_exhausted'):s.publish(repo, s.Context(HEAD, '1031'))
        self.assertEqual(len(repo.push_calls), 3)
        stale = FakeRepo(stale=True)
        with self.assertRaisesRegex(s.Failure, 'stale_application_source'):s.publish(stale, s.Context(HEAD, '1031'))
        self.assertFalse(stale.push_calls)

    def test_actual_source_guard_rejects_nonmanifest_changes(self):
        repo = object.__new__(s.Git);repo.run = Mock(side_effect=[(b'', 0), (b'README.md\x00', 0)])
        with self.assertRaisesRegex(s.Failure, 'stale_application_source'):repo.source_guard(HEAD, OTHER, DESIRED)

    def test_actual_source_guard_allows_only_owned_manifest_descendant(self):
        for owned in [True, False]:
            repo = object.__new__(s.Git)
            repo.run = Mock(side_effect=[(b'', 0), (b'k8s/app.yaml\x00', 0), (b'k8s/app.yaml\x00', 0)])
            repo.text = Mock(side_effect=[OTHER, OTHER + ' ' + HEAD])
            repo.blob = Mock(return_value=('image: ' + (DESIRED if owned else s.IMAGE + ':1.5.0-400216f5') + '\n').encode())
            if owned:repo.source_guard(HEAD, OTHER, DESIRED)
            else:
                with self.assertRaisesRegex(s.Failure, 'foreign_manifest_descendant'):repo.source_guard(HEAD, OTHER, DESIRED)

    def test_symlink_blob_is_rejected(self):
        repo = object.__new__(s.Git);repo.run = Mock(return_value=(b'120000 blob ' + b'a' * 40 + b'\tk8s/app.yaml\x00', 0))
        with self.assertRaisesRegex(s.Failure, 'regular_source_file_required'):repo.blob(HEAD, s.MANIFEST)

    def test_read_and_revoke_before_git(self):
        vault = FakeVault();state = {}
        self.assertEqual(s.credential(vault, 'synthetic', state), PASSWORD)
        self.assertEqual(vault.calls, ['login', 'read', 'revoke']);self.assertTrue(state['revoked'])

    def test_primary_read_error_not_masked_by_revoke_error(self):
        vault = FakeVault(fail='read', revoke_fail=True)
        with self.assertRaises(s.Failure) as raised:s.credential(vault, 'synthetic', {})
        self.assertEqual(raised.exception.code, 'vault_read_failed');self.assertEqual(raised.exception.cleanup, 'vault_revoke_failed')

    def test_revoke_error_after_good_read_fails_closed(self):
        with self.assertRaisesRegex(s.Failure, 'vault_revoke_failed'):s.credential(FakeVault(revoke_fail=True), 'synthetic', {})
        factory = Mock()
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(s.main(environment(), FakeVault(revoke_fail=True), factory), 1)
        factory.assert_not_called()

    def test_schema_or_overprivileged_authority_rejected_and_revoked(self):
        for vault in [FakeVault(record={'GITOPS_PUSH_TOKEN': PASSWORD, 'extra': 'not permitted'}),
                      FakeVault(record={'GITOPS_PUSH_TOKEN': 'bad\nprotocol'}),
                      FakeVault(authority={'client_token': LEASE, 'policies': [s.ROLE], 'identity_policies': ['unexpected-extra'], 'token_type': 'service', 'lease_duration': 300}),
                      FakeVault(authority={'client_token': LEASE, 'policies': ['root'], 'token_type': 'service', 'lease_duration': 300})]:
            with self.assertRaises(s.Failure):s.credential(vault, 'synthetic', {})
            self.assertEqual(vault.calls[-1], 'revoke')

    def test_unexpected_authority_does_not_mark_verified_login_or_run_git(self):
        authority = {'client_token': LEASE, 'policies': ['root'],
                     'token_type': 'service', 'lease_duration': 300}
        vault = FakeVault(authority=authority);factory = Mock();out = io.StringIO()
        with contextlib.redirect_stdout(out):code = s.main(environment(), vault, factory)
        result = json.loads(out.getvalue())
        self.assertEqual(code, 1);self.assertEqual(result['error'], 'unexpected_vault_authority')
        self.assertFalse(result['vault_login_ok']);self.assertTrue(result['revoked'])
        self.assertEqual(vault.calls, ['login', 'revoke']);factory.assert_not_called()

    def test_unsafe_returned_lease_is_never_used_for_read_or_revoke(self):
        for lease in [None, 42, {}, '', 'short', 'unit-only-invalid-lease\nheader',
                      'unit-only-invalid-lease\rheader', 'unit-only-invalid-lease\x00tail']:
            authority = {'client_token': lease, 'policies': [s.ROLE],
                         'token_type': 'service', 'lease_duration': 300}
            vault = FakeVault(authority=authority);state = {'vault_login_ok': False}
            with self.subTest(lease_type=type(lease).__name__), self.assertRaisesRegex(s.Failure, 'invalid_vault_token'):
                s.credential(vault, 'synthetic', state)
            self.assertFalse(state['vault_login_ok']);self.assertEqual(vault.calls, ['login'])

    def test_legacy_value_never_falls_back_when_Vault_fails(self):
        for failure in ['login', 'read']:
            env = environment(GITOPS_PUSH_TOKEN='synthetic-valid-but-forbidden-legacy-value')
            factory = Mock();out = io.StringIO()
            with contextlib.redirect_stdout(out):code = s.main(env, FakeVault(fail=failure), factory)
            self.assertEqual(code, 1);factory.assert_not_called();self.assertNotIn('GITOPS_PUSH_TOKEN', env)
            self.assertNotIn('synthetic-valid-but-forbidden-legacy-value', out.getvalue())

    def test_main_passes_only_Vault_value_to_git_and_safe_markers(self):
        env = environment(GITOPS_PUSH_TOKEN='synthetic-legacy-forbidden')
        vault = FakeVault();repo = FakeRepo();factory = Mock(return_value=repo);out = io.StringIO()
        refresh = Mock()
        with contextlib.redirect_stdout(out):self.assertEqual(s.main(env, vault, factory, refresh), 0)
        self.assertEqual(factory.call_args.args[1], PASSWORD)
        self.assertEqual(vault.calls, ['login', 'read', 'revoke'])
        self.assertTrue(json.loads(out.getvalue())['gitops_updated'])
        refresh.assert_called_once_with(OTHER)
        for secret in [PASSWORD, LEASE, 'synthetic-legacy-forbidden']:self.assertNotIn(secret, out.getvalue())

    def test_git_argv_config_and_errors_never_contain_password(self):
        process = Mock(returncode=0);process.communicate.return_value = (b'', PASSWORD.encode())
        with tempfile.TemporaryDirectory() as directory, patch.object(s.subprocess, 'Popen', return_value=process) as popen:
            repo = s.Git(directory, PASSWORD)
            for call in popen.call_args_list:
                argv = call.args[0];self.assertNotIn(PASSWORD, repr(argv));self.assertNotIn('--force', argv)
                self.assertEqual(call.kwargs['env']['PROMPT_GITOPS_PASSWORD'], PASSWORD)
                self.assertNotIn('GITOPS_PUSH_TOKEN', call.kwargs['env'])
                self.assertFalse(any('oauth2:' in arg for arg in argv))
            process.returncode = 128
            with self.assertRaises(s.Failure) as raised:repo.run('fetch', 'origin')
            self.assertNotIn(PASSWORD, str(raised.exception))

    def test_redirects_are_never_followed(self):
        self.assertIsNone(s.NoRedirect().redirect_request(None, None, 302, 'redirect', {}, 'https://elsewhere.invalid'))

    def test_refresh_failure_preserves_successful_writeback_metadata(self):
        refresh = Mock(side_effect=s.Failure('argocd_refresh_failed'));out = io.StringIO()
        with contextlib.redirect_stdout(out):code = s.main(environment(), FakeVault(), Mock(return_value=FakeRepo()), refresh)
        result = json.loads(out.getvalue())
        self.assertEqual(code, 1);self.assertEqual(result['error'], 'argocd_refresh_failed')
        self.assertTrue(result['gitops_updated']);self.assertEqual(result['revision'], OTHER)

    def test_refresh_is_only_the_existing_repo_main_event_without_credentials(self):
        response = Mock(status=200);response.__enter__ = Mock(return_value=response);response.__exit__ = Mock(return_value=False)
        opener = Mock();opener.open.return_value = response
        with patch.object(s.urllib.request, 'build_opener', return_value=opener):s.notify(OTHER)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://argocd.int.downops.win/api/webhook')
        self.assertNotIn('Authorization', request.headers)
        self.assertNotIn(PASSWORD, repr(request.headers))
        payload = json.loads(request.data);self.assertEqual(payload['ref'], 'refs/heads/main')
        self.assertEqual(payload['after'], OTHER)
        self.assertEqual(payload['repository']['url'], 'ssh://git@10.2.0.11:2222/downops/prompt-gateway.git')

    def test_git_timeout_reaps_only_owned_process_group_and_hides_details(self):
        process = Mock(pid=123456, returncode=-9)
        process.communicate.side_effect = [s.subprocess.TimeoutExpired('unit-command', 45), (b'', PASSWORD.encode())]
        repo = object.__new__(s.Git);repo.root = Path('/unit-only');repo.env = {'PROMPT_GITOPS_PASSWORD': PASSWORD}
        with patch.object(s.subprocess, 'Popen', return_value=process), patch.object(s.os, 'killpg') as kill:
            with self.assertRaisesRegex(s.Failure, 'git_timeout') as raised:repo.run('fetch', 'origin')
        kill.assert_called_once_with(123456, s.signal.SIGKILL)
        self.assertEqual(process.communicate.call_count, 2)
        self.assertNotIn(PASSWORD, str(raised.exception))

    def test_Vault_password_protocol_injection_is_rejected(self):
        for value in ['short', 'synthetic-password\npassword=second', 'synthetic-password\rheader', 'synthetic-password\x00tail']:
            with self.subTest(value=value):self.assertFalse(s.safe_password(value))

    def test_real_git_objects_write_only_manifest_without_checkout_or_network(self):
        # All commits live only in this disposable synthetic repository. Network
        # prepare/current/push methods are mocked; no application checkout exists.
        with tempfile.TemporaryDirectory() as directory:
            repo = s.Git(directory, PASSWORD)
            query = b'protocol=https\nhost=gitlab.int.downops.win\npath=downops/prompt-gateway.git\n\n'
            filled = repo.run('credential', 'fill', data=query)[0]
            self.assertIn(b'username=oauth2\n', filled)
            self.assertIn(('password=' + PASSWORD + '\n').encode(), filled)
            repo.run('credential', 'approve', data=filled)
            self.assertFalse((Path(directory) / '.git-credentials').exists())
            repo.run('read-tree', '--empty')
            for path, content in [('VERSION', b'1.5.0\n'), (s.MANIFEST, OLD), ('README.md', b'unchanged source\n')]:
                blob = repo.run('hash-object', '-w', '--stdin', '--no-filters', data=content)[0].decode().strip()
                repo.run('update-index', '--add', '--cacheinfo', '100644,' + blob + ',' + path)
            tree = repo.text('write-tree')
            source = repo.run('commit-tree', tree, data=b'unit-only synthetic source\n')[0].decode().strip()
            repo.prepare = Mock();repo.current = Mock(return_value=source);repo.push = Mock(return_value=True)
            result = s.publish(repo, s.Context(source, '1031'))
            changes = repo.text('diff-tree', '--no-commit-id', '--name-only', '-r', source, result['revision'])
            self.assertEqual(changes, s.MANIFEST)
            self.assertIn((s.IMAGE + ':1.5.0-' + source[:8]).encode(), repo.blob(result['revision'], s.MANIFEST))
            self.assertFalse((Path(directory) / 'VERSION').exists())
            config = (Path(directory) / '.git/config').read_text()
            self.assertIn(s.REPOSITORY, config)
            self.assertNotIn(PASSWORD, config);self.assertNotIn('password=', config)
            self.assertNotIn('credential', config);self.assertNotIn('pushurl', config)


if __name__ == '__main__':
    unittest.main()
