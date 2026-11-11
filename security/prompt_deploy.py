"""Protected Prompt GitOps publisher. No application code is executed.

Local JWT checks are sanity checks only: Vault validates the signature/role.
Git operates on objects and a private index, never an application checkout.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import tempfile
import urllib.error
import urllib.request

VAULT = 'https://vault.int.downops.win'
AUDIENCE = 'https://vault.downops.win/prompt-gitops'
ROLE = 'security-ci-prompt-deploy'
KV_PATH = '/v1/downops/data/services/gitlab/gitops/instance-010'
REPOSITORY = 'https://gitlab.int.downops.win/downops/prompt-gateway.git'
IMAGE = 'registry.int.downops.win/downops/prompt-gateway'
MANIFEST = 'k8s/app.yaml'
SHA = re.compile(r'[0-9a-f]{40}\Z')
VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z')
TAG = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-[0-9a-f]{8}\Z')


class Failure(Exception):
    def __init__(self, code, cleanup=None):
        super().__init__(code)
        self.code = code
        self.cleanup = cleanup


def require(condition, code):
    if not condition:
        raise Failure(code)


@dataclass(frozen=True)
class Context:
    head: str
    pipeline: str


def context(env, jwt):
    required = {'CI_PROJECT_ID': '10', 'CI_PROJECT_PATH': 'downops/prompt-gateway',
                'CI_PROJECT_NAMESPACE_ID': '4', 'CI_PROJECT_NAMESPACE': 'downops',
                'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'main',
                'CI_COMMIT_REF_NAME': 'main', 'CI_COMMIT_REF_PROTECTED': 'true'}
    require(all(env.get(k) == v for k, v in required.items()) and not env.get('CI_COMMIT_TAG'),
            'protected_main_push_required')
    head = env.get('CI_COMMIT_SHA', '')
    require(SHA.fullmatch(head) and env.get('CI_COMMIT_SHORT_SHA') == head[:8], 'invalid_commit_identity')
    pipeline = env.get('CI_PIPELINE_ID', '')
    require(re.fullmatch(r'[1-9][0-9]{0,15}', pipeline), 'invalid_pipeline_identity')
    require(isinstance(jwt, str) and 0 < len(jwt) < 65536, 'missing_deploy_oidc')
    try:
        parts = jwt.split('.')
        require(len(parts) == 3, 'invalid_deploy_oidc')
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
        require(isinstance(claims, dict), 'invalid_deploy_oidc')
    except Exception:
        raise Failure('invalid_deploy_oidc') from None
    aud = claims.get('aud')
    require(aud == AUDIENCE or aud == [AUDIENCE], 'wrong_deploy_audience')
    signed = {'project_id': '10', 'project_path': 'downops/prompt-gateway',
              'namespace_id': '4', 'namespace_path': 'downops', 'pipeline_source': 'push',
              'ref_type': 'branch', 'ref': 'main', 'ref_path': 'refs/heads/main'}
    require(all(str(claims.get(k)) == v for k, v in signed.items()) and
            str(claims.get('ref_protected')).lower() == 'true', 'wrong_deploy_context')
    return Context(head, pipeline)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Vault:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, body=None, token=None):
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        if token:
            headers['X-Vault-Token'] = token
        request = urllib.request.Request(VAULT + path,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers=headers)
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(65537)
                require(len(raw) <= 65536, 'vault_response_size')
                return json.loads(raw) if raw else {}
        except Failure:
            raise
        except Exception:
            raise Failure('vault_request_failed') from None

    def login(self, jwt):
        try:
            return self.request('/v1/auth/gitlab-ci/login', {'role': ROLE, 'jwt': jwt})['auth']
        except Exception:
            raise Failure('vault_login_failed') from None

    def read(self, token):
        try:
            return self.request(KV_PATH, token=token)['data']['data']
        except Exception:
            raise Failure('vault_read_failed') from None

    def revoke(self, token):
        try:
            self.request('/v1/auth/token/revoke-self', {}, token)
        except Exception:
            raise Failure('vault_revoke_failed') from None


def safe_password(value):
    return isinstance(value, str) and 20 <= len(value) <= 4096 and all(33 <= ord(c) <= 126 for c in value)


def credential(vault, jwt, state):
    """Only safe returned lease strings may enter read/revoke HTTP headers.

    Short, malformed or control-containing client tokens fail closed without
    further HTTP requests. A safe lease is still revoked if authority checks fail.
    """
    lease = None
    password = None
    primary = cleanup = None
    try:
        auth = vault.login(jwt)
        lease = auth.get('client_token')
        require(safe_password(lease), 'invalid_vault_token')
        require(auth.get('policies') == [ROLE] and not auth.get('identity_policies') and
                auth.get('token_policies', [ROLE]) == [ROLE] and auth.get('token_type') == 'service' and
                isinstance(auth.get('lease_duration'), int) and not isinstance(auth['lease_duration'], bool) and
                0 < auth['lease_duration'] <= 300,
                'unexpected_vault_authority')
        state['vault_login_ok'] = True
        record = vault.read(lease)
        require(isinstance(record, dict) and set(record) == {'GITOPS_PUSH_TOKEN'} and
                safe_password(record['GITOPS_PUSH_TOKEN']), 'invalid_write_token_schema')
        password = record['GITOPS_PUSH_TOKEN']
        state['vault_read_ok'] = True
    except BaseException as error:
        primary = error if isinstance(error, Failure) else Failure('vault_operation_failed')
    finally:
        if lease and safe_password(lease):
            try:
                vault.revoke(lease)
                state['revoked'] = True
            except BaseException:
                cleanup = 'vault_revoke_failed'
    if primary:
        raise Failure(primary.code, cleanup) from None
    if cleanup:
        raise Failure(cleanup) from None
    state['credential_source'] = 'vault'
    return password


def version(raw):
    require(isinstance(raw, bytes) and len(raw) <= 64, 'invalid_version')
    try:
        value = raw.decode('ascii').removesuffix('\n')
    except UnicodeError:
        raise Failure('invalid_version') from None
    require(VERSION.fullmatch(value), 'invalid_version')
    return value


def rewrite(raw, desired):
    require(desired.startswith(IMAGE + ':') and TAG.fullmatch(desired[len(IMAGE) + 1:]),
            'invalid_desired_image')
    require(len(raw) <= 512 * 1024 and b'\x00' not in raw, 'invalid_manifest')
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise Failure('invalid_manifest') from None
    output = []
    found = []
    for line in text.splitlines(keepends=True):
        field = re.match(r'^([ \t]*image:[ \t]*)(.*)', line)
        if not field:
            output.append(line)
            continue
        scalar = re.fullmatch(r'''(?P<q>["']?)(?P<value>[^\s"']+)(?P=q)(?P<suffix>[ \t]*(?:\#[^\r\n]*)?)(?P<eol>\r?\n)?''', line[len(field[1]):])
        require(scalar is not None, 'malformed_image_field')
        value = scalar['value']
        if value.startswith(IMAGE + ':'):
            require(TAG.fullmatch(value[len(IMAGE) + 1:]), 'malformed_target_tag')
            found.append(value)
            output.append(field[1] + scalar['q'] + desired + scalar['q'] + scalar['suffix'] + (scalar['eol'] or ''))
        else:
            output.append(line)
    require(len(found) == 1, 'canonical_target_count')
    updated = ''.join(output).encode()
    exact = re.findall(r'''(?m)^[ \t]*image:[ \t]*["']?''' + re.escape(desired) +
                       r'''["']?[ \t]*(?:\#[^\r\n]*)?\r?$''', updated.decode('utf-8'))
    require(len(exact) == 1, 'desired_image_assertion')
    return updated, found[0] == desired


HELPER = '!f() { if [ "$1" = get ]; then printf "username=oauth2\\npassword=%s\\n" "$PROMPT_GITOPS_PASSWORD"; fi; }; f'


class Git:
    def __init__(self, root, password):
        self.root = Path(root)
        self.env = {'PATH': os.defpath, 'HOME': str(root), 'LANG': 'C',
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                    'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': 'https',
                    'GIT_LFS_SKIP_SMUDGE': '1', 'GIT_INDEX_FILE': str(self.root / 'index'),
                    'PROMPT_GITOPS_PASSWORD': password,
                    'GIT_AUTHOR_NAME': 'prompt-gateway-ci', 'GIT_AUTHOR_EMAIL': 'ci@downops.win',
                    'GIT_COMMITTER_NAME': 'prompt-gateway-ci', 'GIT_COMMITTER_EMAIL': 'ci@downops.win'}
        self.run('init', '-q', '--template=')
        self.run('remote', 'add', 'origin', REPOSITORY)
        self.run('config', '--unset-all', 'remote.origin.pushurl', allowed=(0, 5))

    def run(self, *args, data=None, allowed=(0,)):
        command = ['git', '-C', str(self.root), '-c', 'core.hooksPath=/dev/null',
                   '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=/dev/null',
                   '-c', 'http.sslVerify=true', '-c', 'http.followRedirects=false',
                   '-c', 'submodule.recurse=false', '-c', 'fetch.recurseSubmodules=false',
                   '-c', 'commit.gpgsign=false', '-c', 'credential.helper=',
                   '-c', 'credential.helper=' + HELPER, *args]
        process = subprocess.Popen(command, env=self.env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, _ = process.communicate(data, timeout=45)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise Failure('git_timeout') from None
        require(len(stdout) <= 16 * 1024 * 1024, 'git_output_size')
        require(process.returncode in allowed, 'git_command_failed')
        return stdout, process.returncode

    def text(self, *args):
        return self.run(*args)[0].decode('utf-8').strip()

    def prepare(self, source):
        self.run('fetch', '-q', '--no-tags', '--depth=50', 'origin', source)

    def current(self):
        self.run('fetch', '-q', '--no-tags', '--depth=50', 'origin', 'refs/heads/main')
        head = self.text('rev-parse', 'FETCH_HEAD')
        require(SHA.fullmatch(head), 'invalid_remote_head')
        return head

    def blob(self, revision, path):
        listing = self.run('ls-tree', '-z', revision, '--', path)[0]
        require(listing.startswith(b'100644 blob ') and listing.endswith(b'\t' + path.encode() + b'\x00') and listing.count(b'\x00') == 1,
                'regular_source_file_required')
        return self.run('show', revision + ':' + path)[0]

    def source_guard(self, source, current, desired):
        if current == source:
            return
        self.run('merge-base', '--is-ancestor', source, current)
        changes = self.run('diff', '--name-only', '-z', source, current)[0].split(b'\x00')
        require(set(changes) - {b'', MANIFEST.encode()} == set(), 'stale_application_source')
        commits = self.text('rev-list', '--max-count=51', source + '..' + current).splitlines()
        require(0 < len(commits) <= 50, 'unbounded_manifest_history')
        for commit in commits:
            parents = self.text('rev-list', '--parents', '-n', '1', commit).split()
            require(len(parents) == 2, 'nonlinear_manifest_history')
            touched = self.run('diff-tree', '--no-commit-id', '--name-only', '-r', '-z', commit)[0].split(b'\x00')
            require(set(touched) - {b''} == {MANIFEST.encode()}, 'non_manifest_descendant')
        _, already = rewrite(self.blob(current, MANIFEST), desired)
        require(already, 'foreign_manifest_descendant')

    def commit(self, parent, content, tag, pipeline):
        self.run('read-tree', parent)
        blob = self.run('hash-object', '-w', '--stdin', '--no-filters', data=content)[0].decode().strip()
        require(SHA.fullmatch(blob), 'invalid_blob_identity')
        self.run('update-index', '--add', '--cacheinfo', '100644,' + blob + ',' + MANIFEST)
        tree = self.text('write-tree')
        require(SHA.fullmatch(tree), 'invalid_tree_identity')
        commit = self.run('commit-tree', tree, '-p', parent,
                          data=('deploy: ' + tag + ' [skip ci]\n\nPipeline ' + pipeline + '\n').encode())[0].decode().strip()
        require(SHA.fullmatch(commit), 'invalid_writeback_identity')
        return commit

    def push(self, commit):
        return self.run('push', '--porcelain', 'origin', commit + ':refs/heads/main', allowed=(0, 1))[1] == 0


def publish(repo, ctx):
    repo.prepare(ctx.head)
    tag = version(repo.blob(ctx.head, 'VERSION')) + '-' + ctx.head[:8]
    desired = IMAGE + ':' + tag
    for attempt in range(1, 4):
        current = repo.current()
        repo.source_guard(ctx.head, current, desired)
        updated, already = rewrite(repo.blob(current, MANIFEST), desired)
        if already:
            return {'gitops_updated': False, 'already_desired': True, 'revision': current,
                    'desired_image': desired, 'attempts': attempt}
        # No checkout, filters, hooks, application scripts, or force push.
        commit = repo.commit(current, updated, tag, ctx.pipeline)
        if repo.push(commit):
            return {'gitops_updated': True, 'already_desired': False, 'revision': commit,
                    'desired_image': desired, 'attempts': attempt}
    raise Failure('git_push_retries_exhausted')


def notify(revision):
    """Existing private refresh-only hook; never sync/patch a workload."""
    require(SHA.fullmatch(revision), 'invalid_refresh_revision')
    payload = {'object_kind': 'push', 'ref': 'refs/heads/main', 'after': revision,
               'project': {'web_url': 'https://10.2.0.11/downops/prompt-gateway'},
               'repository': {'url': 'ssh://git@10.2.0.11:2222/downops/prompt-gateway.git'}}
    request = urllib.request.Request('https://argocd.int.downops.win/api/webhook',
                                     data=json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json', 'X-Gitlab-Event': 'Push Hook'})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=20) as response:
            require(response.status == 200, 'argocd_refresh_failed')
            response.read(4096)
    except Exception:
        raise Failure('argocd_refresh_failed') from None


def main(env=None, vault=None, repo_factory=Git, refresh=notify):
    env = os.environ if env is None else env
    # The retained legacy CI variable is neither copied nor a fallback.
    env.pop('GITOPS_PUSH_TOKEN', None)
    state = {'no_legacy_fallback': True, 'vault_login_ok': False,
             'vault_read_ok': False, 'revoked': False}
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        jwt = env.pop('VAULT_GITOPS_ID_TOKEN', '')
        ctx = context(env, jwt)
        password = credential(vault or Vault(), jwt, state)
        with tempfile.TemporaryDirectory(prefix='prompt-gitops-') as directory:
            outcome = publish(repo_factory(directory, password), ctx)
        state.update(outcome)
        refresh(outcome['revision'])
        state['argocd_refresh_accepted'] = True
        print(json.dumps({**state, 'repository_sha256': hashlib.sha256(REPOSITORY.encode()).hexdigest()}, sort_keys=True))
        return 0
    except BaseException as error:
        failure = error if isinstance(error, Failure) else Failure('deploy_internal_error')
        print(json.dumps({**state, 'error': failure.code, 'cleanup_error': failure.cleanup}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
