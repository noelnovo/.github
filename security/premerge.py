"""Pinned reusable control plane: analyze PR data without executing it with secrets."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import security_gate

ROOT = Path(__file__).resolve().parents[1]
MAX_DOWNLOAD = 32 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}\Z')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise RuntimeError('Invalid commit identity')
    return value


def download(url, *, token=None, data=None, binary=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password:
        raise RuntimeError('Verified HTTPS required')
    headers = {'User-Agent': 'DownOps-Pinned-Security', 'Accept': 'application/vnd.github+json'}
    if token:
        if parsed.hostname != 'api.github.com':
            raise RuntimeError('GitHub credential destination rejected')
        headers['Authorization'] = 'Bearer ' + token
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, headers=headers,
        data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=60) as response:
            raw = response.read(MAX_DOWNLOAD + 1)
    except urllib.error.HTTPError as error:
        if binary and error.code == 302:
            location = error.headers['Location']
            host = urllib.parse.urlsplit(location).hostname or ''
            if not (host == 'codeload.github.com' or host.endswith('.blob.core.windows.net')
                    or host.endswith('.actions.githubusercontent.com')):
                raise RuntimeError('Unexpected signed-download destination') from None
            return download(location, binary=True)  # Never forward API credentials.
        raise RuntimeError('GitHub HTTP ' + str(error.code)) from None
    if len(raw) > MAX_DOWNLOAD:
        raise RuntimeError('Bounded download exceeded')
    return raw if binary else (json.loads(raw) if raw else {})


def api(profile, path):
    return download('https://api.github.com/repos/' + profile['repository'] + path,
                    token=os.environ['GITHUB_TOKEN'])


def identity(event, env):
    if env.get('GITHUB_EVENT_NAME') != 'pull_request':
        raise RuntimeError('Only PR events are supported')
    profiles = json.loads((ROOT / 'security/profiles.json').read_text())
    project_id = str(event['repository']['id'])
    if project_id != env.get('GITHUB_REPOSITORY_ID') or project_id not in profiles:
        raise RuntimeError('Caller repository is not registered')
    profile = profiles[project_id]
    pr = event['pull_request']
    if (profile['repository'] != env.get('GITHUB_REPOSITORY')
        or pr['base']['repo']['id'] != int(project_id)
        or pr['base']['ref'] not in profile['targets']):
        raise RuntimeError('Unexpected repository or target')
    number = event['number']
    if type(number) is not int or number <= 0:
        raise RuntimeError('Invalid PR number')
    return profile, {'number': number, 'head': sha(pr['head']['sha']),
                     'base': sha(pr['base']['sha']), 'target': pr['base']['ref']}


def candidate(profile, expected):
    current = api(profile, '/pulls/' + str(expected['number']))
    if (current['state'] != 'open' or current['head']['sha'] != expected['head']
        or current['base']['sha'] != expected['base'] or current['base']['ref'] != expected['target']
        or current['base']['repo']['id'] != int(profile['repository_id'])):
        raise RuntimeError('PR source or target changed; new run required')
    if current.get('mergeable') is False:
        raise RuntimeError('Conflicting candidate')
    if not current.get('merge_commit_sha'):
        return None
    commit = sha(current['merge_commit_sha'])
    parents = api(profile, '/git/commits/' + commit)['parents']
    if [p['sha'] for p in parents] != [expected['base'], expected['head']]:
        raise RuntimeError('Candidate parent mismatch')
    return commit


def controller():
    expected = sha(os.environ.get('SECURITY_CONTROL_SHA'))
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if actual != expected:
        raise RuntimeError('Control checkout is not the pinned code revision')


def safe_path(name):
    path = PurePosixPath(name)
    if not path.parts or path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name:
        raise RuntimeError('Unsafe archive path')
    return path


def unpack_source(data, destination):
    total = 0
    seen = set()
    prefix = None
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            path = safe_path(member.name)
            prefix = prefix or path.parts[0]
            if path.parts[0] != prefix or (not member.isfile() and not member.isdir()):
                raise RuntimeError('Unexpected source root, link or device')
            relative = PurePosixPath(*path.parts[1:])
            if not relative.parts:
                continue
            if relative.parts[0] in ['.git', '.scannerwork', 'bom.json', 'sonar-project.properties']:
                continue
            if str(relative) in seen:
                raise RuntimeError('Duplicate source entry')
            seen.add(str(relative))
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if total > MAX_EXPANDED or len(seen) > 20000:
                raise RuntimeError('Source expansion exceeded bounds')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
            target.chmod(0o600)


def unpack_bom(data, destination):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = [m for m in archive.infolist() if not m.is_dir()]
        if len(files) != 1:
            raise RuntimeError('Exactly one SBOM artifact file is required')
        member = files[0]
        path = safe_path(member.filename)
        mode = (member.external_attr >> 16) & 0o170000
        if str(path) != 'bom.json' or mode not in [0, stat.S_IFREG] or member.file_size > 16 * 1024 * 1024:
            raise RuntimeError('Unexpected SBOM artifact entry')
        raw = archive.read(member)
        bom = json.loads(raw)
        if bom.get('bomFormat') != 'CycloneDX' or not bom.get('components'):
            raise RuntimeError('Resolved, nonempty CycloneDX SBOM required')
        (destination / 'bom.json').write_bytes(raw)


def artifact(profile, commit):
    run = int(os.environ['GITHUB_RUN_ID'])
    attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
    name = 'security-bom-' + commit + '-' + str(attempt)
    rows = api(profile, '/actions/runs/' + str(run) + '/artifacts?per_page=100')['artifacts']
    matches = [a for a in rows if a['name'] == name and not a['expired']]
    if len(matches) != 1 or matches[0].get('workflow_run', {}).get('id') != run:
        raise RuntimeError('Same-run immutable artifact missing')
    item = matches[0]
    digest = item.get('digest', '')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
        raise RuntimeError('Artifact digest missing')
    data = download('https://api.github.com/repos/' + profile['repository']
        + '/actions/artifacts/' + str(int(item['id'])) + '/zip',
        token=os.environ['GITHUB_TOKEN'], binary=True)
    if 'sha256:' + hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError('Artifact checksum mismatch')
    return data


def context(profile, expected):
    controller()
    commit = None
    for attempt in range(5):
        commit = candidate(profile, expected)
        if commit:
            break
        time.sleep(2)
    if not commit:
        raise RuntimeError('Candidate is not ready')
    hugo = profile.get('build_args', {}).get(expected['target'], {}).get('HUGO_BASEURL', '')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('candidate=' + commit + '\n')
        output.write('hugo_baseurl=' + hugo + '\n')
    print(json.dumps({'candidate_verified': True, 'candidate': commit, 'target': expected['target']}))


def evaluate(profile, expected):
    if os.environ.get('SECURITY_BUILD_RESULT') != 'success':
        raise RuntimeError('Failed, cancelled or skipped producer cannot pass')
    controller()
    commit = sha(os.environ.get('SECURITY_CANDIDATE'))
    if candidate(profile, expected) != commit:
        raise RuntimeError('Stale candidate before analysis')
    data = artifact(profile, commit)
    source = download('https://api.github.com/repos/' + profile['repository'] + '/tarball/' + commit,
                      token=os.environ['GITHUB_TOKEN'], binary=True)
    cfg = {**profile, 'provider': 'github-reusable', 'vault_url': 'https://vault.downops.win',
           'audience': 'https://vault.downops.win', 'auth_mount': 'github-actions'}
    with tempfile.TemporaryDirectory(prefix='security-pr-', dir=os.environ.get('RUNNER_TEMP')) as directory:
        work = Path(directory)
        unpack_source(source, work)
        unpack_bom(data, work)
        properties = ('sonar.sources=' + profile['sources'] + '\nsonar.tests=ci\n'
            'sonar.test.inclusions=ci/test_*.py\nsonar.exclusions=**/__pycache__/**,ci/test_*.py\n'
            'sonar.sourceEncoding=UTF-8\nsonar.scm.disabled=true\nsonar.scm.revision=' + commit + '\n')
        (work / 'sonar-project.properties').write_text(properties)
        security_gate.ROOT = work
        # Do NOT call image prepare/build here. The privileged job only analyzes
        # independently fetched source and the verified SBOM as data.
        security_gate.scan(cfg)
    if candidate(profile, expected) != commit:
        raise RuntimeError('PR changed during analysis; success refused')
    print(json.dumps({'security_passed': True, 'candidate': commit}))


def main():
    try:
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        profile, expected = identity(event, os.environ)
        if sys.argv[1:] == ['context']:
            context(profile, expected)
        elif sys.argv[1:] == ['gate']:
            evaluate(profile, expected)
        else:
            raise RuntimeError('Expected context or gate')
    except Exception as error:
        reasons = {'Failed, cancelled or skipped producer cannot pass': 'producer_not_successful',
            'SonarQube quality gate failed; publication blocked': 'quality_gate_rejected'}
        print(json.dumps({'security_failed': True, 'error_type': type(error).__name__,
            'reason': reasons.get(str(error), 'details_withheld') if isinstance(error, RuntimeError) else 'details_withheld'}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
