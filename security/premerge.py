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
import xml.etree.ElementTree as ET
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


def api(profile, path, data=None):
    return download('https://api.github.com/repos/' + profile['repository'] + path,
                    token=os.environ['GITHUB_TOKEN'], data=data)


def identity(event, env):
    profiles = json.loads((ROOT / 'security/profiles.json').read_text())
    project_id = str(event['repository']['id'])
    if project_id != env.get('GITHUB_REPOSITORY_ID') or project_id not in profiles:
        raise RuntimeError('Caller repository is not registered')
    profile = profiles[project_id]
    event_name = env.get('GITHUB_EVENT_NAME')
    if (profile['repository'] != env.get('GITHUB_REPOSITORY')
        or event_name not in profile.get('events', ['pull_request'])):
        raise RuntimeError('Unexpected repository or event')
    if event_name == 'push':
        target = env.get('GITHUB_REF', '').removeprefix('refs/heads/')
        commit = sha(event['after'])
        if (target not in profile['targets'] or env.get('GITHUB_REF') != 'refs/heads/' + target
            or env.get('GITHUB_SHA') != commit or event.get('deleted')):
            raise RuntimeError('Unexpected push identity')
        return profile, {'event': event_name, 'number': 0, 'head': commit, 'base': None, 'target': target}
    pr = event['pull_request']
    if (profile['repository'] != env.get('GITHUB_REPOSITORY')
        or pr['base']['repo']['id'] != int(project_id)
        or pr['base']['ref'] not in profile['targets']):
        raise RuntimeError('Unexpected repository or target')
    number = event['number']
    if type(number) is not int or number <= 0:
        raise RuntimeError('Invalid PR number')
    return profile, {'event': event_name, 'number': number, 'head': sha(pr['head']['sha']),
                     'base': sha(pr['base']['sha']), 'target': pr['base']['ref']}


def candidate(profile, expected):
    if expected.get('event') == 'push':
        current = api(profile, '/branches/' + expected['target'])
        if current['commit']['sha'] != expected['head'] or not current.get('protected'):
            raise RuntimeError('Stale or unprotected push source')
        return sha(current['commit']['sha'])
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


def publish(profile, expected, state):
    # Existing Android branch protection consumes these exact statuses. Image
    # profiles keep their existing check-run interface, without extra statuses.
    if not profile.get('status_prefix') or expected.get('event') != 'pull_request':
        return
    if state not in ['pending', 'success', 'failure']:
        raise RuntimeError('Invalid required-status state')
    api(profile, '/statuses/' + expected['head'], {
        'state': state, 'context': profile['status_prefix'] + expected['target'],
        'description': 'Exact candidate ' + ('passed the security gate' if state == 'success' else 'security ' + state),
        'target_url': 'https://github.com/' + profile['repository'] + '/actions/runs/' + str(int(os.environ['GITHUB_RUN_ID']))})


def safe_path(name):
    path = PurePosixPath(name)
    if not path.parts or path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name:
        raise RuntimeError('Unsafe archive path')
    return path


def unpack_source(data, destination, *, android=False):
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
            if android and (relative.parts[0] == 'build' or relative.parts[:2] == ('app', 'build')):
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


def validated_lcov(raw, destination, sources):
    if len(raw) > 2 * 1024 * 1024:
        raise RuntimeError('Coverage report exceeded bounds')
    allowed = {str(safe_path(name)) for name in sources}
    seen, lines = set(), []
    current, maximum, has_data = None, 0, False
    summary = {}
    for line in raw.decode('utf-8').splitlines():
        if line.startswith('SF:'):
            if current is not None:
                raise RuntimeError('Unterminated LCOV source record')
            name = line[3:]
            for prefix in ['file:///app/', '/app/']:
                if name.startswith(prefix):
                    name = name[len(prefix):]
                    break
            current = str(safe_path(name))
            if current not in allowed or current in seen:
                raise RuntimeError('Unexpected or duplicate coverage source')
            source = destination.joinpath(*PurePosixPath(current).parts)
            if not source.is_file() or source.is_symlink():
                raise RuntimeError('Coverage source is absent or not regular')
            maximum = len(source.read_bytes().splitlines())
            seen.add(current)
            has_data = False
            summary = {}
            line = 'SF:' + current  # Path mapping only; never change hit counts.
        elif line.startswith('DA:'):
            fields = line[3:].split(',')
            if (current is None or len(fields) < 2 or not fields[0].isdigit()
                or not fields[1].isdigit() or not 1 <= int(fields[0]) <= maximum):
                raise RuntimeError('Invalid LCOV source line/count')
            has_data = True
        elif line.partition(':')[0] in ['FNF', 'FNH', 'LF', 'LH', 'BRF', 'BRH']:
            key, _, value = line.partition(':')
            if current is None or key in summary or not value.isdigit():
                raise RuntimeError('Invalid LCOV record totals')
            summary[key] = value
        elif line == 'end_of_record':
            # Declaration-only TypeScript has no runtime statements. Preserve its
            # genuine zero-line record, never discard it or invent executable hits.
            declaration = (current is not None and current.endswith('.d.ts')
                and summary == dict.fromkeys(['FNF', 'FNH', 'LF', 'LH', 'BRF', 'BRH'], '0'))
            if current is None or (not has_data and not declaration):
                raise RuntimeError('LCOV record has no executable line data')
            current = None
        lines.append(line)
    if current is not None or seen != allowed:
        raise RuntimeError('Missing required coverage source evidence')
    report = destination / 'coverage/lcov.info'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text('\n'.join(lines) + '\n')
    report.chmod(0o600)
    print(json.dumps({'coverage_report_validated': True, 'source_files': len(seen)}))


def validated_python_coverage(raw, destination, sources):
    """Treat coverage.py XML as bounded scanner data, never as executable input."""
    if len(raw) > 2 * 1024 * 1024 or any(marker in raw.upper() for marker in [b'<!DOCTYPE', b'<!ENTITY']):
        raise RuntimeError('Python coverage exceeded bounds or contains declarations')
    allowed = {str(safe_path(name)) for name in sources}
    text = raw.decode('utf-8')
    if '\x00' in text:
        raise RuntimeError('Python coverage must use UTF-8')
    document = ET.fromstring(text)
    if document.tag != 'coverage':
        raise RuntimeError('Expected coverage.py XML')
    seen = set()
    for entry in document.findall('./packages/package/classes/class'):
        name = entry.get('filename', '')
        for prefix in ['/app/', '/srv/']:
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        name = str(safe_path(name))
        matches = [p for p in allowed if p == name or p.rsplit('/', 1)[-1] == name]
        if len(matches) != 1 or matches[0] in seen:
            raise RuntimeError('Unexpected or duplicate Python coverage source')
        name = matches[0]
        source = destination / name
        if not source.is_file() or source.is_symlink():
            raise RuntimeError('Python coverage source is not regular')
        maximum = len(source.read_bytes().splitlines())
        lines, numbered = entry.findall('./lines/line'), set()
        for line in lines:
            number, hits = line.get('number', ''), line.get('hits', '')
            if (not number.isdigit() or not hits.isdigit() or not 1 <= int(number) <= maximum
                    or number in numbered):
                raise RuntimeError('Invalid Python coverage source line/count')
            numbered.add(number)
        if not lines and maximum:
            # Empty package initializers contain no executable statements.
            if source.read_text().strip():
                raise RuntimeError('Python coverage record has no line data')
        entry.set('filename', name)  # Path mapping only; preserve real hit/branch data.
        seen.add(name)
    if seen != allowed:
        raise RuntimeError('Missing Python coverage source evidence')
    roots = document.find('sources')
    if roots is not None:
        roots.clear()
        ET.SubElement(roots, 'source').text = '.'
    report = destination / 'coverage/python.xml'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_bytes(ET.tostring(document))
    report.chmod(0o600)


def unpack_bom(data, destination, *, coverage_sources=None, python_sources=None):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = [m for m in archive.infolist() if not m.is_dir()]
        expected = ({'bom.json'} | ({'coverage/lcov.info'} if coverage_sources else set())
                    | ({'coverage/python.xml'} if python_sources else set()))
        entries = {}
        for member in files:
            name = str(safe_path(member.filename))
            mode = (member.external_attr >> 16) & 0o170000
            if name not in expected or name in entries or mode not in [0, stat.S_IFREG]:
                raise RuntimeError('Unexpected SBOM/coverage artifact entry')
            limit = 16 * 1024 * 1024 if name == 'bom.json' else 2 * 1024 * 1024
            if member.file_size > limit:
                raise RuntimeError('SBOM/coverage artifact exceeded bounds')
            entries[name] = member
        if set(entries) != expected:
            raise RuntimeError('Required SBOM/coverage artifact file missing')
        member = entries['bom.json']
        raw = archive.read(member)
        bom = json.loads(raw)
        if bom.get('bomFormat') != 'CycloneDX' or not bom.get('components'):
            raise RuntimeError('Resolved, nonempty CycloneDX SBOM required')
        (destination / 'bom.json').write_bytes(raw)
        if coverage_sources:
            validated_lcov(archive.read(entries['coverage/lcov.info']), destination, coverage_sources)
        if python_sources:
            validated_python_coverage(archive.read(entries['coverage/python.xml']), destination, python_sources)


def unpack_android(data, destination, *, coverage_report=None):
    """Bytecode and coverage XML are scanner data only. No Gradle/JAR/script executes here."""
    total, classes, sbom, coverage = 0, 0, False, False
    seen = set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if len(archive.infolist()) > 20000:
            raise RuntimeError('Too many Android artifact entries')
        for member in archive.infolist():
            path = safe_path(member.filename)
            mode = (member.external_attr >> 16) & 0o170000
            if mode not in [0, stat.S_IFREG, stat.S_IFDIR]:
                raise RuntimeError('Android artifact link/device rejected')
            if member.is_dir():
                continue
            name = str(path)
            is_bom = name == 'build/reports/cyclonedx/bom.json'
            is_coverage = name == coverage_report if coverage_report else False
            allowed = is_bom or is_coverage or (name.startswith(('app/build/intermediates/javac/',
                'app/build/tmp/kotlin-classes/', 'app/build/intermediates/built_in_kotlinc/'))
                and name.endswith(('.class', '.jar', '.kotlin_module')))
            if not allowed or name in seen:
                raise RuntimeError('Unexpected or duplicate Android artifact path')
            seen.add(name)
            total += member.file_size
            if total > MAX_EXPANDED or ((is_bom or is_coverage) and member.file_size > 16 * 1024 * 1024):
                raise RuntimeError('Android artifact expansion exceeded bounds')
            raw = archive.read(member)
            if is_bom:
                bom = json.loads(raw)
                if bom.get('bomFormat') != 'CycloneDX' or not bom.get('components'):
                    raise RuntimeError('Resolved Android CycloneDX required')
                (destination / 'bom.json').write_bytes(raw)
                sbom = True
            elif is_coverage:
                if not raw.lstrip().startswith(b'<?xml') or b'<coverage' not in raw:
                    raise RuntimeError('Resolved Android coverage XML required')
                target = destination.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                target.chmod(0o600)
                coverage = True
            else:
                target = destination.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                target.chmod(0o600)
                classes += name.endswith('.class')
    if not classes or not sbom or (coverage_report and not coverage):
        raise RuntimeError('Android SBOM, compiled classes and coverage report required')


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
    publish(profile, expected, 'pending')
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
        output.write('adapter=' + profile.get('adapter', 'image') + '\n')
        output.write('reuse_android=' + str(profile.get('adapter') == 'android' and expected.get('event') == 'push').lower() + '\n')
        output.write('target=' + expected['target'] + '\n')
        output.write('analysis_group=' + profile.get('analysis_group', 'sonar-dtrack-analysis-' + profile['repository_id']) + '\n')
        output.write('coverage_format=' + ('jacoco' if profile.get('coverage_report')
            else ('lcov' if profile.get('coverage_sources') else 'none')) + '\n')
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
    if 'roles' in profile:
        cfg['role'] = profile['roles'][expected['event']]
    with tempfile.TemporaryDirectory(prefix='security-pr-', dir=os.environ.get('RUNNER_TEMP')) as directory:
        work = Path(directory)
        if profile.get('adapter') == 'android':
            unpack_source(source, work, android=True)
            unpack_android(data, work, coverage_report=profile.get('coverage_report'))
        else:
            unpack_source(source, work)
            unpack_bom(data, work, coverage_sources=profile.get('coverage_sources'),
                       python_sources=profile.get('python_sources'))
        settings = {'sonar.sources': profile['sources'], 'sonar.tests': 'ci',
            'sonar.test.inclusions': 'ci/test_*.py', 'sonar.exclusions': '**/__pycache__/**,ci/test_*.py',
            'sonar.sourceEncoding': 'UTF-8', 'sonar.scm.disabled': 'true', 'sonar.scm.revision': commit}
        if profile.get('adapter') == 'android':
            settings.pop('sonar.test.inclusions')
        settings.update(profile.get('sonar_properties', {}))
        properties = ''.join(key + '=' + value + '\n' for key, value in settings.items())
        (work / 'sonar-project.properties').write_text(properties)
        security_gate.ROOT = work
        # Do NOT call image prepare/build here. The privileged job only analyzes
        # independently fetched source and the verified SBOM as data.
        security_gate.scan(cfg)
    if candidate(profile, expected) != commit:
        raise RuntimeError('PR changed during analysis; success refused')
    publish(profile, expected, 'success')
    print(json.dumps({'security_passed': True, 'candidate': commit}))


def main():
    profile, expected = None, None
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
        if profile is not None and expected is not None:
            try:
                publish(profile, expected, 'failure')
            except Exception:
                pass  # Failure/missing/pending required status never becomes green.
        reasons = {'Failed, cancelled or skipped producer cannot pass': 'producer_not_successful',
            'SonarQube quality gate failed; publication blocked': 'quality_gate_rejected'}
        print(json.dumps({'security_failed': True, 'error_type': type(error).__name__,
            'reason': reasons.get(str(error), 'details_withheld') if isinstance(error, RuntimeError) else 'details_withheld'}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
