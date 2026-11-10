"""Job-time SonarQube and Dependency-Track gates. Never log credentials/payloads."""
import base64
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCANNER = 'sonarsource/sonar-scanner-cli@sha256:38207bba3d98c8ce6f6c051ea2b9f05a24480da78c9ee5945ceafc3d9de02b88'
SYFT = 'anchore/syft@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(url, method='GET', data=None, headers=None, *, form=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password:
        raise RuntimeError('Verified HTTPS without URL credentials is required')
    req = urllib.request.Request(url, method=method,
        data=None if data is None else (urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()),
        headers={'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json',
                 'User-Agent': 'Mozilla/5.0 DownOps-Security-CI', **(headers or {})})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=60) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raise RuntimeError('Security service rejected request: HTTP ' + str(error.code)) from None
    except (urllib.error.URLError, ValueError):
        raise RuntimeError('Security service unavailable or invalid response') from None


def config():
    return json.loads((ROOT / 'ci/security.json').read_text())


def trusted_identity(cfg, env):
    if cfg['provider'] == 'github-reusable':
        # Vault additionally binds signed caller repository/owner IDs and the
        # immutable job_workflow_ref of the called reusable workflow.
        return (env.get('GITHUB_ACTIONS') == 'true'
            and env.get('GITHUB_REPOSITORY') == cfg['repository']
            and env.get('GITHUB_REPOSITORY_ID') == cfg['repository_id']
            and ((env.get('GITHUB_EVENT_NAME') == 'pull_request'
                  and env.get('GITHUB_BASE_REF') in cfg['targets'])
                 or (env.get('GITHUB_EVENT_NAME') == 'push' and 'push' in cfg.get('events', [])
                     and env.get('GITHUB_REF') in ['refs/heads/' + b for b in cfg['targets']])))
    if cfg['provider'] == 'github':
        return (env.get('GITHUB_ACTIONS') == 'true'
            and env.get('GITHUB_REPOSITORY') == cfg['repository']
            and env.get('GITHUB_EVENT_NAME') == cfg.get('event', 'push')
            and env.get('GITHUB_REF') in ['refs/heads/' + b for b in cfg['branches']]
            and env.get('GITHUB_WORKFLOW_REF') == cfg['repository'] + '/.github/workflows/'
                + cfg['workflow'] + '@' + env.get('GITHUB_REF', ''))
    return (env.get('GITLAB_CI') == 'true'
        and env.get('CI_PROJECT_ID') == cfg['project_id']
        and env.get('CI_PROJECT_PATH') == cfg['repository']
        and env.get('CI_PIPELINE_SOURCE') == 'push'
        and env.get('CI_COMMIT_REF_PROTECTED') == 'true'
        and env.get('CI_COMMIT_BRANCH') in cfg['branches'])


def login(cfg):
    if not trusted_identity(cfg, os.environ):
        raise RuntimeError('Only an exact trusted push job can obtain scanner credentials')
    if cfg['provider'] in ['github', 'github-reusable']:
        url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
        if urllib.parse.urlsplit(url).hostname != 'token.actions.githubusercontent.com':
            # GitHub uses geographically sharded *.actions.githubusercontent.com hosts.
            if not (urllib.parse.urlsplit(url).hostname or '').endswith('.actions.githubusercontent.com'):
                raise RuntimeError('Unexpected GitHub OIDC endpoint')
        url += ('&' if '?' in url else '?') + urllib.parse.urlencode({'audience': cfg['audience']})
        jwt = request(url, headers={'Authorization': 'Bearer '
            + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})['value']
        if cfg['provider'] == 'github-reusable':
            # Context only, never the JWT or credentials. Vault verifies the
            # signature and the immutable called-workflow binding independently.
            claims = json.loads(base64.urlsafe_b64decode(jwt.split('.')[1] + '==='))
            print(json.dumps({'oidc_caller_repository_id': claims.get('repository_id'),
                'oidc_event': claims.get('event_name'),
                'oidc_called_workflow': claims.get('job_workflow_ref')}))
    else:
        jwt = os.environ['VAULT_ID_TOKEN']
    return request(cfg['vault_url'] + '/v1/auth/' + cfg['auth_mount'] + '/login',
        'POST', {'role': cfg['role'], 'jwt': jwt})['auth']['client_token']


def prepare(cfg):
    if cfg['sbom'] == 'image':
        # Build before reading credentials; no credential is passed to the build.
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        branch = os.environ.get('GITHUB_REF_NAME', os.environ.get('CI_COMMIT_BRANCH', ''))
        args = []
        for key, value in cfg.get('build_args_by_branch', {}).get(branch, {}).items():
            args.extend(['--build-arg', key + '=' + value])
        subprocess.run(['docker', 'build', '--label', 'org.opencontainers.image.revision=' + revision,
            '-t', 'security-target:ci', *args, '.'], check=True, cwd=ROOT)
        archive = ROOT / 'security-image.tar'
        subprocess.run(['docker', 'save', '-o', str(archive), 'security-target:ci'], check=True)
        with (ROOT / 'bom.json').open('wb') as output:
            subprocess.run(['docker', 'run', '--rm', '--volume', str(ROOT) + ':/work:ro',
                SYFT, 'docker-archive:/work/security-image.tar', '-o', 'cyclonedx-json'],
                stdout=output, check=True)
        image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}',
            'security-target:ci'], text=True).strip()
        receipt = {'revision': revision, 'image_id': image_id, 'sha256': file_hash(archive)}
        (ROOT / 'security-image.json').write_text(json.dumps(receipt) + '\n')
    else:
        # The pinned Gradle CycloneDX plugin resolves actual transitive dependencies.
        source = ROOT / 'build/reports/cyclonedx/bom.json'
        (ROOT / 'bom.json').write_bytes(source.read_bytes())
    bom = json.loads((ROOT / 'bom.json').read_text())
    if bom.get('bomFormat') != 'CycloneDX' or not bom.get('components'):
        raise RuntimeError('A nonempty resolved CycloneDX SBOM is required')
    print(json.dumps({'sbom_generated': True, 'components': len(bom['components'])}))


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def reuse():
    receipt = json.loads((ROOT / 'security-image.json').read_text())
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if receipt['revision'] != revision or receipt['sha256'] != file_hash(ROOT / 'security-image.tar'):
        raise RuntimeError('Scanned image source/checksum does not match this publication')
    subprocess.run(['docker', 'load', '-i', str(ROOT / 'security-image.tar')], check=True,
                   capture_output=True)
    raw = subprocess.check_output(['docker', 'image', 'inspect', 'security-target:ci'])
    image = json.loads(raw)[0]
    if (image['Id'] != receipt['image_id']
        or image['Config']['Labels']['org.opencontainers.image.revision'] != revision):
        raise RuntimeError('Scanned image identity does not match this publication')
    print(json.dumps({'exact_scanned_image_reused': True, 'revision': revision}))


def dependency_track(creds, bom, *, wait=time.sleep):
    url = creds['DT_URL'].rstrip('/')
    project = str(uuid.UUID(creds['DT_PROJECT_UUID']))
    headers = {'X-Api-Key': creds['DT_API_KEY']}
    result = request(url + '/api/v1/bom', 'PUT', {
        'project': project, 'bom': base64.b64encode(bom).decode()}, headers)
    token = str(uuid.UUID(result['token']))
    for _ in range(120):
        state = request(url + '/api/v1/event/token/' + token, headers=headers)
        if state.get('processing') is False:
            break
        if state.get('processing') is not True:
            raise RuntimeError('Dependency-Track returned invalid processing state')
        wait(5)
    else:
        raise RuntimeError('Dependency-Track analysis timed out')
    counts = {}
    offset = 0
    while True:
        findings = request(url + '/api/v1/finding/project/' + project
            + '?suppressed=false&offset=' + str(offset) + '&limit=100', headers=headers)
        if not isinstance(findings, list):
            raise RuntimeError('Dependency-Track returned invalid findings')
        for finding in findings:
            severity = finding['vulnerability']['severity']
            counts[severity] = counts.get(severity, 0) + 1
        if len(findings) < 100:
            break
        offset += len(findings)
    metrics = request(url + '/api/v1/metrics/project/' + project + '/current', headers=headers)
    policy_failures = metrics.get('policyViolationsFail')
    if not isinstance(policy_failures, int):
        raise RuntimeError('Dependency-Track policy metrics are unavailable')
    print(json.dumps({'dependency_track_completed': True, 'findings': counts,
        'policy_failures': policy_failures, 'quality_gate_authority': 'sonarqube-plugin'}))
    # Findings are measures, not a second hard-coded policy. The configured
    # SonarQube gate owns severity/fixable/policy thresholds.
    return True


def sonar_request(creds, path, data=None):
    token = creds['SONAR_SETTINGS_TOKEN']
    headers = {'Authorization': 'Basic ' + base64.b64encode((token + ':').encode()).decode()}
    return request(creds['SONAR_HOST_URL'].rstrip('/') + path,
        'GET' if data is None else 'POST', data, headers, form=data is not None)


def synchronize_plugin(settings, reader):
    project = settings['SONAR_PROJECT_KEY']
    parameters = {'sonar.dependencytrack.url': reader['DT_URL'],
        'sonar.dependencytrack.project.uuid': reader['DT_PROJECT_UUID'],
        'sonar.dependencytrack.api.key': reader['DT_API_KEY']}
    for key, value in parameters.items():
        # Supported Sonar API, with Vault-injected values in HTTPS bodies only.
        sonar_request(settings, '/api/settings/set', {'component': project, 'key': key, 'value': value})
    gate = sonar_request(settings, '/api/qualitygates/get_by_project?'
        + urllib.parse.urlencode({'project': project}))['qualityGate']
    details = sonar_request(settings, '/api/qualitygates/show?'
        + urllib.parse.urlencode({'name': gate['name']}))
    expected = [c for c in details['conditions']
        if c['metric'].startswith(('new_dependencytrack_', 'dependencytrack_'))]
    if not expected:
        raise RuntimeError('The assigned Sonar quality gate has no Dependency-Track conditions')
    print(json.dumps({'sonar_plugin_settings_synchronized': True,
        'dependencytrack_gate_conditions': [c['metric'] for c in expected]}))
    return expected


def verify_plugin_gate(settings, expected):
    report = ROOT / '.scannerwork/report-task.txt'
    values = dict(line.split('=', 1) for line in report.read_text().splitlines() if '=' in line)
    task = sonar_request(settings, '/api/ce/task?'
        + urllib.parse.urlencode({'id': values['ceTaskId']}))['task']
    if task.get('status') != 'SUCCESS' or task.get('componentKey') != settings['SONAR_PROJECT_KEY']:
        raise RuntimeError('Cannot verify completed analysis for this project')
    status = sonar_request(settings, '/api/qualitygates/project_status?'
        + urllib.parse.urlencode({'analysisId': task['analysisId']}))['projectStatus']
    actual = {c['metricKey']: c for c in status['conditions']}
    diagnostics = []
    for configured in expected:
        condition = actual.get(configured['metric'])
        if not condition or condition.get('status') not in ['OK', 'ERROR']:
            raise RuntimeError('A configured Dependency-Track metric was not evaluated')
        value = Decimal(condition['actualValue'])
        threshold = Decimal(condition['errorThreshold'])
        if not value.is_finite() or not threshold.is_finite():
            raise RuntimeError('Dependency-Track gate returned invalid numeric values')
        if threshold != Decimal(configured['error']) or condition['comparator'] != configured['op']:
            raise RuntimeError('Dependency-Track gate configuration changed during analysis')
        diagnostics.append({'metric': configured['metric'], 'value': str(value),
            'threshold': str(threshold), 'comparator': condition['comparator'],
            'status': condition['status']})
    print(json.dumps({'dependencytrack_metrics_evaluated': True,
        'sonar_quality_gate_status': status['status'], 'dependencytrack_conditions': diagnostics}))
    return status['status'] == 'OK' and all(c['status'] == 'OK' for c in diagnostics)


def sonar(creds):
    env = dict(os.environ, SONAR_TOKEN=creds['SONAR_TOKEN'],
        SONAR_HOST_URL=creds['SONAR_HOST_URL'])
    # Never accept a stale report from a previous scanner invocation.
    (ROOT / '.scannerwork/report-task.txt').unlink(missing_ok=True)
    result = subprocess.run(['docker', 'run', '--rm',
        '--user', str(os.getuid()) + ':' + str(os.getgid()),
        # The image wrapper converts SONAR_TOKEN into a command-line property.
        # The current scanner reads SONAR_TOKEN natively; keep it in env only.
        '--entrypoint', 'sonar-scanner',
        '--env', 'SONAR_TOKEN', '--env', 'SONAR_HOST_URL',
        '--env', 'SONAR_USER_HOME=/tmp/sonar',
        '--volume', str(ROOT) + ':/usr/src', SCANNER,
        '-Dsonar.projectKey=' + creds['SONAR_PROJECT_KEY'],
        '-Dsonar.qualitygate.wait=true', '-Dsonar.qualitygate.timeout=300'],
        env=env, capture_output=True, timeout=600)
    # Scanner output may contain sensitive diagnostics. Emit fixed categories only.
    text = (result.stdout + result.stderr).decode(errors='replace').lower()
    categories = {name: any(needle in text for needle in needles)
        for name, needles in {
            'registry_rate_limited': ['toomanyrequests', 'you have reached your unauthenticated pull rate limit'],
            'image_pull_denied': ['pull access denied'],
            'image_unavailable': ['manifest unknown', 'no matching manifest'],
            'docker_unavailable': ['cannot connect to the docker daemon'],
            'network_failure': ['connection refused', 'failed to connect', 'unknownhostexception', 'connection timed out'],
            'tls_failure': ['sslhandshakeexception', 'pkix path building failed'],
            'http_401': ['http 401', 'status code: 401', 'status 401'],
            'http_403': ['http 403', 'status code: 403', 'status 403'],
            'filesystem_permission': ['accessdeniedexception', 'permission denied', 'unable to create'],
            'missing_binaries': ['please provide compiled classes', 'no files nor directories matching'],
            'duplicate_index': ['indexed twice'],
            'unsafe_git_directory': ['dubious ownership', 'unsafe repository'],
            'out_of_memory': ['outofmemoryerror'],
        }.items()}
    print(json.dumps({'sonarqube_quality_gate_passed': result.returncode == 0,
        'scanner_exit_code': result.returncode,
        'quality_gate_rejected': 'quality gate status: failed' in text,
        'authentication_failure': 'not authorized' in text or 'authentication failed' in text,
        'analysis_submitted': 'analysis report uploaded' in text,
        'scanner_failure_categories': categories}))
    return result.returncode == 0


def scan(cfg):
    bom = (ROOT / 'bom.json').read_bytes()
    if not json.loads(bom).get('components'):
        raise RuntimeError('Refusing to scan an empty SBOM')
    token = login(cfg)
    print(json.dumps({'vault_authenticated': True}))
    headers = {'X-Vault-Token': token}
    try:
        def read(service):
            path = 'downops/data/services/' + service + '/clients/' + cfg['instance']
            return request(cfg['vault_url'] + '/v1/' + path, headers=headers)['data']['data']
        dt = read('dependency-track')
        sq = read('sonarqube')
        reader = request(cfg['vault_url'] + '/v1/downops/data/services/dependency-track/sonarqube/'
            + cfg['instance'], headers=headers)['data']['data']
        settings = request(cfg['vault_url'] + '/v1/downops/data/services/sonarqube/project-settings/'
            + cfg['instance'], headers=headers)['data']['data']
        if (reader['DT_PROJECT_UUID'] != dt['DT_PROJECT_UUID']
            or reader['DT_URL'] != dt['DT_URL']
            or settings['SONAR_PROJECT_KEY'] != sq['SONAR_PROJECT_KEY']
            or settings['SONAR_HOST_URL'] != sq['SONAR_HOST_URL']):
            raise RuntimeError('Scanner and plugin credentials refer to different projects')
        print(json.dumps({'scanner_credentials_loaded': True}))
        # Preserve ordering: current BOM analysis -> secret/config synchronization
        # -> plugin measures -> configured quality gate. Never analyze stale DT data.
        print(json.dumps({'security_stage': 'dependency_track_analysis'}))
        dependency_track(dt, bom)
        print(json.dumps({'security_stage': 'sonar_plugin_configuration'}))
        expected = synchronize_plugin(settings, reader)
        print(json.dumps({'security_stage': 'sonar_analysis'}))
        scanner_passed = sonar(sq)
        print(json.dumps({'security_stage': 'sonar_plugin_gate_verification'}))
        gate_passed = verify_plugin_gate(settings, expected)
        if not scanner_passed or not gate_passed:
            raise RuntimeError('SonarQube quality gate failed; publication blocked')
    finally:
        request(cfg['vault_url'] + '/v1/auth/token/revoke-self', 'POST', {}, headers)


def main():
    cfg = config()
    if sys.argv[1:] == ['prepare']:
        prepare(cfg)
    elif sys.argv[1:] == ['scan']:
        scan(cfg)
    elif sys.argv[1:] == ['reuse']:
        reuse()
    else:
        raise RuntimeError('Expected prepare, scan, or reuse')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'security_gate_failed': True, 'error_type': type(error).__name__}))
        raise SystemExit(1)
