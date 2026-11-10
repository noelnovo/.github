"""Pinned GitLab adapter; candidate code is data in the credentialed job.

The existing privileged/shared executor is an owner-accepted trust boundary,
NOT an isolation boundary. External CI configuration is controlled by Maintainers.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.parse

import premerge
import security_gate as gate

CONTROL = Path(__file__).resolve().parents[1]
API = 'https://gitlab.int.downops.win/api/v4'
VAULT = 'https://vault.int.downops.win'


def command(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError('Security command failed: ' + args[0])
    return result.stdout.decode().strip()


def profile(env):
    profiles = json.loads((CONTROL / 'security/gitlab_profiles.json').read_text())
    cfg = profiles.get(env.get('CI_PROJECT_ID'))
    if not cfg or cfg['repository'] != env.get('CI_PROJECT_PATH'):
        raise RuntimeError('Unregistered caller')
    if env.get('CI_PIPELINE_SOURCE') not in ['merge_request_event', 'push']:
        raise RuntimeError('Untrusted pipeline source')
    if env.get('CI_PIPELINE_SOURCE') == 'push' and env.get('CI_COMMIT_REF_PROTECTED') != 'true':
        raise RuntimeError('Only protected pushes may scan')
    return cfg


def api(path):
    return gate.request(API + '/projects/' + str(int(os.environ['CI_PROJECT_ID'])) + path,
                        headers={'JOB-TOKEN': os.environ['CI_JOB_TOKEN']})


def candidate(cfg, source):
    env = os.environ
    head = premerge.sha(env['CI_COMMIT_SHA'])
    actual = command('git', 'rev-parse', 'HEAD', cwd=source)
    if actual != head:
        raise RuntimeError('Checkout is not the pipeline candidate')
    if env['CI_PIPELINE_SOURCE'] == 'merge_request_event':
        if env.get('CI_MERGE_REQUEST_SOURCE_PROJECT_ID') != env['CI_PROJECT_ID']:
            raise RuntimeError('Fork MRs require a separately registered trust policy')
        target = env['CI_MERGE_REQUEST_TARGET_BRANCH_NAME']
        mr = api('/merge_requests/' + str(int(env['CI_MERGE_REQUEST_IID'])))
        if (mr['state'] != 'opened' or mr['sha'] != head or mr['target_branch'] != target
                or str(mr['target_project_id']) != env['CI_PROJECT_ID']):
            raise RuntimeError('MR source/target changed')
    else:
        target = env['CI_COMMIT_BRANCH']
    if target not in cfg['targets']:
        raise RuntimeError('Unregistered target')
    remote = command('git', 'ls-remote', 'origin', 'refs/heads/' + target, cwd=source).split()
    if len(remote) != 2:
        raise RuntimeError('Current target missing')
    base = premerge.sha(remote[0])
    command('git', 'fetch', '--no-tags', 'origin', base, cwd=source)
    if env['CI_PIPELINE_SOURCE'] == 'merge_request_event':
        command('git', 'merge-base', '--is-ancestor', base, head, cwd=source)
    elif base != head:
        raise RuntimeError('Protected push is stale')
    return {'project': env['CI_PROJECT_ID'], 'pipeline': env['CI_PIPELINE_ID'],
            'event': env['CI_PIPELINE_SOURCE'], 'head': head, 'base': base, 'target': target}


def validate_bom(raw):
    if len(raw) > 16 * 1024 * 1024:
        raise RuntimeError('SBOM exceeded bounds')
    bom = json.loads(raw)
    if bom.get('bomFormat') != 'CycloneDX' or not bom.get('components'):
        raise RuntimeError('Resolved nonempty CycloneDX required')
    return hashlib.sha256(raw).hexdigest()


def build(cfg, source):
    identity = candidate(cfg, source)
    out = source / 'security-output'
    if out.exists():
        raise RuntimeError('Unexpected preexisting security artifacts')
    out.mkdir()
    image = 'security-candidate:' + str(int(os.environ['CI_JOB_ID']))
    command('docker', 'build', '--label', 'org.opencontainers.image.revision=' + identity['head'],
            '-t', image, '.', cwd=source)
    # Syft speaks to this job's disposable DinD daemon. No host socket or registry
    # credentials and no dependency filtering, including the runtime OS packages.
    result = subprocess.run(['docker', 'run', '--rm', '--network', 'host',
        '-e', 'DOCKER_HOST=tcp://127.0.0.1:2375', gate.SYFT, image, '-o', 'cyclonedx-json'],
        capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError('Runtime SBOM generation failed')
    raw = result.stdout
    receipt = {**identity, 'bom_sha256': validate_bom(raw)}
    (out / 'bom.json').write_bytes(raw)
    (out / 'receipt.json').write_text(json.dumps(receipt) + '\n')
    if candidate(cfg, source) != identity:
        raise RuntimeError('Candidate changed while building')
    print(json.dumps({'candidate_build_verified': identity, 'sbom_components': len(json.loads(raw)['components'])}))


def credentials(cfg):
    # The signed project/event/ref/job bounds are enforced by Vault. GitLab CE
    # external configs have null ci_config_sha; don't invent a workflow claim.
    return gate.request(VAULT + '/v1/auth/gitlab-ci/login', 'POST', {
        'role': cfg['roles'][os.environ['CI_PIPELINE_SOURCE']],
        'jwt': os.environ['VAULT_ID_TOKEN']})['auth']['client_token']


def sonar(creds, work):
    # DinD cannot bind-mount this job's filesystem. Copy data, not executables,
    # into the scanner and retrieve only report-task.txt afterwards.
    name = 'security-scanner-' + str(int(os.environ['CI_JOB_ID']))
    env = {'PATH': os.environ['PATH'], 'DOCKER_HOST': os.environ['DOCKER_HOST'],
           'SONAR_TOKEN': creds['SONAR_TOKEN'], 'SONAR_HOST_URL': creds['SONAR_HOST_URL']}
    command_args = ['docker', 'create', '--name', name, '--entrypoint', 'sonar-scanner',
        '--env', 'SONAR_TOKEN', '--env', 'SONAR_HOST_URL', '--env', 'SONAR_USER_HOME=/tmp/sonar',
        gate.SCANNER, '-Dsonar.projectKey=' + creds['SONAR_PROJECT_KEY'],
        '-Dsonar.qualitygate.wait=true', '-Dsonar.qualitygate.timeout=300']
    created = subprocess.run(command_args, env=env, capture_output=True, timeout=300)
    if created.returncode:
        raise RuntimeError('Pinned scanner creation failed')
    try:
        command('docker', 'cp', str(work) + '/.', name + ':/usr/src/')
        # Source is data only; source-created modes are readable, never executable.
        result = subprocess.run(['docker', 'start', '--attach', name], capture_output=True, timeout=600)
        text = (result.stdout + result.stderr).decode(errors='replace').lower()
        print(json.dumps({'scanner_exit_code': result.returncode,
            'analysis_submitted': 'analysis report uploaded' in text,
            'quality_gate_rejected': 'quality gate status: failed' in text,
            'scanner_permission_error': 'permission denied' in text or 'accessdeniedexception' in text,
            'scanner_auth_error': 'not authorized' in text,
            'scanner_memory_error': 'outofmemoryerror' in text}))
        report = work / '.scannerwork'
        report.mkdir(exist_ok=True)
        command('docker', 'cp', name + ':/usr/src/.scannerwork/report-task.txt', str(report / 'report-task.txt'))
        return result.returncode == 0
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=60, check=True)


def evaluate(cfg, source):
    identity = candidate(cfg, source)
    out = source / 'security-output'
    if out.is_symlink() or not out.is_dir():
        raise RuntimeError('Invalid artifact directory')
    for name in ['bom.json', 'receipt.json']:
        path = out / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            raise RuntimeError('Invalid same-pipeline artifact')
    raw = (out / 'bom.json').read_bytes()
    if json.loads((out / 'receipt.json').read_text()) != {**identity, 'bom_sha256': validate_bom(raw)}:
        raise RuntimeError('Artifact candidate/pipeline/digest mismatch')
    # git archive does not execute build tools or source hooks. Never copy a
    # repository scanner configuration, source symlinks, or generated reports.
    archive = subprocess.run(['git', 'archive', '--format=tar.gz', '--prefix=source/', identity['head']],
        cwd=source, capture_output=True, check=True, timeout=60).stdout
    with tempfile.TemporaryDirectory(prefix='gitlab-security-') as directory:
        work = Path(directory)
        premerge.unpack_source(archive, work)
        (work / 'bom.json').write_bytes(raw)
        (work / 'sonar-project.properties').write_text(
            'sonar.sources=' + cfg['sources'] + '\nsonar.tests=' + cfg['tests']
            + '\nsonar.sourceEncoding=UTF-8\nsonar.scm.disabled=true\nsonar.scm.revision='
            + identity['head'] + '\n')
        gate.ROOT = work
        for path in work.rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        token = credentials(cfg)
        headers = {'X-Vault-Token': token}
        try:
            def read(service):
                return gate.request(VAULT + '/v1/downops/data/services/' + service + '/'
                    + cfg['instance'], headers=headers)['data']['data']
            dt, sq = read('dependency-track/clients'), read('sonarqube/clients')
            reader, settings = read('dependency-track/sonarqube'), read('sonarqube/project-settings')
            if (dt['DT_PROJECT_UUID'] != reader['DT_PROJECT_UUID'] or dt['DT_URL'] != reader['DT_URL']
                    or sq['SONAR_PROJECT_KEY'] != settings['SONAR_PROJECT_KEY']
                    or sq['SONAR_HOST_URL'] != settings['SONAR_HOST_URL']):
                raise RuntimeError('Credential target mismatch')
            print(json.dumps({'vault_authenticated': True, 'scoped_records_loaded': 4}))
            gate.dependency_track(dt, raw)
            expected = gate.synchronize_plugin(settings, reader)
            scanner_ok = sonar(sq, work)
            gate_ok = gate.verify_plugin_gate(settings, expected)
            if not scanner_ok or not gate_ok:
                raise RuntimeError('Configured SonarQube quality gate rejected candidate')
            if candidate(cfg, source) != identity:
                raise RuntimeError('Candidate changed during analysis; rerun required')
            print(json.dumps({'security_gate_passed': True, 'candidate': identity}))
        finally:
            gate.request(VAULT + '/v1/auth/token/revoke-self', 'POST', {}, headers)


def main():
    if command('git', 'rev-parse', 'HEAD', cwd=CONTROL) != premerge.sha(os.environ['SECURITY_CONTROL_SHA']):
        raise RuntimeError('Controller must match the immutable entrypoint pin')
    cfg = profile(os.environ)
    source = Path(os.environ['CI_PROJECT_DIR']).resolve()
    if sys.argv[1:] == ['build']:
        build(cfg, source)
    elif sys.argv[1:] == ['scan']:
        evaluate(cfg, source)
    else:
        raise RuntimeError('Expected build or scan')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'security_gate_failed': True, 'error_type': type(error).__name__,
            'reason': str(error) if type(error) is RuntimeError else 'Internal operation failed'}))
        raise SystemExit(1)
