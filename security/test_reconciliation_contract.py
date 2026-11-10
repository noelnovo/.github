"""Keep the separately reviewed Android baseline intact during web/Python maintenance.

Rebaseline these guards only with an explicitly reviewed Android change. They
preserve existing behavior, including known limitations; they add no exclusions.
No Git history or network access is required by these tests in a shallow checkout.
"""
import ast
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FROZEN_ANDROID_BASE = 'cc4ce6779f6f4ee751f1f30b2a319b08adb20830'


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


class ReconciliationContractTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/dependency-track-scan.yml').read_text()
        self.profiles = json.loads((ROOT / 'security/profiles.json').read_text())
        self.code = (ROOT / 'security/premerge.py').read_text()
        self.tree = ast.parse(self.code)

    def test_configuration_documents_start_with_configuration_not_download_status(self):
        self.assertTrue(self.workflow.startswith('name:'), 'Workflow has unexpected leading text')
        self.assertTrue((ROOT / 'security/profiles.json').read_text().startswith('{'))
        self.assertTrue(json.loads((ROOT / 'security/gitlab_profiles.json').read_text()))

    def test_android_profile_is_exactly_the_frozen_reviewed_object(self):
        canonical = json.dumps(self.profiles['909094292'], sort_keys=True, separators=(',', ':'))
        self.assertEqual(digest(canonical), '0cf666022015e2d6159482cabb741b77b9fe2f184e4f88c390bd23387f184573')

    def test_android_unpack_and_dispatch_are_preserved(self):
        functions = {n.name: n for n in self.tree.body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(digest(ast.get_source_segment(self.code, functions['unpack_android'])),
                         '2b6c78a78b91103a3b97b32b10a0304d0c64dd9e4cf7ed1c3a8b48eeabe76598')
        self.assertEqual(digest(ast.get_source_segment(self.code, functions['context'])),
                         'ee09a57eadb9e6a3f2352b6cea9444c5cac4bf02bead1715578b4ffc64e93340')
        calls = [node for node in ast.walk(self.tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'unpack_android']
        self.assertEqual(len(calls), 1)
        self.assertEqual(digest(ast.dump(calls[0], include_attributes=False)),
                         '054aa35e4affcc8a18b40b713ac24075a1b2532c954767674cb5bae329564fd5')

    def test_android_gradle_and_artifact_fields_are_unchanged(self):
        gradle = next(line for line in self.workflow.splitlines() if 'sh gradlew ' in line)
        self.assertEqual(digest(gradle), '65f73be157ac48435b261b3788c2770133e7fd97adf80cbcd8c81853c0bd4885')
        artifact = self.workflow.split("        if: needs.candidate.outputs.adapter == 'android'\n", 1)[1]
        artifact = artifact.split('\n  quality-gate:', 1)[0].strip()
        self.assertEqual(digest(artifact), '9d409f1ba369d0c9726c4214d9174c23c437b2c5326096011f4ae0f9ada008a6')

    def test_three_target_profiles_require_both_reports_without_coverage_exclusions(self):
        gitlab = json.loads((ROOT / 'security/gitlab_profiles.json').read_text())
        for profile in [self.profiles['864547743'], self.profiles['1406330066'], gitlab['10']]:
            props = profile['sonar_properties']
            self.assertFalse('sonar.coverage.exclusions' in props, 'Coverage exclusions added to a target profile')
            self.assertEqual(props['sonar.javascript.lcov.reportPaths'], 'coverage/lcov.info')
            self.assertEqual(props['sonar.python.coverage.reportPaths'], 'coverage/python.xml')
            self.assertTrue(profile['coverage_sources'])
            self.assertTrue(profile['python_sources'])
        sources = self.profiles['864547743']['coverage_sources']
        for name in ['src/pages/api/contact.ts', 'src/types.d.ts', 'src/data/dataDef.ts']:
            self.assertIn(name, sources)

    def test_python_coverage_extension_stays_in_the_existing_image_artifact(self):
        image_artifact = self.workflow.split("      - uses: actions/upload-artifact@v4\n        if: needs.candidate.outputs.adapter == 'image'\n", 1)[1]
        image_artifact = image_artifact.split('      - uses: actions/upload-artifact@v4', 1)[0]
        self.assertIn('coverage/python.xml', image_artifact)
        self.assertIn('coverage/lcov.info', image_artifact)
        gate = self.workflow.split('\n  quality-gate:\n', 1)[1]
        self.assertFalse(any(command in gate for command in ['npm ', 'pytest ', 'docker build', 'node --test']))


if __name__ == '__main__':
    unittest.main()
