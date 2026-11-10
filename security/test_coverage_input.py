import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import premerge as control

SOURCES = ['ci/one.mjs', 'ci/two.cjs']


def report(prefix=''):
    return ''.join('TN:\nSF:' + prefix + name + '\nDA:1,1\nDA:2,0\nend_of_record\n' for name in SOURCES).encode()


def fixture(root):
    (root / 'ci').mkdir()
    for name in SOURCES:(root / name).write_text('line one\nline two\n')


def artifact(coverage):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('bom.json', json.dumps({'bomFormat': 'CycloneDX', 'components': [{}]}))
        if coverage is not None:archive.writestr('coverage/lcov.info', coverage)
    return output.getvalue()


class CoverageInputTests(unittest.TestCase):
    def test_only_reviewed_source_paths_are_mapped_and_hit_counts_unchanged(self):
        for prefix in ['', '/app/', 'file:///app/']:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory);fixture(root)
                control.validated_lcov(report(prefix), root, SOURCES)
                self.assertEqual((root / 'coverage/lcov.info').read_bytes(), report())

    def test_missing_traversal_absolute_duplicate_and_out_of_bounds_fail_closed(self):
        bad = [b'', report().replace(b'ci/one.mjs', b'../one.mjs'),
               report().replace(b'ci/one.mjs', b'/etc/passwd'),
               report().replace(b'ci/two.cjs', b'ci/one.mjs'),
               report().replace(b'DA:2,0', b'DA:9999,100'),
               report().replace(b'DA:1,1', b'DA:1,-1'),
               report().replace(b'end_of_record\n', b''),
               report().split(b'TN:')[1]]
        for data in bad:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises((RuntimeError, ValueError)):
                root = Path(directory);fixture(root)
                control.validated_lcov(data, root, SOURCES)

    def test_unavailable_source_cannot_claim_coverage(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(RuntimeError):
            control.validated_lcov(report(), Path(directory), SOURCES)

    def test_image_profile_requires_coverage_inside_same_verified_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);fixture(root)
            with self.assertRaises(RuntimeError):control.unpack_bom(artifact(None), root, coverage_sources=SOURCES)
            control.unpack_bom(artifact(report('/app/')), root, coverage_sources=SOURCES)
            self.assertTrue((root / 'bom.json').is_file())
            self.assertTrue((root / 'coverage/lcov.info').is_file())
            with self.assertRaises(RuntimeError):control.unpack_bom(artifact(report()), root)


if __name__ == '__main__':unittest.main()
