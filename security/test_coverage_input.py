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
    def test_only_declarations_can_report_genuine_zero_executable_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'types.d.ts').write_text('declare interface Example { name: string }\n')
            raw = b'TN:\nSF:types.d.ts\nFNF:0\nFNH:0\nLF:0\nLH:0\nBRF:0\nBRH:0\nend_of_record\n'
            control.validated_lcov(raw, root, ['types.d.ts'])
            self.assertEqual((root/'coverage/lcov.info').read_bytes(), raw)
            (root/'code.ts').write_text('export const answer = 42;\n')
            for bad, sources in [(raw.replace(b'types.d.ts', b'code.ts'), ['code.ts']),
                                 (raw.replace(b'LF:0\n', b''), ['types.d.ts']),
                                 (raw.replace(b'LH:0', b'LH:1'), ['types.d.ts'])]:
                with self.assertRaises(RuntimeError):control.validated_lcov(bad, root, sources)

    def python_report(self, filename='ci/one.py', lines='<line number="1" hits="2" branch="true" condition-coverage="50% (1/2)"/>'):
        return ('<?xml version="1.0"?><coverage><!-- coverage.py --><sources><source>/app</source></sources>'
                '<packages><package><classes><class filename="' + filename + '"><lines>' + lines
                + '</lines></class></classes></package></packages></coverage>').encode()

    def test_python_paths_map_but_line_hits_and_branches_are_preserved(self):
        import xml.etree.ElementTree as ET
        for name in ['ci/one.py', 'one.py', '/app/ci/one.py', '/srv/ci/one.py']:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root/'ci').mkdir(); (root/'ci/one.py').write_text('pass\n')
                control.validated_python_coverage(self.python_report(name), root, ['ci/one.py'])
                result = ET.parse(root/'coverage/python.xml')
                self.assertEqual(result.find('.//class').get('filename'), 'ci/one.py')
                self.assertEqual(result.find('.//line').attrib, {'number':'1','hits':'2','branch':'true','condition-coverage':'50% (1/2)'})

    def test_python_missing_invalid_oversized_external_entity_and_traversal_fail_closed(self):
        cases = [b'', b'x'*(2*1024*1024+1), b'<coverage/>',
                 self.python_report('../one.py'), self.python_report('/etc/passwd'),
                 self.python_report(lines='<line number="999" hits="1"/>'),
                 self.python_report(lines='<line number="1" hits="-1"/>'),
                 self.python_report(lines=''),
                 self.python_report(lines='<line number="1" hits="1"/><line number="1" hits="1"/>'),
                 b'<!DOCTYPE coverage [<!ENTITY x SYSTEM "file:///etc/passwd">]><coverage>&x;</coverage>',
                 '<coverage/>'.encode('utf-16')]
        for raw in cases:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises((RuntimeError, ValueError, UnicodeError, control.ET.ParseError)):
                root = Path(directory); (root/'ci').mkdir(); (root/'ci/one.py').write_text('pass\n')
                control.validated_python_coverage(raw, root, ['ci/one.py'])

    def test_python_coverage_is_required_inside_verified_bom_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'ci').mkdir(); (root/'ci/one.py').write_text('pass\n')
            with self.assertRaises(RuntimeError):
                control.unpack_bom(artifact(None), root, python_sources=['ci/one.py'])
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                archive.writestr('bom.json', '{"bomFormat":"CycloneDX","components":[{}]}')
                archive.writestr('coverage/python.xml', self.python_report())
            control.unpack_bom(output.getvalue(), root, python_sources=['ci/one.py'])
            self.assertTrue((root/'coverage/python.xml').is_file())
            with self.assertRaises(RuntimeError):
                control.unpack_bom(output.getvalue(), root)

    def test_python_symlink_or_duplicate_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'ci').mkdir(); (root/'retained').write_text('pass\n')
            (root/'ci/one.py').symlink_to(root/'retained')
            with self.assertRaises(RuntimeError):
                control.validated_python_coverage(self.python_report(), root, ['ci/one.py'])
            (root/'ci/one.py').unlink(); (root/'ci/one.py').write_text('pass\n')
            raw = self.python_report().replace(b'</classes>', b'<class filename="one.py"><lines><line number="1" hits="1"/></lines></class></classes>')
            with self.assertRaises(RuntimeError):
                control.validated_python_coverage(raw, root, ['ci/one.py'])

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
