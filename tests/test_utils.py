import os
import sys
import tempfile
import unittest

from pshtt.utils import smart_open


class TestSmartOpen(unittest.TestCase):
    def test_without_filename(self):
        with smart_open() as fh:
            self.assertIs(fh, sys.stdout)

    def test_with_empty_filename(self):
        """Should raise a `FileNotFoundError`"""
        with self.assertRaises(FileNotFoundError):
            with smart_open('') as fh:
                pass

    def test_with_real_filename(self):
        test_data = 'This is the test data'

        with tempfile.TemporaryDirectory() as tmp_dirname:
            # Make a temporary file to use
            filename = os.path.join(tmp_dirname, 'foo')

            with smart_open(filename) as fh:
                fh.write(test_data)

            self.assertEqual(test_data, open(filename).read())
