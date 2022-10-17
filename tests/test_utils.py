"""Test the utility functions for the pshtt library."""

# Standard Python Libraries
import os
import sys
import tempfile
import unittest

# cisagov Libraries
from pshtt.utils import smart_open


class TestSmartOpen(unittest.TestCase):
    """Test the functionality of the smart_open function."""

    def test_without_filename(self):
        """Test that standard out is used if no filename is provided."""
        with smart_open() as fh:
            self.assertIs(fh, sys.stdout)

    def test_with_empty_filename(self):
        """Test when an empty string is provided as a filename.

        Should raise a `FileNotFoundError`
        """
        with self.assertRaises(FileNotFoundError):  # noqa
            with smart_open(""):
                pass

    def test_with_real_filename(self):
        """Test when a valid string is provided as a filename."""
        test_data = "This is the test data"

        with tempfile.TemporaryDirectory() as tmp_dirname:
            # Make a temporary file to use
            filename = os.path.join(tmp_dirname, "foo")

            with smart_open(filename) as fh:
                fh.write(test_data)

            self.assertEqual(test_data, open(filename).read())
