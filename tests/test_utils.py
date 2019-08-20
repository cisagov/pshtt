
import datetime
import os
import sys
import tempfile
import unittest

from pshtt.utils import format_datetime, format_last_exception, json_for, smart_open


class TestSmartOpen(unittest.TestCase):
    def test_without_filename(self):
        with smart_open() as fh:
            self.assertIs(fh, sys.stdout)

    @unittest.skipIf(sys.version_info[0] < 3, 'Python 3 version of test')
    def test_with_empty_filename(self):
        """Should raise a `FileNotFoundError`"""
        with self.assertRaises(FileNotFoundError):  # noqa
            with smart_open(''):
                pass

    @unittest.skipIf(sys.version_info[0] >= 3, 'Python 2 version of test')
    def test_with_empty_filename_python2(self):
        """Should raise a `FileNotFoundError`"""
        with self.assertRaises(IOError):
            with smart_open(''):
                pass

    @unittest.skipIf(sys.version_info[0] < 3, 'Python 3 version of test')
    def test_with_real_filename(self):
        test_data = 'This is the test data'

        with tempfile.TemporaryDirectory() as tmp_dirname:
            # Make a temporary file to use
            filename = os.path.join(tmp_dirname, 'foo')

            with smart_open(filename) as fh:
                fh.write(test_data)

            self.assertEqual(test_data, open(filename).read())

    def test_json_for_in_order(self):
        test_data = {"apple": 1, "orange": "two"}
        test_result = (
                        "{\n"
                        "  \"apple\": 1,\n"
                        "  \"orange\": \"two\"\n"
                        "}"
                        )
        self.assertTrue(test_result == json_for(test_data))

    def test_json_for_out_of_order(self):
        test_data = {"orange": "two", "apple": 1}
        test_result = (
                        "{\n"
                        "  \"apple\": 1,\n"
                        "  \"orange\": \"two\"\n"
                        "}"
                        )
        self.assertTrue(test_result == json_for(test_data))

    def test_format_last_exception(self):
        try:
            raise Exception("Oh no!")
        except:
            self.assertTrue(format_last_exception().split("\n")[5] == "Exception: Oh no!")

    def test_format_datetime_date(self):
        test_data = datetime.date(2011, 10, 12)
        self.assertTrue(format_datetime(test_data) == "2011-10-12")

    def test_format_datetime_str(self):
        test_data = "2011-10-12"
        self.assertTrue(format_datetime(test_data) == test_data)
