import unittest

from pfsense_guard.versioning import at_or_below, below, version_tuple


class VersionTests(unittest.TestCase):
    def test_release_suffix(self):
        self.assertEqual(version_tuple("2.8.1-RELEASE"), (2, 8, 1))

    def test_dotted_comparison(self):
        self.assertTrue(at_or_below("2.8.1", "2.8.1"))
        self.assertTrue(below("2.8.1", "2.9.0"))
        self.assertFalse(at_or_below("26.07", "26.03.1"))

    def test_bad_version(self):
        with self.assertRaises(ValueError):
            version_tuple("unknown")


if __name__ == "__main__":
    unittest.main()
