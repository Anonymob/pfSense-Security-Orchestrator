import unittest

from pfsense_guard.backup import decrypt_backup, encrypt_backup


SAMPLE = b"<?xml version='1.0'?><pfsense><version>2.8.1</version></pfsense>"


class BackupTests(unittest.TestCase):
    def test_encrypted_round_trip(self):
        encrypted = encrypt_backup(SAMPLE, "correct horse battery staple")
        self.assertNotIn(b"pfsense", encrypted.lower())
        self.assertEqual(decrypt_backup(encrypted, "correct horse battery staple"), SAMPLE)

    def test_wrong_password_fails(self):
        encrypted = encrypt_backup(SAMPLE, "correct horse battery staple")
        with self.assertRaises(Exception):
            decrypt_backup(encrypted, "wrong horse battery staple")

    def test_invalid_xml_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_backup(b"<bad", "correct horse battery staple")


if __name__ == "__main__":
    unittest.main()
