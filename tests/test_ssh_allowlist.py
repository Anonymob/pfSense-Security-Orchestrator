import unittest

from pfsense_guard.ssh_client import PfSenseSSH


class SSHAllowlistTests(unittest.TestCase):
    def test_fixed_commands_allowed(self):
        self.assertTrue(PfSenseSSH.is_allowed_readonly_command("cat /etc/version"))
        self.assertTrue(PfSenseSSH.is_allowed_readonly_command("sysctl net.inet.tcp.syncookies"))
        self.assertTrue(PfSenseSSH.is_allowed_readonly_command("php -d display_errors=0 -f /tmp/pfso_0123456789abcdef.php"))

    def test_arbitrary_commands_rejected(self):
        self.assertFalse(PfSenseSSH.is_allowed_readonly_command("reboot"))
        self.assertFalse(PfSenseSSH.is_allowed_readonly_command("cat /etc/version; rm -rf /"))


if __name__ == "__main__":
    unittest.main()
