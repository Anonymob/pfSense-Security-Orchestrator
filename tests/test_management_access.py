import unittest

from pfsense_guard.firewall_rules.management_access import build_management_policy


class ManagementPolicyTests(unittest.TestCase):
    def test_allow_then_deny_and_correct_ports(self):
        rules = build_management_policy("192.168.50.0/24", webgui_port=8443, ssh_port=2222)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0].action, "pass")
        self.assertEqual(rules[1].action, "block")
        self.assertEqual(rules[0].destination_ports, [8443, 2222])

    def test_invalid_network(self):
        with self.assertRaises(ValueError):
            build_management_policy("not-a-subnet")


if __name__ == "__main__":
    unittest.main()
