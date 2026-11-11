import unittest

from pfsense_guard.config import TargetConfig
from pfsense_guard.multi_target import MultiTargetRunner
from pathlib import Path


def target(host):
    return TargetConfig(host, 22, "admin", Path("known_hosts"), "CE", key_path=Path("key"))


class MultiTargetTests(unittest.TestCase):
    def test_duplicate_target_rejected(self):
        runner = MultiTargetRunner(max_workers=2)
        with self.assertRaises(ValueError):
            runner.run([target("fw1"), target("fw1")], lambda item: item.host)

    def test_bounded_runner_collects_results(self):
        runner = MultiTargetRunner(max_workers=2)
        result = runner.run([target("fw1"), target("fw2")], lambda item: item.host.upper())
        self.assertEqual(result["fw1:22"], "FW1")
        self.assertEqual(result["fw2:22"], "FW2")


if __name__ == "__main__":
    unittest.main()
