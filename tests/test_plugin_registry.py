import unittest

from pfsense_guard.plugin_registry import ModuleRegistry


class FakeModule:
    name = "fake"

    def run(self, ssh, report):
        return []


class PluginRegistryTests(unittest.TestCase):
    def test_register_and_reject_duplicates(self):
        registry = ModuleRegistry()
        registry.register(FakeModule())
        with self.assertRaises(ValueError):
            registry.register(FakeModule())

    def test_disabled_plugins_do_not_load(self):
        registry = ModuleRegistry()
        self.assertEqual(registry.load_community_plugins(enabled=False), [])


if __name__ == "__main__":
    unittest.main()
