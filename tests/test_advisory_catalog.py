import json
import unittest
from pathlib import Path

from pfsense_guard.modules.cve_catalog import CVECatalogModule
from pfsense_guard.models import AuditReport


class DummySSH:
    pass


class AdvisoryTests(unittest.TestCase):
    def test_catalog_contains_core_items_and_new_xmlrpc_issue(self):
        path = Path(__file__).resolve().parents[1] / "data" / "advisories.json"
        catalog = json.loads(path.read_text())
        ids = {item["id"] for item in catalog["advisories"]}
        self.assertTrue({"CVE-2026-97730", "CVE-2026-38961", "CVE-2026-92182", "CVE-2023-27100"}.issubset(ids))

    def test_old_ce_release_flagged_for_lfi(self):
        report = AuditReport("lab-fw", "CE", "2.8.1")
        findings = CVECatalogModule("CE", "2.8.1").run(DummySSH(), report)
        lfi = next(item for item in findings if item.finding_id == "CVE-2026-97730")
        self.assertEqual(lfi.status, "potentially_affected")

    def test_newer_ce_release_above_lfi_range(self):
        report = AuditReport("lab-fw", "CE", "2.9.0")
        findings = CVECatalogModule("CE", "2.9.0").run(DummySSH(), report)
        lfi = next(item for item in findings if item.finding_id == "CVE-2026-97730")
        self.assertEqual(lfi.status, "version_above_affected_range")

    def test_plus_release_before_2607_is_affected_by_lfi(self):
        report = AuditReport("lab-fw", "Plus", "26.05")
        findings = CVECatalogModule("Plus", "26.05").run(DummySSH(), report)
        lfi = next(item for item in findings if item.finding_id == "CVE-2026-97730")
        self.assertEqual(lfi.status, "potentially_affected")

    def test_plus_2607_is_not_in_lfi_affected_before_range(self):
        report = AuditReport("lab-fw", "Plus", "26.07")
        findings = CVECatalogModule("Plus", "26.07").run(DummySSH(), report)
        lfi = next(item for item in findings if item.finding_id == "CVE-2026-97730")
        self.assertEqual(lfi.status, "version_at_or_above_fixed_release")


if __name__ == "__main__":
    unittest.main()
