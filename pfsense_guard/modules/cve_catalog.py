from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding
from ..versioning import at_or_below, below


_CATALOG = Path(__file__).resolve().parents[2] / "data" / "advisories.json"


class CVECatalogModule:
    name = "cve_catalog"

    def __init__(self, edition: str, version: str):
        self.edition = edition
        self.version = version

    def run(self, ssh, report) -> list[Finding]:
        try:
            catalog = json.loads(_CATALOG.read_text(encoding="utf-8"))
        except Exception as exc:
            report.errors.append(f"Unable to load advisory catalogue: {exc}")
            return []

        findings: list[Finding] = []
        for advisory in catalog["advisories"]:
            affected = advisory.get("affected_through", {}).get(self.edition)
            affected_before = advisory.get("affected_before", {}).get(self.edition)
            fixed_from = advisory.get("fixed_from", {}).get(self.edition)
            status = "manual_review_required"
            severity = advisory.get("severity", "INFO")
            evidence = "The vendor source does not provide a safe automatic version comparison for this item."

            if affected:
                try:
                    is_affected = at_or_below(self.version, affected)
                    status = "potentially_affected" if is_affected else "version_above_affected_range"
                    evidence = f"Detected {self.edition} {self.version}; vendor advisory affected-through threshold: {affected}. Patch-package state must still be checked."
                except ValueError:
                    evidence = f"Could not parse detected version '{self.version}'."
            elif affected_before:
                try:
                    is_affected = below(self.version, affected_before)
                    status = "potentially_affected" if is_affected else "version_at_or_above_fixed_release"
                    evidence = f"Detected {self.edition} {self.version}; vendor advisory affects releases before {affected_before}. Patch-package state must still be checked."
                except ValueError:
                    evidence = f"Could not parse detected version '{self.version}'."
            elif fixed_from:
                try:
                    is_affected = below(self.version, fixed_from)
                    status = "potentially_affected" if is_affected else "version_at_or_above_fixed_release"
                    evidence = f"Detected {self.edition} {self.version}; vendor fixed-release threshold: {fixed_from}."
                except ValueError:
                    evidence = f"Could not parse detected version '{self.version}'."

            findings.append(Finding(
                finding_id=advisory["id"],
                title=advisory["title"],
                severity=severity,
                status=status,
                evidence=evidence,
                recommendation=advisory["recommendation"],
                source_url=advisory["source_url"],
                auto_remediation="vendor_update_or_admin_review",
            ))
        return findings
