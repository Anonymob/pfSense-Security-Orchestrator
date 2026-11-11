from __future__ import annotations

from ..models import Finding
from ..php_runner import PHPHelperRunner


class DashboardAuditModule:
    name = "dashboard_audit"

    def run(self, ssh, report) -> list[Finding]:
        try:
            data = PHPHelperRunner(ssh).run("dashboard_widget_audit")
        except Exception as exc:
            report.errors.append(f"Dashboard widget audit: {exc}")
            return []

        report.inventory["dashboard_widget_audit"] = str(data)
        findings: list[Finding] = []
        if data.get("rss_reference_detected"):
            findings.append(Finding(
                finding_id="CVE-2026-38961-COMPENSATING-CONTROL",
                title="RSS dashboard widget reference detected",
                severity="MEDIUM",
                status="review_required",
                evidence="The read-only config scan found an RSS-related reference under the dashboard widgets section. This is not proof of exploitability or of an affected firmware version.",
                recommendation="Until the vendor patch is confirmed, remove untrusted feeds or remove the RSS widget. Do not delete the entire widgets configuration.",
                source_url="https://docs.netgate.com/downloads/pfSense-SA-26_04.webgui.asc",
            ))
        if data.get("widget_sequence_present"):
            findings.append(Finding(
                finding_id="CVE-2026-97730-COMPENSATING-CONTROL",
                title="Dashboard widget sequence configuration exists",
                severity="INFO",
                status="review_required",
                evidence="A widget sequence field exists. Its presence alone does not prove that the LFI vulnerability is exploitable.",
                recommendation="Restrict dashboard configuration privileges to trusted administrators and verify the official System Patches fix or a fixed firmware release.",
                source_url="https://docs.netgate.com/downloads/pfSense-SA-26_18.webgui.asc",
            ))
        return findings
