from __future__ import annotations

from ..models import Finding


class SSHGuardAuditModule:
    name = "sshguard_audit"

    def run(self, ssh, report) -> list[Finding]:
        package = report.inventory.get("sshguard_package", "not collected")
        return [Finding(
            finding_id="SSHGUARD-001",
            title="SSHGuard package inventory recorded",
            severity="INFO",
            status="review_required",
            evidence=package,
            recommendation="CVE-2023-27100 and later SSHGuard advisories are fixed through vendor patches/releases. Do not invent SSHGuard settings or assume a custom login-attempt limit fixes parser bugs. Keep the WebGUI off untrusted networks and verify the installed pfSense release and System Patches status.",
            source_url="https://docs.netgate.com/downloads/pfSense-SA-23_05.sshguard.asc",
        )]
