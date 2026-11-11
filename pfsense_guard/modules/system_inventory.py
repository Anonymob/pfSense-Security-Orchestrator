from __future__ import annotations

from ..models import Finding


class SystemInventoryModule:
    name = "system_inventory"

    def run(self, ssh, report) -> list[Finding]:
        for command, label, key in [
            ("cat /etc/version", "pfSense version", "firmware_version_raw"),
            ("uname -a", "Kernel and platform", "kernel"),
            ("pkg info -x 'php[0-9]*'", "Installed PHP packages", "php_packages"),
            ("pkg info -x 'pfSense-pkg-WireGuard'", "WireGuard package inventory", "wireguard_package"),
            ("pkg info -x 'sshguard'", "SSHGuard package inventory", "sshguard_package"),
        ]:
            try:
                result = ssh.run_readonly(command, label=label)
                report.inventory[key] = result.stdout or result.stderr or f"command exited {result.exit_code}"
            except Exception as exc:
                report.errors.append(f"{label}: {exc}")

        report.findings.append(Finding(
            finding_id="INV-001",
            title="System inventory collected",
            severity="INFO",
            status="collected",
            evidence=f"Version file: {report.inventory.get('firmware_version_raw', 'not available')}",
            recommendation="Verify the exact CE/Plus edition and firmware version against Netgate advisories before applying any remediation.",
        ))
        return []
