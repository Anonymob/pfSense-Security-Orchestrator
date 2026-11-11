from __future__ import annotations

from ..models import Finding


class DOSBaselineAuditModule:
    name = "dos_baseline_audit"
    _TUNABLES = (
        "net.inet.tcp.syncookies",
        "net.inet.icmp.icmplim",
        "net.inet.ip.sourceroute",
        "net.inet.icmp.drop_redirect",
        "kern.randompid",
    )

    def run(self, ssh, report) -> list[Finding]:
        observed: dict[str, str] = {}
        for tunable in self._TUNABLES:
            try:
                result = ssh.run_readonly(f"sysctl {tunable}", label=f"Read sysctl {tunable}")
                observed[tunable] = result.stdout if result.ok else (result.stderr or "not available on this build")
            except Exception as exc:
                observed[tunable] = f"audit error: {exc}"
        report.inventory["sysctl_observations"] = str(observed)
        return [Finding(
            finding_id="DOS-BASELINE-001",
            title="DoS-related sysctl values collected (read-only)",
            severity="INFO",
            status="observed",
            evidence=str(observed),
            recommendation="Do not blindly set kernel tunables. Validate each parameter against the exact pfSense/FreeBSD release and test its impact. Kernel tunables alone do not mitigate upstream volumetric DDoS; use upstream filtering/scrubbing and validated traffic-shaping/state policies.",
            source_url="https://docs.netgate.com/pfsense/en/latest/",
        )]
