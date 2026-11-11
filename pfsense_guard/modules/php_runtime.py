from __future__ import annotations

from ..models import Finding
from ..php_runner import PHPHelperRunner


class PHPRuntimeModule:
    name = "php_runtime"

    def run(self, ssh, report) -> list[Finding]:
        try:
            data = PHPHelperRunner(ssh).run("runtime_info")
            report.inventory["php_runtime"] = str(data.get("php_version", "unknown"))
            report.inventory["php_sapi"] = str(data.get("sapi", "unknown"))
            return [Finding(
                finding_id="PHP-RUNTIME-001",
                title="PHP CLI runtime version observed",
                severity="INFO",
                status="observed",
                evidence=f"PHP {data.get('php_version', 'unknown')} ({data.get('sapi', 'unknown')})",
                recommendation="Compare the installed PHP package with Netgate's current PHP security update guidance. A CLI version read alone is not proof that all GUI/Captive Portal workers are patched.",
                source_url="https://www.netgate.com/blog/critical-php-security-update",
            )]
        except Exception as exc:
            report.errors.append(f"PHP runtime audit: {exc}")
            return []
