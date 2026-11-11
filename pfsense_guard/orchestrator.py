from __future__ import annotations

from .models import AuditReport
from .modules.cve_catalog import CVECatalogModule
from .modules.dashboard_audit import DashboardAuditModule
from .modules.dos_audit import DOSBaselineAuditModule
from .modules.php_runtime import PHPRuntimeModule
from .modules.sshguard_audit import SSHGuardAuditModule
from .modules.system_inventory import SystemInventoryModule
from .plugin_registry import ModuleRegistry


class Orchestrator:
    """Runs registered audit modules in order against one connected firewall."""

    def __init__(self, ssh, target: str, edition: str, version: str, enable_community_plugins: bool = False):
        self.ssh = ssh
        self.report = AuditReport(target=target, edition=edition, version=version)
        self.registry = ModuleRegistry()
        for module in (
            SystemInventoryModule(),
            PHPRuntimeModule(),
            DashboardAuditModule(),
            DOSBaselineAuditModule(),
            SSHGuardAuditModule(),
            CVECatalogModule(edition=edition, version=version),
        ):
            self.registry.register(module)
        try:
            loaded = self.registry.load_community_plugins(enabled=enable_community_plugins)
            if loaded:
                self.report.inventory["community_plugins_loaded"] = ", ".join(loaded)
        except Exception as exc:
            self.report.errors.append(f"Community plugin loading failed: {exc}")

    def run(self) -> AuditReport:
        for module in self.registry.modules:
            try:
                self.report.findings.extend(module.run(self.ssh, self.report))
            except Exception as exc:
                self.report.errors.append(f"Module {module.name} failed: {exc}")
        return self.report
