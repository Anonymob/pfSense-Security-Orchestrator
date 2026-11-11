from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class CommandResult:
    command_label: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    status: str
    evidence: str
    recommendation: str
    source_url: str | None = None
    auto_remediation: str = "not_implemented"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditReport:
    target: str
    edition: str
    version: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    inventory: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "tool": "pfSense Security Orchestrator",
            "target": self.target,
            "edition": self.edition,
            "version": self.version,
            "started_at": self.started_at,
            "findings": [item.to_dict() for item in self.findings],
            "inventory": self.inventory,
            "errors": self.errors,
        }
