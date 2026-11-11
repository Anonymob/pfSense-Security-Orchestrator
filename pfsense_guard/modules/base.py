from __future__ import annotations

from typing import Protocol

from ..models import Finding


class AuditModule(Protocol):
    """Contract for built-in and community audit modules.

    Modules must be read-only in v0.1 and return structured findings. A future
    write-capable module must use a separate reviewed interface.
    """

    name: str

    def run(self, ssh, report) -> list[Finding]: ...
