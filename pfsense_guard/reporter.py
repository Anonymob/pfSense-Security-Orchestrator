from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import AuditReport


def write_report(report: AuditReport, destination: Path = Path("reports")) -> Path:
    destination = destination.expanduser()
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(destination, 0o700)
    except OSError:
        pass
    safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", report.target)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    path = destination / f"{safe_target}_{stamp}.json"
    data = json.dumps(report.to_dict(), indent=2, sort_keys=True).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def print_report(report: AuditReport) -> None:
    print("\n=== pfSense Security Orchestrator: Audit Summary ===")
    print(f"Target: {report.target} | Edition: {report.edition} | Version: {report.version}")
    print(f"Findings: {len(report.findings)} | Errors: {len(report.errors)}")
    for finding in report.findings:
        print(f"\n[{finding.severity}] {finding.finding_id}: {finding.title}")
        print(f"Status: {finding.status}")
        print(f"Evidence: {finding.evidence}")
        print(f"Recommendation: {finding.recommendation}")
    if report.errors:
        print("\nAudit errors:")
        for error in report.errors:
            print(f" - {error}")
