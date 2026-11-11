from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$|^[0-9a-fA-F:%.]+$")


@dataclass(slots=True)
class TargetConfig:
    host: str
    port: int
    username: str
    known_hosts: Path
    edition: str
    key_path: Path | None = None
    password: str | None = field(default=None, repr=False)
    key_passphrase: str | None = field(default=None, repr=False)

    def validate(self) -> None:
        if not self.host or not _HOST_RE.fullmatch(self.host):
            raise ValueError("Enter a valid IP address or hostname.")
        if not 1 <= self.port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535.")
        if not self.username or any(ch.isspace() for ch in self.username):
            raise ValueError("SSH username must be non-empty and contain no spaces.")
        if self.edition not in {"CE", "Plus"}:
            raise ValueError("Edition must be CE or Plus.")
        if self.key_path is None and self.password is None:
            raise ValueError("Provide either an SSH key or a password.")
        if self.key_path is not None and not self.key_path.expanduser().is_file():
            raise ValueError(f"SSH private key not found: {self.key_path}")


def validate_subnet(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValueError("Enter a valid management CIDR, e.g. 192.168.1.0/24.") from exc
