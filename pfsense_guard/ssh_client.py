from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from .config import TargetConfig
from .models import CommandResult


class PfSenseSSH:
    """Small SSH adapter. Unknown host keys are rejected, never auto-accepted."""

    def __init__(self, target: TargetConfig) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:  # pragma: no cover - exercised on minimal installs
            raise RuntimeError("Paramiko is required. Install dependencies with: pip install -r requirements.txt") from exc

        self._paramiko: Any = paramiko
        self.target = target
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        known_hosts = Path(target.known_hosts).expanduser()
        if known_hosts.exists():
            self.client.load_host_keys(str(known_hosts))
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.connected = False

    def connect(self) -> None:
        kwargs: dict[str, Any] = {
            "hostname": self.target.host,
            "port": self.target.port,
            "username": self.target.username,
            "timeout": 12,
            "banner_timeout": 12,
            "auth_timeout": 15,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.target.key_path:
            kwargs["key_filename"] = str(self.target.key_path.expanduser())
            if self.target.key_passphrase:
                kwargs["passphrase"] = self.target.key_passphrase
        else:
            kwargs["password"] = self.target.password
        self.client.connect(**kwargs)
        self.connected = True

    @staticmethod
    def is_allowed_readonly_command(command: str) -> bool:
        exact = {
            "cat /etc/version",
            "uname -a",
            "pkg info -x 'php[0-9]*'",
            "pkg info -x 'pfSense-pkg-WireGuard'",
            "pkg info -x 'sshguard'",
        }
        return (
            command in exact
            or re.fullmatch(r"sysctl [A-Za-z0-9_.]+", command) is not None
            or re.fullmatch(r"php -d display_errors=0 -f /tmp/pfso_[a-f0-9]{16}\.php", command) is not None
        )

    def run_readonly(self, command: str, label: str, timeout: int = 20) -> CommandResult:
        """Run an allowlisted read-only command; arbitrary remote shell text is rejected."""
        if not self.is_allowed_readonly_command(command):
            raise ValueError(f"Command is not in the read-only allowlist: {label}")
        if not self.connected:
            raise RuntimeError("SSH session is not connected.")
        _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout, get_pty=False)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        code = stdout.channel.recv_exit_status()
        return CommandResult(command_label=label, stdout=out, stderr=err, exit_code=code)

    def open_sftp(self):
        if not self.connected:
            raise RuntimeError("SSH session is not connected.")
        return self.client.open_sftp()

    def close(self) -> None:
        try:
            self.client.close()
        finally:
            self.connected = False
