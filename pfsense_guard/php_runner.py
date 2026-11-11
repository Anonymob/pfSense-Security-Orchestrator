from __future__ import annotations

import json
import secrets
from pathlib import Path

from .ssh_client import PfSenseSSH


_HELPERS = {
    "runtime_info": "runtime_info.php",
    "dashboard_widget_audit": "dashboard_widget_audit.php",
}


class PHPHelperRunner:
    """Uploads and runs only bundled, read-only PHP diagnostics."""

    def __init__(self, ssh: PfSenseSSH) -> None:
        self.ssh = ssh
        self.helper_dir = Path(__file__).parent / "php"

    def run(self, helper_name: str) -> dict:
        if helper_name not in _HELPERS:
            raise ValueError(f"Unknown PHP helper: {helper_name}")
        local_path = self.helper_dir / _HELPERS[helper_name]
        remote_path = f"/tmp/pfso_{secrets.token_hex(8)}.php"
        sftp = self.ssh.open_sftp()
        try:
            sftp.put(str(local_path), remote_path)
            sftp.chmod(remote_path, 0o600)
        finally:
            sftp.close()

        try:
            # The path contains only a fixed prefix and cryptographically random hex.
            result = self.ssh.run_readonly(
                f"php -d display_errors=0 -f {remote_path}",
                label=f"PHP helper: {helper_name}",
                timeout=20,
            )
            if not result.ok:
                raise RuntimeError(result.stderr or result.stdout or "PHP helper failed without diagnostic output.")
            return json.loads(result.stdout)
        finally:
            # Best-effort SFTP cleanup of this transient helper file.
            try:
                cleanup_sftp = self.ssh.open_sftp()
                try:
                    cleanup_sftp.remove(remote_path)
                finally:
                    cleanup_sftp.close()
            except Exception:
                pass
