from __future__ import annotations

import getpass
from pathlib import Path

from .backup import create_encrypted_backup
from .config import TargetConfig, validate_subnet
from .firewall_rules.management_access import build_management_policy
from .orchestrator import Orchestrator
from .nvd_feed import fetch_pfSense_candidates, save_candidate_feed
from .reporter import print_report, write_report
from .ssh_client import PfSenseSSH
from .updates.netgate_php_update import command_plan


def _ask_port() -> int:
    raw = input("SSH port [22]: ").strip() or "22"
    port = int(raw)
    if not 1 <= port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535.")
    return port


def _ask_target() -> TargetConfig | None:
    print("\nType 'exit' at the firewall address prompt to quit.")
    while True:
        host = input("pfSense management IP/hostname: ").strip()
        if host.lower() == "exit":
            return None
        try:
            port = _ask_port()
            username = input("SSH username [admin]: ").strip() or "admin"
            edition = input("pfSense edition (CE/Plus): ").strip().capitalize()
            if edition not in {"Ce", "Plus"}:
                raise ValueError("Edition must be CE or Plus.")
            edition = "CE" if edition == "Ce" else "Plus"
            auth = input("Authentication: (K)ey or (P)assword [K]: ").strip().upper() or "K"
            key_path = None
            password = None
            key_passphrase = None
            if auth == "K":
                key_path = Path(input("SSH private-key path: ").strip()).expanduser()
                if not key_path.is_file():
                    raise ValueError(f"Private key not found: {key_path}")
                passphrase_answer = input("Is this key passphrase-protected? (y/N): ").strip().lower()
                if passphrase_answer == "y":
                    key_passphrase = getpass.getpass("SSH key passphrase: ")
            elif auth == "P":
                password = getpass.getpass("SSH password: ")
            else:
                raise ValueError("Choose K or P for authentication.")
            known_hosts = Path(input("known_hosts file [~/.ssh/known_hosts]: ").strip() or "~/.ssh/known_hosts").expanduser()
            target = TargetConfig(host, port, username, known_hosts, edition, key_path, password, key_passphrase)
            target.validate()
            return target
        except (ValueError, OSError) as exc:
            print(f"[!] {exc}. Please try again or type 'exit' at the address prompt.")


def _confirm_backup(ssh, host: str) -> None:
    answer = input("Create an encrypted config.xml backup before auditing? (Y/n): ").strip().lower()
    if answer == "n":
        print("[!] No backup created. Audit remains read-only.")
        return
    first = getpass.getpass("Backup encryption passphrase (12+ characters): ")
    second = getpass.getpass("Confirm backup passphrase: ")
    if first != second:
        raise ValueError("Backup passphrases did not match.")
    path = create_encrypted_backup(ssh, host, Path("backups"), first)
    print(f"[+] Encrypted backup saved: {path}")


def main() -> int:
    print("=" * 72)
    print(" pfSense Security Orchestrator v0.1.0")
    print(" Modular vulnerability assessment | safe audit-first mode")
    print("=" * 72)
    print("Use only on firewalls you own or are explicitly authorized to administer.")
    print("This release audits and generates plans; it does not edit firewall rules or config.xml.\n")

    while True:
        target = _ask_target()
        if target is None:
            print("Exiting.")
            return 0

        ssh = None
        try:
            ssh = PfSenseSSH(target)
            print(f"\n[*] Connecting to {target.host}:{target.port}...")
            ssh.connect()
            print("[+] SSH connected. Host key was accepted only if already trusted in known_hosts.")

            version_result = ssh.run_readonly("cat /etc/version", label="Read pfSense version")
            detected_version = version_result.stdout.strip()
            if not version_result.ok or not detected_version:
                raise RuntimeError("Could not read /etc/version. Check account permissions and pfSense build.")
            print(f"[+] Firmware version string: {detected_version}")

            _confirm_backup(ssh, target.host)

            management_subnet = input("Management CIDR for a suggested WebGUI/SSH policy (blank to skip): ").strip()
            if management_subnet:
                normalized = validate_subnet(management_subnet)
                webgui_port_raw = input("WebGUI HTTPS port [443]: ").strip() or "443"
                try:
                    webgui_port = int(webgui_port_raw)
                except ValueError as exc:
                    raise ValueError("WebGUI port must be a number between 1 and 65535.") from exc
                policy = build_management_policy(normalized, webgui_port=webgui_port, ssh_port=target.port)
                print("\n--- Proposed management policy (NOT applied) ---")
                for item in policy:
                    print(item.to_dict())
                print("Review interface assignment, current management path, anti-lockout behavior and rule order before implementation.")

            refresh_feed = input("Refresh the NVD pfSense CVE candidate feed? (y/N): ").strip().lower() == "y"
            if refresh_feed:
                api_key = getpass.getpass("NVD API key (press Enter to use public rate limits): ").strip() or None
                try:
                    candidate_data = fetch_pfSense_candidates(api_key=api_key)
                    feed_path = save_candidate_feed(candidate_data)
                    print(f"[+] Retrieved {len(candidate_data['candidates'])} NVD candidates; saved to {feed_path}")
                    print("[!] NVD keyword matches are discovery leads, not confirmed pfSense vulnerabilities.")
                except Exception as feed_error:
                    print(f"[!] NVD feed refresh failed: {feed_error}")

            load_plugins = input("Load installed third-party community audit plugins? (y/N): ").strip().lower() == "y"
            if load_plugins:
                print("[!] Plugins are local Python code. Only enable packages you have reviewed and trust.")

            # Strip the release suffix and feed the numeric release into version matching.
            version = detected_version.split("-", 1)[0].strip()
            report = Orchestrator(ssh, target.host, target.edition, version, enable_community_plugins=load_plugins).run()
            print_report(report)
            report_path = write_report(report)
            print(f"\n[+] JSON report saved: {report_path}")

            print("\nNetgate PHP security update command plans are available for review:")
            print("  Reboot method:")
            for command in command_plan("reboot"):
                print(f"    {command}")
            print("  WebGUI + Captive Portal restart method:")
            for command in command_plan("restart"):
                print(f"    {command}")
            print("  WebGUI-only restart method (only when Captive Portal is not used):")
            for command in command_plan("restart-gui-only"):
                print(f"    {command}")
            print("These are display-only. Review Netgate's current advisory and maintenance impact before running them.")
            return 0

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            return 130
        except Exception as exc:
            print(f"\n[-] {type(exc).__name__}: {exc}")
            retry = input("Connection or audit failed. Retry with another target/credential? (Y/n): ").strip().lower()
            if retry == "n":
                return 1
        finally:
            if ssh is not None:
                ssh.close()


if __name__ == "__main__":
    raise SystemExit(main())
