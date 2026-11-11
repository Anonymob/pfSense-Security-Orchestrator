# pfSense Security Orchestrator

**Version 0.1.0 - research prototype / audit-first foundation**

A modular Python framework for assessing pfSense exposure, recording evidence, generating management-firewall policy plans, and mapping vendor advisories to installed firmware versions.

> This is not a universal CVE fixer and is not yet a production-certified appliance-management product. The initial release does not persistently change firewall configuration. It downloads an optional encrypted configuration backup and uploads/removes transient read-only PHP diagnostics. It does not edit `config.xml`, change firewall rules, change sysctls, upgrade packages, restart services, or reboot a firewall.

## Why audit-first?

A firewall is a high-impact control plane. A bad rule can lock out administrators or expose services; an incorrect XML edit can break service generation. Netgate warns that direct configuration editing can have unintended consequences and recommends backups. This project therefore separates **assessment**, **policy planning**, and **remediation execution**. Write-capable adapters must be reviewed and tested independently before they are enabled.

## Features in this foundation

- Interactive retry loop with an explicit `exit` path.
- Configurable SSH port and username.
- SSH private-key authentication or hidden password input.
- Strict SSH host-key checking using `known_hosts`; unknown keys are rejected.
- Optional encrypted local backup of `/conf/config.xml` using PBKDF2-HMAC-SHA256 and Fernet; files are created with owner-only permissions.
- Modular audit pipeline: system inventory, PHP runtime, dashboard widget metadata, selected DoS-related sysctls, SSHGuard package inventory, and vendor-advisory mapping.
- Separate declarative management-access policy module. It prints an allow-then-deny plan and never applies it.
- Bundled PHP helpers are read-only diagnostics. Python uploads them over SFTP, calls PHP CLI, parses JSON, and removes the temporary helper.
- Optional NVD keyword-feed refresh. Results are stored as **unreviewed candidates**, not automatically trusted or treated as confirmed pfSense vulnerabilities.
- Opt-in Python entry-point plugin system (`pfsense_guard.modules`) for community audit modules.
- Bounded multi-target runner helper (1-10 workers, default 3) for a future fleet CLI; the current interactive CLI remains single-firewall.
- JSON reports suitable for later comparison and research analysis.
- Unit tests for version matching, firewall policy planning, advisory mapping, encrypted backups, plugin registration, command allowlisting and multi-target scheduling.

## Requirements

- Python 3.11+
- SSH access to a pfSense lab device/account with permission to read `/conf/config.xml` for backups and run the read-only inventory commands.
- PHP CLI available on the pfSense target for the optional bundled PHP checks.
- A trusted host key already present in `~/.ssh/known_hosts` (or a separately supplied file).

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Run:

```bash
python main.py
```

The tool asks for the target address, SSH port, edition, authentication method, and known-hosts file. It asks whether to save an encrypted backup and optionally asks for a management CIDR to generate a policy plan.

## SSH host-key enrollment

Do **not** automatically trust a key merely because `ssh-keyscan` returned it. Obtain the SSH host-key fingerprint from the pfSense console or another trusted channel, compare it, and only then add the key to your `known_hosts` file. A common workflow is:

```bash
ssh-keyscan -p 22 FIREWALL_IP > /tmp/pfsense_known_hosts
ssh-keygen -lf /tmp/pfsense_known_hosts
# Compare the fingerprint out-of-band before appending it:
cat /tmp/pfsense_known_hosts >> ~/.ssh/known_hosts
```

Replace the port if your appliance uses a non-default SSH port. `ssh-keyscan` alone does not authenticate the device.

## Architecture

```text
main.py
  └── cli.py
       ├── ssh_client.py             #strict Paramiko transport
       ├── backup.py                 #encrypted config backup
       ├── orchestrator.py           #ordered module runner
       ├── plugin_registry.py        #opt-in community entry points
       ├── multi_target.py           #bounded fleet runner helper
       ├── nvd_feed.py               #unreviewed NVD candidate import
       │    ├── modules/system_inventory.py
       │    ├── modules/php_runtime.py
       │    ├── modules/dashboard_audit.py
       │    ├── modules/dos_audit.py
       │    ├── modules/sshguard_audit.py
       │    └── modules/cve_catalog.py
       ├── firewall_rules/management_access.py  #rules kept separate
       ├── php_runner.py             #Python -> bundled PHP diagnostics
       └── reporter.py               #JSON evidence report

data/advisories.json               # versioned starter advisory catalogue
pfsense_guard/updates/*.py           #vendor command plans; display-only
```

## PHP versus Python

Python owns orchestration, connection management, policy, version matching, tests, reporting and community plugin loading. PHP is included only as a narrow pfSense-side diagnostics bridge in this first release. The PHP helpers do not change configuration. Do not use arbitrary uploaded PHP to rewrite `config.xml` or firewall rules.

The documented pfSense developer shell is `pfSsh.php`. Netgate documents it as an advanced way to manipulate firewall configuration, and warns that playback scripts have execution constraints. The earlier Gemini sample's use of `pfSense-developer.php` is not the documented entry point. See the official PHP shell documentation before adding a write-capable helper.

A community REST API package exists, but it is not affiliated with or supported by Netgate; it also has pfSense-version and architecture compatibility constraints and can be removed during upgrades. Keep it behind an optional adapter, never assume it is part of pfSense itself.

## Current advisory catalogue

The starter catalogue includes:

- CVE-2026-109618 and CVE-2026-109619: PHP package security updates. Netgate's October 21, 2026 instructions use a command-line package update sequence and include WireGuard package handling plus service restart or reboot options. The engine prints those commands for review; it does not execute them.
- CVE-2026-97730: dashboard widget-sequence LFI/path traversal. Apply the vendor patch/fixed release and restrict dashboard modification to trusted administrators.
- CVE-2026-38961: RSS widget stored XSS. Remove untrusted feeds or the RSS widget until patched; retain unrelated widgets.
- CVE-2026-92182: XML-RPC privilege-check issue with remote LDAP/RADIUS authentication. Review local-account matching and the vendor System Patches guidance.
- CVE-2023-27100: historical SSHGuard brute-force protection bypass, fixed in newer pfSense releases.
- pfSense-SA-25_09.sshguard: later SSHGuard/WebGUI parsing advisory. Netgate states this affects WebGUI login methods, not SSH logins.

The catalogue is deliberately curated and conservative. Version-range matching does not prove that a recommended patch is or is not installed. Patch-package state, edition and branch must be checked against the live vendor advisory. The PHP CVEs in particular are package-level and should not be treated as fully resolved based only on a firmware version string.

## Netgate PHP update command plans

For the October 2026 PHP vulnerabilities, Netgate publishes the following options. The programme prints them as a reference only:

**Best-practice package update and reboot:**

```sh
pfSense-upgrade -c && \
pkg upgrade -y && \
pkg upgrade -fy pfSense-pkg-WireGuard && \
/etc/rc.reboot
```

**Update packages and restart PHP/WebGUI/Captive Portal services:**

```sh
pfSense-upgrade -c && \
pkg upgrade -y && \
pkg upgrade -fy pfSense-pkg-WireGuard && \
/etc/rc.php-fpm_restart && \
/etc/rc.restart_webgui && \
/etc/rc.captiveportal_configure
```

Netgate also documents a WebGUI-only restart option when Captive Portal is not used. The code retains that exact command plan as well. Netgate notes that updating over a WireGuard connection is likely to interrupt connectivity. Review the live instructions, backup, maintenance window, installed packages, and connection path before executing any method.

## Firewall policy generation

`firewall_rules/management_access.py` emits a conceptual allow rule for the supplied management CIDR followed by a block rule for other sources to the WebGUI/SSH ports. **It is not a pfSense ruleset export and it is not automatically applied.** Actual implementation must account for the interface where the rules attach, port changes, IPv4/IPv6, aliases, anti-lockout behavior, CARP/HA, VPN paths and rule order. Netgate recommends using a management-network alias and preserving an allow rule before a deny rule.

## Community plugins

Third-party Python packages may register audit modules in the `pfsense_guard.modules` entry-point group. Each module must expose a unique `name` and implement `run(ssh, report) -> list[Finding]`. The CLI asks before loading installed plugins because importing third-party modules executes local Python code. Only install and enable plugins whose source you have reviewed.

Example entry point in a contributor's `pyproject.toml`:

```toml
[project.entry-points."pfsense_guard.modules"]
my_webgui_audit = "my_pfsense_plugin.audit:MyWebGUIAudit"
```

The interface is deliberately audit-only in v0.1. Write-capable remediation modules need a separate reviewed contract, policy-diff, confirmation, rollback and post-change verification.

## Multi-firewall execution

`pfsense_guard/multi_target.py` includes a bounded `ThreadPoolExecutor` helper with a maximum of 10 workers and duplicate-target rejection. It is not yet wired into the single-target CLI. Before enabling fleet changes, add per-target locks, rate limits, per-device rollback, partial-failure reporting and a lab-tested target inventory format. Do not run concurrent write operations against one appliance.

## Testing

```bash
python -m unittest discover -s tests -v
```

The tests do not connect to a firewall. They validate local parsing, version matching, policy-plan generation, encryption round-trips, command filtering, plugin registration and bounded scheduling. Hardware/lab integration tests are still required.

## Roadmap

1. Add adapters for a specifically pinned and tested pfSense CE/Plus version matrix.
2. Implement XML/config inspection with schema-aware parsing and signed evidence output.
3. Add CVE feeds (NVD API plus Netgate advisories) with caching, source timestamps and affected-version/patch verification.
4. Implement a policy-diff and rollback engine before any write operation.
5. Add a separately enabled firewall-rule adapter with pre-change lockout checks and a management-path verification step.
6. Add update execution profiles that follow live Netgate instructions, require backup, maintenance-window acknowledgement and typed target confirmation.
7. Add bounded multi-firewall workers, per-target locks, retry/backoff and job-level audit logs.
8. Add CI, static analysis, dependency scanning, signed releases and a contributor review process.

## Research framing

The defensible research contribution is not that this is the only script that fixes most CVEs. It is the combination of (1) vendor-advisory correlation, (2) configuration/attack-surface assessment, (3) safe remediation planning, (4) controlled execution with backups and approvals, and (5) post-remediation verification with evidence. Measure precision, coverage, false positives, rollback success, recovery time, and performance in the isolated lab.
