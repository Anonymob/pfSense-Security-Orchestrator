# Review of the Gemini conversation and final V3 proposals

This document records how the suggestions in the last section of the supplied Gemini conversation are carried into this repository.

| Original suggestion | Project treatment | Reason / guardrail |
|---|---|---|
| SSH port input | Implemented | Port is configurable and range-validated. |
| SSH key path / RSA / Ed25519 | Implemented | Paramiko loads the selected private key; encrypted-key passphrase is supported. |
| Password authentication | Implemented | Password is entered through `getpass`; it is not written into reports. |
| Configuration backup toggle | Implemented | Optional SFTP download of `/conf/config.xml`; encrypted locally; timestamped; owner-only permissions. |
| Idempotency | Foundation implemented | Default workflow is read-only; policy plans are deterministic. Write-capable remediation still needs change detection and rollback tests. |
| Concurrency | Helper implemented, fleet CLI deferred | `MultiTargetRunner` is bounded to at most 10 workers and rejects duplicate target/port pairs. Fleet writes are not enabled. |
| Attack-vector modules | Implemented | Modules are separated by inventory, PHP, dashboard, DoS, SSHGuard and CVE catalogue. |
| WebGUI management IP allowlisting | Plan-only | Generates an ordered allow/deny policy. Actual pfSense rule application requires interface, alias, anti-lockout and management-path reconciliation. |
| SSHGuard hardening | Audit/recommendation only | The cited bypasses are parser / log handling defects fixed by vendor updates; arbitrary SSHGuard tuning is not a reliable fix. |
| CVE feed | Implemented as discovery | Optional NVD query caches unreviewed candidate CVEs; a human must map each to the official Netgate advisory and affected package/release. |
| Retry loop and exit option | Implemented | Failed connection/audit can be retried; `exit` is available at the target prompt. |

## Proposals deliberately not copied literally

### Dashboard configuration surgery

The original code removes the complete `widgets` configuration. Netgate's LFI advisory recommends limiting access to affected dashboard pages to trusted administrators and installing the official patch/fixed release. The RSS XSS advisory says to remove untrusted feeds or the RSS widget as a workaround. Deleting all widgets is broader than the documented workaround and can remove unrelated dashboard state.

### PHP package names

The original script tries `php85 php84 php83 php82` in one command. Netgate's October 21, 2026 instructions instead publish a package-manager sequence that updates all binary packages, reinstalls the WireGuard package, and then either reboots or restarts the relevant PHP/WebGUI/Captive Portal services. The repository stores those vendor command plans for administrator review; it does not auto-run them.

### Developer shell invocation

The supplied script calls `pfSense-developer.php`. Netgate's documentation identifies the PHP developer shell command as `pfSsh.php`. The project therefore does not depend on the unsupported-looking executable name or pipe arbitrary PHP into the shell. Bundled PHP files are ordinary read-only CLI diagnostics; write-capable PHP shell scripts are deferred until a specific supported workflow and rollback procedure are proven.

### SSHGuard and CVE-2023-27100

CVE-2023-27100 is a real historical SSHGuard anti-brute-force bypass affecting pfSense Plus 22.05.1 and CE 2.6.0. Netgate's advisory says it was fixed in Plus 23.01 or later and CE 2.7.0 or later. A later Netgate SSHGuard advisory (SA-25_09) says its parsing issue affects WebGUI login methods, not SSH logins. Key-only SSH access is useful account hygiene, but it does not fix a WebGUI log parser vulnerability.

### CVE-2026-92182

The original conversation did not include this later Netgate advisory. It concerns XML-RPC privilege checks when remote LDAP/RADIUS authentication is used without matching local accounts. The project flags it for manual review rather than automatically classifying it from a version number because the advisory's branch-specific patch guidance should be checked against the appliance's actual System Patches state.

## Research standard

Each module must distinguish: (1) vulnerability detection, (2) compensating control, (3) vendor patch availability, (4) patch installation, and (5) post-remediation verification. These are not interchangeable states.
