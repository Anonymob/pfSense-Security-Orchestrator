# Initial pfSense advisory review

Research snapshot: 2026-11-03. This is a starter list, not a complete CVE inventory. Review live vendor advisories before acting.

## Verified items represented in the starter catalogue

| ID | Affected component / condition | Official guidance / implementation status |
|---|---|---|
| CVE-2026-109618 | PHP runtime used by pfSense WebGUI/Captive Portal | Netgate published command-line package update sequences on 2026-10-21. Risk depends on exposure of the PHP GUI or Captive Portal to untrusted clients. Plans are displayed, not executed. |
| CVE-2026-109619 | PHP runtime used by pfSense WebGUI/Captive Portal | Same Netgate PHP security update guidance; package status needs direct verification. |
| CVE-2026-97730 | Dashboard widget sequence LFI/path traversal | Netgate says limit affected dashboard-page access to trusted administrators; use System Patches or a fixed release. No wholesale widget deletion. |
| CVE-2026-38961 | RSS dashboard widget stored XSS | Workaround: remove untrusted RSS feeds or remove the RSS widget. Use vendor patch/fixed release. |
| CVE-2026-92182 | XML-RPC privilege checking when system remote authentication uses LDAP/RADIUS | Review local-account matching and branch-specific System Patches guidance. Manual-review finding only. |
| CVE-2023-27100 | Historical SSHGuard brute-force protection bypass | Fixed in Plus 23.01+ and CE 2.7.0+. Affects old releases; restrict WebGUI exposure. |
| pfSense-SA-25_09.sshguard | Later SSHGuard/WebGUI parsing bypass and log manipulation | Fixed in Plus 25.11+ and CE 2.9.0+. Netgate says the issue affects WebGUI login methods, not SSH logins. |

## Version interpretation caveat

The catalogue uses advisory-published affected-through / fixed-from values only where the vendor source supports a straightforward comparison. It does not automatically clear a CVE when a device's release string is above a threshold if the vendor also requires a System Patches package or branch-specific check. CVE-2026-92182 and the PHP package CVEs are intentionally kept in manual-review states.

## Not yet covered

The full Netgate security-advisory index contains many additional WebGUI, package, kernel, SSHGuard and service advisories. The next research pass should ingest the complete index, classify affected release/package conditions, and add only items with authoritative source links and testable detection logic. NVD keyword-search results are leads, not a substitute for vendor advisories.
