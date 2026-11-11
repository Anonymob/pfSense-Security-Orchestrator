# Research and validation method

## Research question

Can a modular, advisory-aware orchestration tool reduce the time and operational error involved in identifying and safely remediating pfSense security weaknesses in an isolated lab?

## Evaluation dimensions

- **Advisory coverage:** proportion of selected vendor advisories represented in the local catalogue.
- **Detection precision:** proportion of reported potentially affected devices that are confirmed affected after vendor and package-state review.
- **Detection recall:** proportion of known affected lab snapshots identified by the framework.
- **Remediation success:** proportion of approved remediations that reach the vendor-documented fixed state.
- **Regression rate:** proportion of remediations that break routing, firewall rules, DNS, VPN, Captive Portal, HA/CARP or WebGUI access.
- **Rollback success:** proportion of test changes restored to the exact pre-change baseline.
- **Operational time:** time for inventory, backup, audit, remediation and verification separately.
- **Resource impact:** CPU, memory, state-table usage, packet loss and latency during controlled lab tests.

## Lab controls

Use isolated virtual networks with a pfSense firewall, an attacker VM, and a victim VM. Snapshot the firewall before each experiment. Record the exact pfSense edition, release, package list, enabled services, interface mapping and relevant rules. Do not test flood traffic or exploit payloads against production or public networks.

## Experimental sequence

1. Capture a baseline configuration and metrics.
2. Run read-only inventory and advisory assessment.
3. Independently confirm each finding against the Netgate advisory and package/release state.
4. Apply one vendor-documented remediation at a time, with an approved backup and rollback path.
5. Re-run the audit and benign connectivity tests.
6. Record false positives, false negatives, lockout risk, downtime and restore outcome.
7. Repeat across supported pfSense releases and different network topologies.

## Important research distinction

A CVE is not considered remediated because a command was sent or returned exit code zero. The project must verify the patched package/release, relevant service restart state, and functional connectivity after the change.
