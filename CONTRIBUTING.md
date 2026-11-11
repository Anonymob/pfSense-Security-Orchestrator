# Contributing

We welcome defensive research and verified pfSense hardening modules.

## Required structure for a new module

Each contribution must include:

1. A unique finding/advisory identifier and a short description of the attack vector.
2. Primary vendor advisory or authoritative CVE references.
3. Exact affected editions, versions and package prerequisites; unknown ranges must be marked unknown rather than guessed.
4. An audit method that gathers evidence without changing the firewall.
5. A remediation recommendation and expected side effects.
6. A rollback plan for every write-capable change.
7. Unit tests plus a lab test plan covering both positive and negative cases.
8. A statement describing whether the module is read-only, plan-only, or write-capable.

## Safety requirements

- Read-only by default.
- Never use `AutoAddPolicy` or silently accept unknown SSH host keys.
- Never store passwords, private keys, API tokens or raw `config.xml` in reports/issues.
- Never hard-code credentials or fetch and execute arbitrary scripts from an untrusted URL.
- Do not mutate `/conf/config.xml` directly unless the contribution documents the vendor-supported procedure, schema, backup, rollback and target release matrix.
- Do not create firewall rules without checking anti-lockout behavior and preserving the management route.
- Use fixed command templates; validate every value before it reaches a shell or PHP source file.
- Do not label a CVE remediated just because an update command returned exit code zero. Verify package/release state after the change.

## Pull requests

Include test output, source links, affected pfSense builds, and a description of the lab setup. Maintainers should review write-capable modules separately from audit-only modules.
