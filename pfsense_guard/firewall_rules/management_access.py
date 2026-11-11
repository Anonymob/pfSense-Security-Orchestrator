from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class PolicyRule:
    sequence: int
    action: str
    protocol: str
    source: str
    destination: str
    destination_ports: list[int]
    description: str

    def to_dict(self) -> dict:
        return asdict(self)


def build_management_policy(
    management_subnet: str,
    webgui_port: int = 443,
    ssh_port: int = 22,
    include_ssh: bool = True,
) -> list[PolicyRule]:
    network = ipaddress.ip_network(management_subnet, strict=False)
    ports = [webgui_port]
    if include_ssh and ssh_port not in ports:
        ports.append(ssh_port)
    if any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Management ports must be between 1 and 65535.")

    # Conceptual rule order only. pfSense interface, anti-lockout and aliases
    # must be reconciled against the actual config before implementing these.
    return [
        PolicyRule(1, "pass", "tcp", str(network), "This Firewall", ports,
                   "Allow management services only from the approved management network"),
        PolicyRule(2, "block", "tcp", "any", "This Firewall", ports,
                   "Block other sources from management services"),
    ]
