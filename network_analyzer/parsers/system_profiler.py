"""Parser for system_profiler command output."""

import re
from typing import Optional


def parse_hardware_port_mapping(output: str) -> dict[str, str]:
    """Parse system_profiler or networksetup to map interfaces to hardware ports.

    Args:
        output: networksetup -listallhardwareports output

    Returns:
        Dictionary mapping interface names to hardware port names
    """
    mapping = {}
    lines = output.strip().split('\n')

    current_port = None
    for line in lines:
        line = line.strip()

        if line.startswith('Hardware Port:'):
            current_port = line.split(':', 1)[1].strip()
        elif line.startswith('Device:') and current_port:
            device = line.split(':', 1)[1].strip()
            mapping[device] = current_port
            current_port = None

    return mapping


def parse_dns_servers(output: str) -> list[str]:
    """Parse scutil --dns output to extract DNS servers.

    Args:
        output: scutil --dns command output

    Returns:
        List of DNS server IPs
    """
    dns_servers = []
    pattern = r'nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)'
    matches = re.findall(pattern, output)

    # Return unique DNS servers
    return list(dict.fromkeys(matches))
