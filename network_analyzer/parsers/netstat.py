"""Parser for netstat command output."""

import re
from typing import Optional
from network_analyzer.models import NetworkMetrics


def parse_netstat_interface(output: str, interface_name: str) -> Optional[NetworkMetrics]:
    """Parse netstat -I output for interface metrics.

    Args:
        output: netstat -I <interface> output
        interface_name: Interface name

    Returns:
        NetworkMetrics object or None if parsing fails
    """
    lines = output.strip().split('\n')

    # Find the data line (skip header)
    for line in lines:
        if line.startswith(interface_name):
            parts = line.split()
            if len(parts) >= 10:
                try:
                    # netstat -I format:
                    # Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
                    return NetworkMetrics(
                        interface=interface_name,
                        packets_in=int(parts[4]),
                        errors_in=int(parts[5]),
                        bytes_in=int(parts[6]),
                        packets_out=int(parts[7]),
                        errors_out=int(parts[8]),
                        bytes_out=int(parts[9]),
                        collisions=int(parts[10]) if len(parts) > 10 else 0
                    )
                except (ValueError, IndexError):
                    pass

    return None


def parse_routing_table(output: str) -> list[dict]:
    """Parse netstat -rn routing table output.

    Args:
        output: netstat -rn output

    Returns:
        List of route entries
    """
    routes = []
    lines = output.strip().split('\n')

    # Skip header lines
    in_ipv4 = False
    for line in lines:
        if 'Destination' in line and 'Gateway' in line:
            in_ipv4 = True
            continue

        if in_ipv4 and line.strip():
            # Stop at IPv6 section
            if 'Internet6' in line:
                break

            parts = line.split()
            if len(parts) >= 4:
                routes.append({
                    'destination': parts[0],
                    'gateway': parts[1],
                    'flags': parts[2],
                    'interface': parts[3] if len(parts) > 3 else ''
                })

    return routes


def get_default_gateway(output: str) -> Optional[str]:
    """Extract default gateway from routing table.

    Args:
        output: netstat -rn output

    Returns:
        Default gateway IP or None
    """
    pattern = r'^default\s+(\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, output, re.MULTILINE)
    return match.group(1) if match else None
