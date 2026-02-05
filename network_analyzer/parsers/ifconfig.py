"""Parser for ifconfig command output."""

import re
from typing import Optional
from network_analyzer.models import InterfaceInfo


def parse_ifconfig(output: str, interface_name: str) -> Optional[InterfaceInfo]:
    """Parse ifconfig output for a specific interface.

    Args:
        output: ifconfig command output
        interface_name: Interface name to parse

    Returns:
        InterfaceInfo object or None if not found
    """
    # Find the interface block - match from interface name to next interface or end
    lines = output.split('\n')
    block_lines = []
    in_block = False

    for line in lines:
        # Start of our interface
        if line.startswith(f"{interface_name}:"):
            in_block = True
            block_lines.append(line)
        # Start of another interface
        elif in_block and line and not line.startswith(('\t', ' ')):
            break
        # Line belonging to current interface
        elif in_block:
            block_lines.append(line)

    if not block_lines:
        return None

    block = '\n'.join(block_lines)

    # Parse MAC address
    mac_match = re.search(r'ether\s+([0-9a-f:]+)', block, re.IGNORECASE)
    mac_address = mac_match.group(1) if mac_match else ""

    # Parse IPv4 address and netmask
    ipv4_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-f]+)', block)
    ipv4_address = None
    netmask = None
    if ipv4_match:
        ipv4_address = ipv4_match.group(1)
        # Convert hex netmask to dotted decimal
        hex_mask = ipv4_match.group(2)
        netmask = '.'.join(str(int(hex_mask[i:i+2], 16)) for i in range(0, 8, 2))

    # Parse IPv6 addresses
    ipv6_addresses = re.findall(r'inet6\s+([0-9a-f:]+)', block, re.IGNORECASE)

    # Parse status
    status_match = re.search(r'status:\s+(\w+)', block)
    status = status_match.group(1) if status_match else "unknown"

    # Parse media type
    media_match = re.search(r'media:\s+([^\n]+)', block)
    media_type = media_match.group(1).strip() if media_match else ""

    # Parse MTU
    mtu_match = re.search(r'mtu\s+(\d+)', block)
    mtu = int(mtu_match.group(1)) if mtu_match else 0

    return InterfaceInfo(
        name=interface_name,
        hardware_port="",  # Will be filled from networksetup
        mac_address=mac_address,
        ipv4_address=ipv4_address,
        ipv6_addresses=ipv6_addresses,
        netmask=netmask,
        status=status,
        media_type=media_type,
        mtu=mtu
    )


def parse_all_interfaces(output: str) -> list[str]:
    """Parse all interface names from ifconfig output.

    Args:
        output: ifconfig -a output

    Returns:
        List of interface names
    """
    pattern = r'^(\w+\d*):\s+flags='
    matches = re.findall(pattern, output, re.MULTILINE)
    return matches
