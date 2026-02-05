"""Parser for DHCP/ipconfig command output."""

import re
from typing import Optional


def parse_dhcp_info(output: str) -> Optional[dict]:
    """Parse ipconfig getpacket output for DHCP information.

    Args:
        output: ipconfig getpacket command output

    Returns:
        Dictionary with DHCP info or None if not DHCP
    """
    if "op = BOOTREPLY" not in output and "op = BOOTREQUEST" not in output:
        return None

    info = {
        'is_dhcp': True,
        'server': None,
        'router': None,
        'dns_servers': [],
        'domain_name': None,
        'lease_time': None,
        'subnet_mask': None
    }

    # Extract DHCP server (server_identifier)
    server_match = re.search(r'server_identifier \(ip\):\s*(\d+\.\d+\.\d+\.\d+)', output)
    if server_match:
        info['server'] = server_match.group(1)

    # Extract router/gateway
    router_match = re.search(r'router \(ip_mult\):\s*\{([^}]+)\}', output)
    if router_match:
        routers = router_match.group(1).split(',')
        info['router'] = routers[0].strip() if routers else None

    # Extract DNS servers
    dns_match = re.search(r'domain_name_server \(ip_mult\):\s*\{([^}]+)\}', output)
    if dns_match:
        dns_servers = [ip.strip() for ip in dns_match.group(1).split(',')]
        info['dns_servers'] = dns_servers

    # Extract domain name
    domain_match = re.search(r'domain_name \(string\):\s*(.+)', output)
    if domain_match:
        info['domain_name'] = domain_match.group(1).strip()

    # Extract subnet mask
    mask_match = re.search(r'subnet_mask \(ip\):\s*(\d+\.\d+\.\d+\.\d+)', output)
    if mask_match:
        info['subnet_mask'] = mask_match.group(1)

    # Extract lease time (hex to seconds)
    lease_match = re.search(r'lease_time \(uint32\):\s*0x([0-9a-fA-F]+)', output)
    if lease_match:
        info['lease_time'] = int(lease_match.group(1), 16)

    return info


def format_lease_time(seconds: int) -> str:
    """Format lease time in human-readable format.

    Args:
        seconds: Lease time in seconds

    Returns:
        Formatted string (e.g., '2 days, 3 hours')
    """
    if seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minutes"
    elif seconds < 86400:
        hours = seconds // 3600
        return f"{hours} hours"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        if hours > 0:
            return f"{days} days, {hours} hours"
        return f"{days} days"
