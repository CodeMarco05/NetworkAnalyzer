"""Offline network data collection (no internet required)."""

import re
from typing import Optional
from network_analyzer.utils import execute_command, is_wifi_interface
from network_analyzer.models import (
    InterfaceInfo,
    NetworkMetrics,
    WiFiInfo,
    PingResult,
    NetworkScan
)
from network_analyzer.parsers.ifconfig import parse_ifconfig, parse_all_interfaces
from network_analyzer.parsers.netstat import (
    parse_netstat_interface,
    parse_routing_table,
    get_default_gateway
)
from network_analyzer.parsers.airport import parse_airport_info, parse_airport_scan
from network_analyzer.parsers.system_profiler import (
    parse_hardware_port_mapping,
    parse_dns_servers
)
from network_analyzer.parsers.dhcp import parse_dhcp_info
import logging

logger = logging.getLogger(__name__)


def get_all_interfaces() -> list[InterfaceInfo]:
    """Get all network interfaces with their details.

    Returns:
        List of InterfaceInfo objects
    """
    interfaces = []

    try:
        # Get hardware port mapping
        stdout, _, _ = execute_command(
            ["networksetup", "-listallhardwareports"],
            timeout=10
        )
        port_mapping = parse_hardware_port_mapping(stdout)

        # Get all interface details
        stdout, _, _ = execute_command(["ifconfig", "-a"], timeout=10)
        interface_names = parse_all_interfaces(stdout)

        for name in interface_names:
            # Skip loopback and some virtual interfaces
            if name.startswith(('lo', 'gif', 'stf', 'fw')):
                continue

            info = parse_ifconfig(stdout, name)
            if info:
                info.hardware_port = port_mapping.get(name, "Unknown")
                interfaces.append(info)

    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")

    return interfaces


def get_interface_metrics(interface: str) -> Optional[NetworkMetrics]:
    """Get network metrics for an interface.

    Args:
        interface: Interface name

    Returns:
        NetworkMetrics object or None
    """
    try:
        stdout, _, _ = execute_command(
            ["netstat", "-I", interface, "-b"],
            timeout=10
        )
        return parse_netstat_interface(stdout, interface)
    except Exception as e:
        logger.error(f"Failed to get metrics for {interface}: {e}")
        return None


def get_wifi_info(interface: str) -> Optional[WiFiInfo]:
    """Get WiFi connection information.

    Args:
        interface: Interface name

    Returns:
        WiFiInfo object or None if not WiFi or not connected
    """
    if not is_wifi_interface(interface):
        return None

    try:
        airport_cmd = [
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport",
            "-I"
        ]
        stdout, _, code = execute_command(airport_cmd, timeout=10)

        if code == 0:
            return parse_airport_info(stdout)
    except Exception as e:
        logger.error(f"Failed to get WiFi info: {e}")

    return None


def get_wifi_scan() -> list[NetworkScan]:
    """Scan for available WiFi networks.

    Returns:
        List of NetworkScan objects
    """
    try:
        airport_cmd = [
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport",
            "-s"
        ]
        stdout, _, code = execute_command(airport_cmd, timeout=30)

        if code == 0:
            return parse_airport_scan(stdout)
    except Exception as e:
        logger.error(f"Failed to scan WiFi networks: {e}")

    return []


def get_routing_info() -> dict:
    """Get routing table information.

    Returns:
        Dictionary with routes and default gateway
    """
    try:
        stdout, _, _ = execute_command(["netstat", "-rn"], timeout=10)
        return {
            'routes': parse_routing_table(stdout),
            'default_gateway': get_default_gateway(stdout)
        }
    except Exception as e:
        logger.error(f"Failed to get routing info: {e}")
        return {'routes': [], 'default_gateway': None}


def get_dns_servers() -> list[str]:
    """Get configured DNS servers.

    Returns:
        List of DNS server IPs
    """
    try:
        stdout, _, _ = execute_command(["scutil", "--dns"], timeout=10)
        return parse_dns_servers(stdout)
    except Exception as e:
        logger.error(f"Failed to get DNS servers: {e}")
        return []


def get_arp_cache() -> list[dict]:
    """Get ARP cache (connected devices on LAN).

    Returns:
        List of ARP entries
    """
    try:
        stdout, _, _ = execute_command(["arp", "-a"], timeout=10)
        entries = []

        # Parse format: hostname (ip) at mac on interface
        pattern = r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)\s+on\s+(\w+)'
        for match in re.finditer(pattern, stdout):
            entries.append({
                'hostname': match.group(1),
                'ip': match.group(2),
                'mac': match.group(3),
                'interface': match.group(4)
            })

        return entries
    except Exception as e:
        logger.error(f"Failed to get ARP cache: {e}")
        return []


def run_ping_test(host: str, count: int = 10) -> Optional[PingResult]:
    """Run ping test to measure latency and packet loss.

    Args:
        host: Hostname or IP to ping
        count: Number of pings

    Returns:
        PingResult object or None on failure
    """
    try:
        stdout, _, code = execute_command(
            ["ping", "-c", str(count), host],
            timeout=count + 10
        )

        if code != 0:
            return PingResult(
                host=host,
                packets_sent=count,
                packets_received=0,
                packet_loss=100.0
            )

        # Parse statistics
        # Format: "10 packets transmitted, 8 packets received, 20.0% packet loss"
        stats_match = re.search(
            r'(\d+) packets transmitted, (\d+) (?:packets )?received, ([\d.]+)% packet loss',
            stdout
        )

        if not stats_match:
            return None

        packets_sent = int(stats_match.group(1))
        packets_received = int(stats_match.group(2))
        packet_loss = float(stats_match.group(3))

        # Parse RTT statistics
        # Format: "round-trip min/avg/max/stddev = 12.345/23.456/34.567/5.678 ms"
        rtt_match = re.search(
            r'round-trip min/avg/max/(?:std-dev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',
            stdout
        )

        if rtt_match:
            return PingResult(
                host=host,
                packets_sent=packets_sent,
                packets_received=packets_received,
                packet_loss=packet_loss,
                min_rtt=float(rtt_match.group(1)),
                avg_rtt=float(rtt_match.group(2)),
                max_rtt=float(rtt_match.group(3)),
                stddev_rtt=float(rtt_match.group(4))
            )
        else:
            return PingResult(
                host=host,
                packets_sent=packets_sent,
                packets_received=packets_received,
                packet_loss=packet_loss
            )

    except Exception as e:
        logger.error(f"Failed to ping {host}: {e}")
        return None


def get_active_connections() -> list[dict]:
    """Get active network connections.

    Returns:
        List of connection entries
    """
    try:
        stdout, _, _ = execute_command(
            ["lsof", "-i", "-P", "-n"],
            timeout=15
        )

        connections = []
        lines = stdout.strip().split('\n')

        # Skip header
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 9:
                connections.append({
                    'command': parts[0],
                    'pid': parts[1],
                    'user': parts[2],
                    'protocol': parts[7] if len(parts) > 7 else '',
                    'state': parts[9] if len(parts) > 9 else ''
                })

        return connections[:50]  # Limit to 50 entries
    except Exception as e:
        logger.error(f"Failed to get active connections: {e}")
        return []


def get_dhcp_info(interface: str) -> Optional[dict]:
    """Get DHCP configuration for an interface.

    Args:
        interface: Interface name

    Returns:
        Dictionary with DHCP info or None if not using DHCP
    """
    try:
        stdout, _, code = execute_command(
            ["ipconfig", "getpacket", interface],
            timeout=10
        )

        if code == 0:
            return parse_dhcp_info(stdout)
    except Exception as e:
        logger.debug(f"Failed to get DHCP info for {interface}: {e}")

    return None


def get_network_dns_servers(interface: str) -> list[str]:
    """Get actual network DNS servers (from DHCP or network config).

    This retrieves the DNS servers provided by the network (via DHCP),
    not local DNS servers like 127.x.x.x from DNS filtering software.

    Args:
        interface: Interface name

    Returns:
        List of DNS server IPs from the network
    """
    dns_servers = []

    # First try DHCP
    dhcp_info = get_dhcp_info(interface)
    if dhcp_info and dhcp_info.get('dns_servers'):
        dns_servers = dhcp_info['dns_servers']
        logger.info(f"Got DNS servers from DHCP: {dns_servers}")
        return dns_servers

    # Fallback to scutil DNS (but filter out local ones)
    try:
        stdout, _, _ = execute_command(["scutil", "--dns"], timeout=10)
        all_dns = parse_dns_servers(stdout)

        # Filter out local DNS servers (127.x.x.x, ::1, etc.)
        dns_servers = [
            dns for dns in all_dns
            if not dns.startswith('127.') and dns != '::1'
        ]

        if dns_servers:
            logger.info(f"Got DNS servers from scutil: {dns_servers}")
            return dns_servers
    except Exception as e:
        logger.error(f"Failed to get DNS servers: {e}")

    return dns_servers
