"""Parser for airport WiFi utility output."""

import re
from typing import Optional
from network_analyzer.models import WiFiInfo, NetworkScan


def parse_airport_info(output: str) -> Optional[WiFiInfo]:
    """Parse airport -I command output.

    Args:
        output: airport -I command output

    Returns:
        WiFiInfo object or None if not connected
    """
    if not output or "AirPort: Off" in output:
        return None

    def extract_value(key: str, default=None):
        """Extract value for a key from output."""
        pattern = rf'{key}:\s*(.+)'
        match = re.search(pattern, output)
        return match.group(1).strip() if match else default

    def extract_int(key: str, default: int = 0) -> int:
        """Extract integer value."""
        value = extract_value(key)
        if value:
            try:
                # Remove any non-numeric characters except minus
                value = re.sub(r'[^\d-]', '', value)
                return int(value)
            except ValueError:
                pass
        return default

    ssid = extract_value('SSID', '')
    if not ssid:
        return None

    rssi = extract_int('agrCtlRSSI', 0)
    noise = extract_int('agrCtlNoise', 0)

    return WiFiInfo(
        ssid=ssid,
        bssid=extract_value('BSSID', ''),
        channel=extract_int('channel', 0),
        rssi=rssi,
        noise=noise,
        snr=rssi - noise,
        tx_rate=extract_int('lastTxRate', 0),
        mcs_index=extract_int('MCS', -1),
        phy_mode=extract_value('PHY Mode', ''),
        security=extract_value('link auth', ''),
        channel_width=extract_int('channelWidth', 0)
    )


def parse_airport_scan(output: str) -> list[NetworkScan]:
    """Parse airport scan command output.

    Args:
        output: airport scan command output

    Returns:
        List of NetworkScan objects
    """
    networks = []
    lines = output.strip().split('\n')

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 7:
            try:
                # Format: SSID BSSID RSSI CHANNEL HT CC SECURITY
                ssid = parts[0]
                bssid = parts[1]
                rssi = int(parts[2])
                channel = int(parts[3])

                # Security is everything after channel info
                security = ' '.join(parts[6:]) if len(parts) > 6 else ''

                networks.append(NetworkScan(
                    ssid=ssid,
                    bssid=bssid,
                    channel=channel,
                    rssi=rssi,
                    security=security
                ))
            except (ValueError, IndexError):
                continue

    return networks
