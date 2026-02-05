"""Utility functions for network analysis."""

import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class CommandExecutionError(Exception):
    """Exception raised when command execution fails."""
    pass


def execute_command(
    cmd: list[str],
    timeout: int = 10,
    check_return_code: bool = False
) -> tuple[str, str, int]:
    """Execute system command with timeout and error handling.

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        check_return_code: Raise exception on non-zero return code

    Returns:
        Tuple of (stdout, stderr, returncode)

    Raises:
        CommandExecutionError: On timeout or command not found
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        if check_return_code and result.returncode != 0:
            raise CommandExecutionError(
                f"Command failed: {' '.join(cmd)}\n"
                f"Return code: {result.returncode}\n"
                f"stderr: {result.stderr}"
            )

        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        raise CommandExecutionError(f"Command timed out: {' '.join(cmd)}")
    except FileNotFoundError:
        logger.error(f"Command not found: {cmd[0]}")
        raise CommandExecutionError(f"Command not found: {cmd[0]}")
    except Exception as e:
        logger.error(f"Unexpected error executing {' '.join(cmd)}: {e}")
        raise CommandExecutionError(f"Failed to execute command: {e}")


def is_wifi_interface(interface: str) -> bool:
    """Check if interface is WiFi.

    Args:
        interface: Interface name (e.g., 'en0')

    Returns:
        True if WiFi interface, False otherwise
    """
    try:
        airport_cmd = [
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport",
            "-I"
        ]
        stdout, _, code = execute_command(airport_cmd, timeout=5)
        return code == 0 and "agrCtlRSSI" in stdout
    except Exception:
        return False


def check_internet_connectivity() -> bool:
    """Check if internet is available.

    Returns:
        True if internet is reachable, False otherwise
    """
    # Method 1: scutil reachability
    try:
        stdout, _, code = execute_command(
            ["scutil", "-r", "8.8.8.8"],
            timeout=5
        )
        if code == 0 and "Reachable" in stdout:
            return True
    except Exception:
        pass

    # Method 2: ping fallback
    try:
        _, _, code = execute_command(
            ["ping", "-c", "1", "-W", "2", "8.8.8.8"],
            timeout=5
        )
        return code == 0
    except Exception:
        return False


def format_bytes(bytes_count: int) -> str:
    """Format bytes into human-readable string.

    Args:
        bytes_count: Number of bytes

    Returns:
        Formatted string (e.g., '1.5 GB')
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"


def calculate_error_rate(errors: int, total_packets: int) -> float:
    """Calculate error rate percentage.

    Args:
        errors: Number of errors
        total_packets: Total packets

    Returns:
        Error rate as percentage
    """
    if total_packets == 0:
        return 0.0
    return (errors / total_packets) * 100


def get_macos_version() -> Optional[tuple[int, int, int]]:
    """Get macOS version.

    Returns:
        Tuple of (major, minor, patch) or None if unable to determine
    """
    try:
        stdout, _, code = execute_command(["sw_vers", "-productVersion"], timeout=5)
        if code == 0:
            parts = stdout.strip().split('.')
            return tuple(int(p) for p in parts)
    except Exception:
        pass
    return None


def supports_network_quality() -> bool:
    """Check if networkQuality command is available (macOS 12.1+).

    Returns:
        True if networkQuality is available, False otherwise
    """
    version = get_macos_version()
    if version is None:
        return False

    major, minor = version[0], version[1] if len(version) > 1 else 0
    return major > 12 or (major == 12 and minor >= 1)


def assess_network_health(
    interface_info,
    metrics,
    wifi_info=None,
    ping_results=None,
    speed_result=None
) -> 'HealthStatus':
    """Assess overall network health.

    Args:
        interface_info: InterfaceInfo object
        metrics: NetworkMetrics object
        wifi_info: Optional WiFiInfo object
        ping_results: Optional list of PingResult objects
        speed_result: Optional SpeedTestResult object

    Returns:
        HealthStatus object
    """
    from network_analyzer.models import HealthStatus

    score = 100
    warnings = []
    errors = []
    recommendations = []

    # Check interface status
    if interface_info.status != "active":
        score -= 50
        errors.append("Interface is not active")
        recommendations.append("Check interface configuration and ensure it's enabled")

    # Check for errors
    if metrics:
        total_packets = metrics.packets_in + metrics.packets_out
        if total_packets > 0:
            error_rate = (metrics.errors_in + metrics.errors_out) / total_packets * 100

            if error_rate > 1.0:
                score -= 20
                errors.append(f"High error rate: {error_rate:.2f}%")
                recommendations.append("Check network cables or WiFi signal strength")
            elif error_rate > 0.1:
                score -= 10
                warnings.append(f"Moderate error rate: {error_rate:.2f}%")

            if metrics.collisions > total_packets * 0.01:
                score -= 5
                warnings.append("High collision rate detected")
                recommendations.append("Network may be congested")

    # Check WiFi signal quality
    if wifi_info:
        if wifi_info.rssi < -80:
            score -= 20
            errors.append(f"Very weak WiFi signal: {wifi_info.rssi} dBm")
            recommendations.append("Move closer to access point or use 5GHz band")
        elif wifi_info.rssi < -70:
            score -= 10
            warnings.append(f"Weak WiFi signal: {wifi_info.rssi} dBm")
            recommendations.append("Consider moving closer to access point")
        elif wifi_info.rssi < -60:
            score -= 5
            warnings.append(f"Fair WiFi signal: {wifi_info.rssi} dBm")

        # Check SNR
        if wifi_info.snr < 20:
            score -= 15
            errors.append(f"Poor signal-to-noise ratio: {wifi_info.snr} dB")
            recommendations.append("High interference detected, try changing WiFi channel")
        elif wifi_info.snr < 30:
            score -= 5
            warnings.append(f"Low signal-to-noise ratio: {wifi_info.snr} dB")

        # Check WiFi standard
        if wifi_info.phy_mode:
            if '802.11b' in wifi_info.phy_mode or '802.11g' in wifi_info.phy_mode:
                warnings.append(f"Using older WiFi standard: {wifi_info.phy_mode}")
                recommendations.append("Upgrade to WiFi 5 (802.11ac) or WiFi 6 (802.11ax)")

        # Check channel width
        if wifi_info.channel_width and wifi_info.channel_width < 40 and wifi_info.band == "5GHz":
            warnings.append(f"Using narrow channel width: {wifi_info.channel_width}MHz on 5GHz")
            recommendations.append("Configure router for 80MHz or 160MHz channel width")

    # Check ping results
    if ping_results:
        for result in ping_results:
            if result.packet_loss > 5.0:
                score -= 15
                errors.append(f"High packet loss to {result.host}: {result.packet_loss:.1f}%")
                recommendations.append("Check network stability and internet connection")
            elif result.packet_loss > 1.0:
                score -= 5
                warnings.append(f"Moderate packet loss to {result.host}: {result.packet_loss:.1f}%")

            if result.avg_rtt > 100:
                score -= 10
                warnings.append(f"High latency to {result.host}: {result.avg_rtt:.1f} ms")
                recommendations.append("Check for network congestion or bandwidth issues")

            if result.jitter > 20:
                score -= 10
                warnings.append(f"High jitter to {result.host}: {result.jitter:.1f} ms")
                recommendations.append("Network instability detected, may affect VoIP and gaming")
            elif result.jitter > 10:
                score -= 5
                warnings.append(f"Moderate jitter to {result.host}: {result.jitter:.1f} ms")

    # Check speed test results
    if speed_result:
        if speed_result.download_mbps < 10:
            score -= 10
            warnings.append(f"Slow download speed: {speed_result.download_mbps:.1f} Mbps")
            recommendations.append("Contact ISP or check for bandwidth throttling")

        if speed_result.upload_mbps < 5:
            score -= 5
            warnings.append(f"Slow upload speed: {speed_result.upload_mbps:.1f} Mbps")

    # Ensure score doesn't go below 0
    score = max(0, score)

    return HealthStatus(
        overall=HealthStatus.from_score(score),
        score=score,
        warnings=warnings,
        errors=errors,
        recommendations=recommendations
    )
