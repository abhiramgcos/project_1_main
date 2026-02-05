"""
Input Validation Module.

Provides validation functions for network-related inputs.
"""

import re
import ipaddress
from typing import Tuple, Optional


def validate_cidr(cidr: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a CIDR notation string.
    
    Args:
        cidr: CIDR string to validate (e.g., '192.168.1.0/24').
    
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not cidr:
        return False, "CIDR cannot be empty"
    
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        
        # Check for reasonable scan size
        if network.num_addresses > 65536:
            return False, "CIDR range too large (max /16 recommended for scanning)"
        
        # Check for reserved ranges
        if network.is_loopback:
            return False, "Cannot scan loopback addresses"
        
        return True, None
    
    except ValueError as e:
        return False, f"Invalid CIDR format: {str(e)}"


def validate_ip(ip_address: str) -> Tuple[bool, Optional[str]]:
    """
    Validate an IP address.
    
    Args:
        ip_address: IP address string to validate.
    
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not ip_address:
        return False, "IP address cannot be empty"
    
    try:
        ip = ipaddress.ip_address(ip_address)
        return True, None
    except ValueError:
        return False, "Invalid IP address format"


def validate_mac(mac_address: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a MAC address.
    
    Args:
        mac_address: MAC address string to validate.
    
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not mac_address:
        return False, "MAC address cannot be empty"
    
    # Common MAC address formats
    patterns = [
        r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$',  # XX:XX:XX:XX:XX:XX
        r'^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$',  # XX-XX-XX-XX-XX-XX
        r'^[0-9A-Fa-f]{12}$',                       # XXXXXXXXXXXX
        r'^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$',  # XXXX.XXXX.XXXX
    ]
    
    for pattern in patterns:
        if re.match(pattern, mac_address):
            return True, None
    
    return False, "Invalid MAC address format"


def validate_port(port: int) -> Tuple[bool, Optional[str]]:
    """
    Validate a port number.
    
    Args:
        port: Port number to validate.
    
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not isinstance(port, int):
        try:
            port = int(port)
        except (ValueError, TypeError):
            return False, "Port must be a number"
    
    if port < 1 or port > 65535:
        return False, "Port must be between 1 and 65535"
    
    return True, None


def validate_port_range(port_range: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a port range string.
    
    Args:
        port_range: Port range string (e.g., '22,80,443' or '1-1024').
    
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not port_range:
        return False, "Port range cannot be empty"
    
    # Handle comma-separated list
    if ',' in port_range:
        ports = port_range.split(',')
        for port in ports:
            port = port.strip()
            if '-' in port:
                # Range within comma-separated list
                is_valid, error = validate_port_range(port)
                if not is_valid:
                    return False, error
            else:
                try:
                    p = int(port)
                    is_valid, error = validate_port(p)
                    if not is_valid:
                        return False, error
                except ValueError:
                    return False, f"Invalid port: {port}"
        return True, None
    
    # Handle range (e.g., 1-1024)
    if '-' in port_range:
        parts = port_range.split('-')
        if len(parts) != 2:
            return False, "Invalid port range format"
        
        try:
            start = int(parts[0].strip())
            end = int(parts[1].strip())
        except ValueError:
            return False, "Port range must contain valid numbers"
        
        is_valid, error = validate_port(start)
        if not is_valid:
            return False, f"Start port: {error}"
        
        is_valid, error = validate_port(end)
        if not is_valid:
            return False, f"End port: {error}"
        
        if start > end:
            return False, "Start port must be less than end port"
        
        return True, None
    
    # Single port
    try:
        port = int(port_range.strip())
        return validate_port(port)
    except ValueError:
        return False, f"Invalid port: {port_range}"


def validate_hostname(hostname: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a hostname.
    
    Args:
        hostname: Hostname to validate.
    
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not hostname:
        return False, "Hostname cannot be empty"
    
    if len(hostname) > 255:
        return False, "Hostname too long (max 255 characters)"
    
    # Check each label
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    
    labels = hostname.split(".")
    
    for label in labels:
        if len(label) > 63:
            return False, "Label too long (max 63 characters)"
        
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', label):
            return False, f"Invalid label: {label}"
    
    return True, None


def normalize_mac(mac_address: str) -> Optional[str]:
    """
    Normalize a MAC address to XX:XX:XX:XX:XX:XX format.
    
    Args:
        mac_address: MAC address in any valid format.
    
    Returns:
        Normalized MAC address or None if invalid.
    """
    is_valid, _ = validate_mac(mac_address)
    if not is_valid:
        return None
    
    # Remove common separators and convert to uppercase
    mac = mac_address.upper()
    mac = re.sub(r'[.:-]', '', mac)
    
    # Format as XX:XX:XX:XX:XX:XX
    if len(mac) == 12:
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    
    return None
