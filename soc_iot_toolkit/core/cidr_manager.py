"""
CIDR Manager Module.

Handles CIDR range detection, validation, and management
for network scanning operations.
"""

import ipaddress
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple
from loguru import logger

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


@dataclass
class CIDRRange:
    """Represents a CIDR range with metadata."""
    cidr: str
    network_address: str
    broadcast_address: str
    netmask: str
    prefix_length: int
    host_count: int
    interface: str
    gateway: Optional[str] = None
    is_private: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cidr": self.cidr,
            "network_address": self.network_address,
            "broadcast_address": self.broadcast_address,
            "netmask": self.netmask,
            "prefix_length": self.prefix_length,
            "host_count": self.host_count,
            "interface": self.interface,
            "gateway": self.gateway,
            "is_private": self.is_private,
        }


class CIDRManager:
    """
    Manages CIDR range detection and validation.
    
    Provides methods for:
    - Auto-detecting CIDR ranges from network interfaces
    - Validating CIDR notation
    - Calculating host counts
    - Managing multiple CIDR ranges for scanning
    """
    
    def __init__(self, interface: Optional[str] = None):
        """
        Initialize the CIDRManager.
        
        Args:
            interface: Optional specific interface to use.
        """
        self._interface = interface
        self._detected_cidrs: List[CIDRRange] = []
        self._selected_cidr: Optional[CIDRRange] = None
    
    def detect_cidrs(self, interface: Optional[str] = None) -> List[CIDRRange]:
        """
        Detect available CIDR ranges from network interfaces.
        
        Args:
            interface: Optional specific interface to scan.
                      If None, scans all interfaces.
        
        Returns:
            List of detected CIDRRange objects.
        """
        self._detected_cidrs.clear()
        target_interface = interface or self._interface
        
        if NETIFACES_AVAILABLE:
            self._detect_with_netifaces(target_interface)
        else:
            self._detect_with_fallback(target_interface)
        
        # Get gateway information
        self._detect_gateways()
        
        logger.info(f"Detected {len(self._detected_cidrs)} CIDR ranges")
        return self._detected_cidrs
    
    def _detect_with_netifaces(self, target_interface: Optional[str] = None) -> None:
        """Detect CIDRs using netifaces library."""
        interfaces = [target_interface] if target_interface else netifaces.interfaces()
        
        for iface_name in interfaces:
            try:
                addrs = netifaces.ifaddresses(iface_name)
                
                if netifaces.AF_INET not in addrs:
                    continue
                
                for addr_info in addrs[netifaces.AF_INET]:
                    ip_addr = addr_info.get("addr")
                    netmask = addr_info.get("netmask")
                    
                    if not ip_addr or not netmask:
                        continue
                    
                    # Skip loopback
                    if ip_addr.startswith("127."):
                        continue
                    
                    cidr_range = self._create_cidr_range(ip_addr, netmask, iface_name)
                    if cidr_range:
                        self._detected_cidrs.append(cidr_range)
            
            except Exception as e:
                logger.error(f"Error detecting CIDR for {iface_name}: {e}")
    
    def _detect_with_fallback(self, target_interface: Optional[str] = None) -> None:
        """Detect CIDRs using system commands (fallback)."""
        try:
            cmd = ["ip", "-o", "-4", "addr", "show"]
            if target_interface:
                cmd.extend(["dev", target_interface])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return
            
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                
                parts = line.split()
                iface_name = parts[1] if len(parts) > 1 else None
                
                # Find inet address
                for i, part in enumerate(parts):
                    if part == "inet" and i + 1 < len(parts):
                        ip_cidr = parts[i + 1]
                        if "/" in ip_cidr:
                            ip_addr, prefix = ip_cidr.split("/")
                            
                            # Skip loopback
                            if ip_addr.startswith("127."):
                                continue
                            
                            # Convert prefix to netmask
                            netmask = self._prefix_to_netmask(int(prefix))
                            
                            cidr_range = self._create_cidr_range(ip_addr, netmask, iface_name)
                            if cidr_range:
                                self._detected_cidrs.append(cidr_range)
        
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Failed to detect CIDRs with fallback: {e}")
    
    def _create_cidr_range(
        self, ip_addr: str, netmask: str, interface: str
    ) -> Optional[CIDRRange]:
        """Create a CIDRRange object from IP and netmask."""
        try:
            # Create network object
            network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
            
            return CIDRRange(
                cidr=str(network),
                network_address=str(network.network_address),
                broadcast_address=str(network.broadcast_address),
                netmask=netmask,
                prefix_length=network.prefixlen,
                host_count=network.num_addresses - 2,  # Exclude network and broadcast
                interface=interface,
                is_private=network.is_private,
            )
        except Exception as e:
            logger.error(f"Error creating CIDR range: {e}")
            return None
    
    def _detect_gateways(self) -> None:
        """Detect and assign gateway addresses to CIDR ranges."""
        gateways = {}
        
        if NETIFACES_AVAILABLE:
            try:
                gw_info = netifaces.gateways()
                if "default" in gw_info and netifaces.AF_INET in gw_info["default"]:
                    default_gw = gw_info["default"][netifaces.AF_INET]
                    gateways[default_gw[1]] = default_gw[0]
            except Exception as e:
                logger.error(f"Error detecting gateways: {e}")
        else:
            # Fallback: parse route command
            try:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n"):
                        parts = line.split()
                        if "via" in parts and "dev" in parts:
                            via_idx = parts.index("via")
                            dev_idx = parts.index("dev")
                            if via_idx + 1 < len(parts) and dev_idx + 1 < len(parts):
                                gateway = parts[via_idx + 1]
                                device = parts[dev_idx + 1]
                                gateways[device] = gateway
            except Exception as e:
                logger.error(f"Error detecting gateways with fallback: {e}")
        
        # Assign gateways to CIDR ranges
        for cidr_range in self._detected_cidrs:
            if cidr_range.interface in gateways:
                cidr_range.gateway = gateways[cidr_range.interface]
    
    def _prefix_to_netmask(self, prefix: int) -> str:
        """Convert prefix length to dotted netmask notation."""
        bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return f"{(bits >> 24) & 0xFF}.{(bits >> 16) & 0xFF}.{(bits >> 8) & 0xFF}.{bits & 0xFF}"
    
    def validate_cidr(self, cidr: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a CIDR notation string.
        
        Args:
            cidr: CIDR string to validate (e.g., '192.168.1.0/24').
        
        Returns:
            Tuple of (is_valid, error_message).
        """
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            
            # Check for reasonable scan size
            if network.num_addresses > 65536:
                return False, "CIDR range too large (max /16 recommended)"
            
            return True, None
        
        except ValueError as e:
            return False, str(e)
    
    def get_host_count(self, cidr: str) -> int:
        """
        Get the number of usable hosts in a CIDR range.
        
        Args:
            cidr: CIDR notation string.
        
        Returns:
            Number of usable host addresses.
        """
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            # Subtract network and broadcast addresses
            return max(0, network.num_addresses - 2)
        except ValueError:
            return 0
    
    def get_host_list(self, cidr: str) -> List[str]:
        """
        Get a list of all host IPs in a CIDR range.
        
        Args:
            cidr: CIDR notation string.
        
        Returns:
            List of IP addresses as strings.
        """
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            return [str(host) for host in network.hosts()]
        except ValueError:
            return []
    
    def select_cidr(self, cidr: str) -> bool:
        """
        Select a CIDR range for scanning.
        
        Args:
            cidr: CIDR notation string to select.
        
        Returns:
            True if selection successful, False otherwise.
        """
        # Check if it's one of the detected CIDRs
        for detected in self._detected_cidrs:
            if detected.cidr == cidr:
                self._selected_cidr = detected
                logger.info(f"Selected CIDR: {cidr}")
                return True
        
        # If not detected, validate and create new
        is_valid, error = self.validate_cidr(cidr)
        if is_valid:
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                self._selected_cidr = CIDRRange(
                    cidr=cidr,
                    network_address=str(network.network_address),
                    broadcast_address=str(network.broadcast_address),
                    netmask=str(network.netmask),
                    prefix_length=network.prefixlen,
                    host_count=network.num_addresses - 2,
                    interface=self._interface or "manual",
                    is_private=network.is_private,
                )
                logger.info(f"Selected custom CIDR: {cidr}")
                return True
            except Exception as e:
                logger.error(f"Error selecting CIDR: {e}")
                return False
        else:
            logger.error(f"Invalid CIDR: {error}")
            return False
    
    def get_selected_cidr(self) -> Optional[CIDRRange]:
        """Get the currently selected CIDR range."""
        return self._selected_cidr
    
    def get_detected_cidrs(self) -> List[CIDRRange]:
        """Get all detected CIDR ranges."""
        return self._detected_cidrs
    
    def get_cidr_summary(self) -> Dict[str, Any]:
        """
        Get a summary of CIDR ranges.
        
        Returns:
            Dictionary with CIDR information.
        """
        return {
            "detected_count": len(self._detected_cidrs),
            "selected": self._selected_cidr.to_dict() if self._selected_cidr else None,
            "cidrs": [c.to_dict() for c in self._detected_cidrs],
        }
    
    def split_cidr(self, cidr: str, new_prefix: int) -> List[str]:
        """
        Split a CIDR range into smaller subnets.
        
        Args:
            cidr: Original CIDR range.
            new_prefix: New prefix length for subnets.
        
        Returns:
            List of subnet CIDR strings.
        """
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            if new_prefix <= network.prefixlen:
                return [cidr]
            
            return [str(subnet) for subnet in network.subnets(new_prefix=new_prefix)]
        except ValueError:
            return []
