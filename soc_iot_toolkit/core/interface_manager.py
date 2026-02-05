"""
Network Interface Manager Module.

Handles detection, enumeration, and management of network interfaces
for the SOC IoT Discovery Toolkit.
"""

import socket
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from loguru import logger

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    logger.warning("netifaces not available, using fallback methods")


@dataclass
class NetworkInterface:
    """Represents a network interface with its properties."""
    name: str
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    mac_address: Optional[str] = None
    broadcast: Optional[str] = None
    is_up: bool = False
    is_loopback: bool = False
    is_wireless: bool = False
    interface_type: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "ip_address": self.ip_address,
            "netmask": self.netmask,
            "mac_address": self.mac_address,
            "broadcast": self.broadcast,
            "is_up": self.is_up,
            "is_loopback": self.is_loopback,
            "is_wireless": self.is_wireless,
            "interface_type": self.interface_type,
        }


class InterfaceManager:
    """
    Manages network interface detection and selection.
    
    Provides methods for:
    - Detecting all available network interfaces
    - Identifying the active/primary interface
    - Getting interface details (IP, MAC, netmask)
    - Filtering interfaces by type
    """
    
    def __init__(self):
        """Initialize the InterfaceManager."""
        self._interfaces: Dict[str, NetworkInterface] = {}
        self._active_interface: Optional[str] = None
        self._refresh_interfaces()
    
    def _refresh_interfaces(self) -> None:
        """Refresh the list of network interfaces."""
        self._interfaces.clear()
        
        if NETIFACES_AVAILABLE:
            self._detect_with_netifaces()
        else:
            self._detect_with_fallback()
        
        self._detect_active_interface()
    
    def _detect_with_netifaces(self) -> None:
        """Detect interfaces using the netifaces library."""
        for iface_name in netifaces.interfaces():
            interface = NetworkInterface(name=iface_name)
            
            # Get addresses
            addrs = netifaces.ifaddresses(iface_name)
            
            # IPv4 address
            if netifaces.AF_INET in addrs:
                ipv4_info = addrs[netifaces.AF_INET][0]
                interface.ip_address = ipv4_info.get("addr")
                interface.netmask = ipv4_info.get("netmask")
                interface.broadcast = ipv4_info.get("broadcast")
            
            # MAC address
            if netifaces.AF_LINK in addrs:
                link_info = addrs[netifaces.AF_LINK][0]
                interface.mac_address = link_info.get("addr")
            
            # Determine interface properties
            interface.is_loopback = iface_name.startswith("lo")
            interface.is_wireless = self._is_wireless_interface(iface_name)
            interface.is_up = interface.ip_address is not None
            interface.interface_type = self._determine_interface_type(iface_name)
            
            self._interfaces[iface_name] = interface
    
    def _detect_with_fallback(self) -> None:
        """Detect interfaces using system commands (fallback method)."""
        try:
            # Use ip command on Linux
            result = subprocess.run(
                ["ip", "-o", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = parts[1].rstrip(":")
                        
                        if iface_name not in self._interfaces:
                            interface = NetworkInterface(name=iface_name)
                            interface.is_loopback = iface_name.startswith("lo")
                            interface.is_wireless = self._is_wireless_interface(iface_name)
                            interface.interface_type = self._determine_interface_type(iface_name)
                            self._interfaces[iface_name] = interface
                        
                        # Parse IP address
                        if "inet " in line:
                            for i, part in enumerate(parts):
                                if part == "inet" and i + 1 < len(parts):
                                    ip_cidr = parts[i + 1]
                                    if "/" in ip_cidr:
                                        self._interfaces[iface_name].ip_address = ip_cidr.split("/")[0]
                                        self._interfaces[iface_name].is_up = True
        
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Failed to detect interfaces: {e}")
    
    def _is_wireless_interface(self, iface_name: str) -> bool:
        """Check if an interface is wireless."""
        wireless_prefixes = ("wlan", "wlp", "wifi", "ath", "ra")
        return iface_name.lower().startswith(wireless_prefixes)
    
    def _determine_interface_type(self, iface_name: str) -> str:
        """Determine the type of network interface."""
        name_lower = iface_name.lower()
        
        if name_lower.startswith("lo"):
            return "loopback"
        elif name_lower.startswith(("eth", "enp", "ens", "eno")):
            return "ethernet"
        elif name_lower.startswith(("wlan", "wlp", "wifi")):
            return "wireless"
        elif name_lower.startswith(("docker", "br-")):
            return "docker"
        elif name_lower.startswith("veth"):
            return "virtual"
        elif name_lower.startswith(("virbr", "vnet")):
            return "virtual_bridge"
        elif name_lower.startswith("tun"):
            return "tunnel"
        elif name_lower.startswith("tap"):
            return "tap"
        else:
            return "other"
    
    def _detect_active_interface(self) -> None:
        """Detect the primary active network interface."""
        try:
            # Try to get the interface used for default route
            if NETIFACES_AVAILABLE:
                gateways = netifaces.gateways()
                if "default" in gateways and netifaces.AF_INET in gateways["default"]:
                    self._active_interface = gateways["default"][netifaces.AF_INET][1]
                    return
            
            # Fallback: find first non-loopback interface with IP
            for name, iface in self._interfaces.items():
                if iface.is_up and not iface.is_loopback and iface.ip_address:
                    self._active_interface = name
                    return
        
        except Exception as e:
            logger.error(f"Failed to detect active interface: {e}")
    
    def get_available_interfaces(self) -> List[NetworkInterface]:
        """
        Get all available network interfaces.
        
        Returns:
            List of NetworkInterface objects.
        """
        return list(self._interfaces.values())
    
    def get_scannable_interfaces(self) -> List[NetworkInterface]:
        """
        Get interfaces suitable for network scanning.
        
        Excludes loopback and down interfaces.
        
        Returns:
            List of NetworkInterface objects suitable for scanning.
        """
        return [
            iface for iface in self._interfaces.values()
            if iface.is_up and not iface.is_loopback and iface.ip_address
        ]
    
    def get_active_interface(self) -> Optional[str]:
        """
        Get the name of the currently active (primary) interface.
        
        Returns:
            Interface name or None if no active interface.
        """
        return self._active_interface
    
    def get_interface(self, name: str) -> Optional[NetworkInterface]:
        """
        Get a specific interface by name.
        
        Args:
            name: Interface name (e.g., 'eth0', 'wlan0').
            
        Returns:
            NetworkInterface object or None if not found.
        """
        return self._interfaces.get(name)
    
    def get_interface_details(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about an interface.
        
        Args:
            name: Interface name.
            
        Returns:
            Dictionary with interface details or None.
        """
        iface = self.get_interface(name)
        if iface:
            return iface.to_dict()
        return None
    
    def set_interface(self, name: str) -> bool:
        """
        Set the active interface for scanning.
        
        Args:
            name: Interface name to set as active.
            
        Returns:
            True if successful, False otherwise.
        """
        if name in self._interfaces:
            iface = self._interfaces[name]
            if iface.is_up and not iface.is_loopback:
                self._active_interface = name
                logger.info(f"Active interface set to: {name}")
                return True
            else:
                logger.warning(f"Interface {name} is not suitable for scanning")
                return False
        else:
            logger.error(f"Interface {name} not found")
            return False
    
    def refresh(self) -> None:
        """Refresh the interface list."""
        self._refresh_interfaces()
        logger.info("Interface list refreshed")
    
    def get_interfaces_by_type(self, interface_type: str) -> List[NetworkInterface]:
        """
        Get interfaces filtered by type.
        
        Args:
            interface_type: Type to filter by (ethernet, wireless, etc.).
            
        Returns:
            List of matching NetworkInterface objects.
        """
        return [
            iface for iface in self._interfaces.values()
            if iface.interface_type == interface_type
        ]
    
    def get_interface_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all interfaces.
        
        Returns:
            Dictionary with interface counts and active interface.
        """
        return {
            "total": len(self._interfaces),
            "active": self._active_interface,
            "up_count": sum(1 for i in self._interfaces.values() if i.is_up),
            "wireless_count": sum(1 for i in self._interfaces.values() if i.is_wireless),
            "ethernet_count": sum(1 for i in self._interfaces.values() if i.interface_type == "ethernet"),
            "interfaces": [i.to_dict() for i in self._interfaces.values()],
        }
