"""
Base Scanner Module.

Provides abstract base class for all scanner implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from enum import Enum


class ScanType(Enum):
    """Enumeration of scan types."""
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    FULL = "full"
    CUSTOM = "custom"


@dataclass
class PortInfo:
    """Represents information about an open port."""
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "port_number": self.port_number,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "product": self.product,
            "extra_info": self.extra_info,
        }


@dataclass
class DeviceInfo:
    """Represents information about a discovered device."""
    ip_address: str
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    manufacturer: Optional[str] = None
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    os_info: Optional[str] = None
    os_accuracy: int = 0
    hostname: Optional[str] = None
    ports: List[PortInfo] = field(default_factory=list)
    status: str = "up"
    last_seen: Optional[datetime] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "manufacturer": self.manufacturer,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "os_info": self.os_info,
            "os_accuracy": self.os_accuracy,
            "hostname": self.hostname,
            "ports": [p.to_dict() for p in self.ports],
            "status": self.status,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }
    
    def get_open_ports(self) -> List[int]:
        """Get list of open port numbers."""
        return [p.port_number for p in self.ports if p.state == "open"]
    
    def has_port(self, port: int) -> bool:
        """Check if device has a specific port open."""
        return port in self.get_open_ports()


@dataclass
class ScanResult:
    """Represents the result of a network scan."""
    scan_id: str
    cidr: str
    interface: str
    start_time: datetime
    end_time: Optional[datetime] = None
    devices: List[DeviceInfo] = field(default_factory=list)
    total_hosts_scanned: int = 0
    hosts_up: int = 0
    scan_type: ScanType = ScanType.STANDARD
    scan_arguments: str = ""
    status: str = "completed"
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "scan_id": self.scan_id,
            "cidr": self.cidr,
            "interface": self.interface,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "devices": [d.to_dict() for d in self.devices],
            "total_hosts_scanned": self.total_hosts_scanned,
            "hosts_up": self.hosts_up,
            "scan_type": self.scan_type.value,
            "scan_arguments": self.scan_arguments,
            "status": self.status,
            "error_message": self.error_message,
            "duration_seconds": self.get_duration(),
        }
    
    def get_duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    def get_devices_by_type(self, device_type: str) -> List[DeviceInfo]:
        """Get devices filtered by type."""
        return [d for d in self.devices if d.device_type == device_type]
    
    def get_devices_with_port(self, port: int) -> List[DeviceInfo]:
        """Get devices with a specific port open."""
        return [d for d in self.devices if d.has_port(port)]


class BaseScanner(ABC):
    """
    Abstract base class for network scanners.
    
    All scanner implementations must inherit from this class
    and implement the required abstract methods.
    """
    
    def __init__(
        self,
        cidr: str,
        interface: Optional[str] = None,
        scan_type: ScanType = ScanType.STANDARD,
    ):
        """
        Initialize the scanner.
        
        Args:
            cidr: CIDR range to scan.
            interface: Network interface to use.
            scan_type: Type of scan to perform.
        """
        self._cidr = cidr
        self._interface = interface
        self._scan_type = scan_type
        self._progress: float = 0.0
        self._is_running: bool = False
        self._is_cancelled: bool = False
        self._progress_callback: Optional[Callable] = None
    
    @property
    def cidr(self) -> str:
        """Get the target CIDR range."""
        return self._cidr
    
    @property
    def interface(self) -> Optional[str]:
        """Get the network interface."""
        return self._interface
    
    @property
    def scan_type(self) -> ScanType:
        """Get the scan type."""
        return self._scan_type
    
    @property
    def progress(self) -> float:
        """Get the current scan progress (0-100)."""
        return self._progress
    
    @property
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self._is_running
    
    @abstractmethod
    def execute_scan(
        self,
        progress_callback: Optional[Callable[[float, int], None]] = None,
        **kwargs
    ) -> ScanResult:
        """
        Execute the network scan.
        
        Args:
            progress_callback: Optional callback for progress updates.
                              Receives (progress_percentage, hosts_scanned).
            **kwargs: Additional scan options.
        
        Returns:
            ScanResult object with discovered devices.
        """
        pass
    
    @abstractmethod
    def cancel_scan(self) -> bool:
        """
        Cancel a running scan.
        
        Returns:
            True if cancellation was successful.
        """
        pass
    
    @abstractmethod
    def get_scan_arguments(self) -> str:
        """
        Get the command-line arguments for the scan.
        
        Returns:
            String of scan arguments.
        """
        pass
    
    def _update_progress(self, progress: float, hosts_scanned: int = 0) -> None:
        """Update scan progress and notify callback."""
        self._progress = min(100.0, max(0.0, progress))
        if self._progress_callback:
            self._progress_callback(self._progress, hosts_scanned)
    
    def validate_cidr(self) -> bool:
        """Validate the CIDR range."""
        import ipaddress
        try:
            ipaddress.IPv4Network(self._cidr, strict=False)
            return True
        except ValueError:
            return False
    
    def get_host_count(self) -> int:
        """Get the number of hosts in the CIDR range."""
        import ipaddress
        try:
            network = ipaddress.IPv4Network(self._cidr, strict=False)
            return max(0, network.num_addresses - 2)
        except ValueError:
            return 0
