"""
Device Fingerprinting Module.

Provides device type identification based on various characteristics
including open ports, services, OS information, and vendor data.
"""

from typing import Optional, Dict, List, Any, TYPE_CHECKING
from dataclasses import dataclass
from loguru import logger

if TYPE_CHECKING:
    from .base_scanner import DeviceInfo


@dataclass
class DeviceProfile:
    """Represents a device profile for fingerprinting."""
    device_type: str
    description: str
    common_ports: List[int]
    common_services: List[str]
    vendor_patterns: List[str]
    os_patterns: List[str]
    priority: int = 0


class DeviceFingerprinter:
    """
    Identifies device types based on network characteristics.
    
    Uses a combination of:
    - Open ports and services
    - OS fingerprinting results
    - Vendor/manufacturer information
    - MAC address OUI patterns
    """
    
    # Device profiles for fingerprinting
    DEVICE_PROFILES = [
        DeviceProfile(
            device_type="router",
            description="Network Router/Gateway",
            common_ports=[22, 23, 53, 80, 443, 161],
            common_services=["ssh", "telnet", "domain", "http", "https", "snmp"],
            vendor_patterns=["cisco", "netgear", "asus", "d-link", "tp-link", 
                           "linksys", "mikrotik", "ubiquiti", "juniper"],
            os_patterns=["routeros", "ios", "junos", "openwrt", "dd-wrt", "tomato"],
            priority=10,
        ),
        DeviceProfile(
            device_type="switch",
            description="Network Switch",
            common_ports=[22, 23, 80, 161, 443],
            common_services=["ssh", "telnet", "http", "snmp"],
            vendor_patterns=["cisco", "hp", "dell", "netgear", "aruba", "juniper"],
            os_patterns=["ios", "comware", "procurve"],
            priority=9,
        ),
        DeviceProfile(
            device_type="access_point",
            description="Wireless Access Point",
            common_ports=[22, 23, 80, 443, 8080],
            common_services=["ssh", "telnet", "http", "https"],
            vendor_patterns=["ubiquiti", "cisco", "aruba", "ruckus", "unifi", 
                           "tp-link", "netgear"],
            os_patterns=["airmax", "unifi"],
            priority=8,
        ),
        DeviceProfile(
            device_type="camera",
            description="IP Camera/NVR",
            common_ports=[80, 443, 554, 8080, 8000, 8443, 37777],
            common_services=["http", "https", "rtsp"],
            vendor_patterns=["hikvision", "dahua", "axis", "foscam", "reolink",
                           "amcrest", "lorex", "swann", "vivotek", "hanwha",
                           "bosch", "geovision"],
            os_patterns=["embedded", "linux"],
            priority=7,
        ),
        DeviceProfile(
            device_type="nas",
            description="Network Attached Storage",
            common_ports=[22, 80, 139, 443, 445, 548, 5000, 5001, 8080, 9000],
            common_services=["ssh", "http", "netbios-ssn", "microsoft-ds", "afp"],
            vendor_patterns=["synology", "qnap", "buffalo", "netgear", "western digital",
                           "asustor", "drobo", "wd"],
            os_patterns=["dsm", "qts", "linux"],
            priority=7,
        ),
        DeviceProfile(
            device_type="printer",
            description="Network Printer/MFP",
            common_ports=[80, 443, 515, 631, 9100],
            common_services=["http", "ipp", "printer", "jetdirect"],
            vendor_patterns=["hp", "canon", "epson", "brother", "xerox", "lexmark",
                           "ricoh", "kyocera", "samsung", "dell"],
            os_patterns=["jetdirect", "cups"],
            priority=6,
        ),
        DeviceProfile(
            device_type="smart_tv",
            description="Smart TV/Media Device",
            common_ports=[8008, 8443, 9080, 1925, 3000, 8001, 9000],
            common_services=["http", "https", "upnp"],
            vendor_patterns=["samsung", "lg", "sony", "vizio", "tcl", "hisense",
                           "philips", "roku", "amazon", "apple"],
            os_patterns=["tizen", "webos", "android", "tvos"],
            priority=5,
        ),
        DeviceProfile(
            device_type="media_player",
            description="Media Streaming Device",
            common_ports=[8008, 8060, 8443, 9080],
            common_services=["http", "upnp", "dlna"],
            vendor_patterns=["roku", "amazon", "apple", "google", "nvidia", "chromecast"],
            os_patterns=["android", "fire", "tvos"],
            priority=5,
        ),
        DeviceProfile(
            device_type="smart_speaker",
            description="Smart Speaker/Voice Assistant",
            common_ports=[8008, 8443, 8080],
            common_services=["http", "https"],
            vendor_patterns=["amazon", "google", "apple", "sonos", "bose"],
            os_patterns=["fire", "cast", "airplay"],
            priority=5,
        ),
        DeviceProfile(
            device_type="smart_home_hub",
            description="Smart Home Hub/Controller",
            common_ports=[80, 443, 8080, 8123, 1900],
            common_services=["http", "https", "upnp"],
            vendor_patterns=["philips", "samsung", "hubitat", "wink", "smartthings",
                           "home assistant", "vera"],
            os_patterns=["linux", "embedded"],
            priority=5,
        ),
        DeviceProfile(
            device_type="thermostat",
            description="Smart Thermostat",
            common_ports=[80, 443, 8080],
            common_services=["http", "https"],
            vendor_patterns=["nest", "ecobee", "honeywell", "emerson"],
            os_patterns=["embedded", "linux"],
            priority=4,
        ),
        DeviceProfile(
            device_type="game_console",
            description="Gaming Console",
            common_ports=[80, 443, 3074, 3478, 3479, 3480],
            common_services=["http", "https"],
            vendor_patterns=["sony", "microsoft", "nintendo"],
            os_patterns=["playstation", "xbox", "switch"],
            priority=4,
        ),
        DeviceProfile(
            device_type="voip_phone",
            description="VoIP Phone",
            common_ports=[80, 443, 5060, 5061],
            common_services=["http", "sip"],
            vendor_patterns=["cisco", "polycom", "yealink", "grandstream", "avaya",
                           "mitel", "snom", "fanvil"],
            os_patterns=["sip", "voip"],
            priority=4,
        ),
        DeviceProfile(
            device_type="server",
            description="Server",
            common_ports=[22, 25, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080],
            common_services=["ssh", "smtp", "http", "pop3", "imap", "https", 
                           "mysql", "postgresql"],
            vendor_patterns=["dell", "hp", "supermicro", "lenovo", "ibm"],
            os_patterns=["linux", "ubuntu", "centos", "debian", "rhel", 
                        "windows server", "freebsd"],
            priority=6,
        ),
        DeviceProfile(
            device_type="workstation",
            description="Desktop/Workstation",
            common_ports=[22, 135, 139, 445, 3389, 5900],
            common_services=["ssh", "msrpc", "netbios-ssn", "microsoft-ds", 
                           "ms-wbt-server", "vnc"],
            vendor_patterns=["dell", "hp", "lenovo", "asus", "acer", "apple"],
            os_patterns=["windows 10", "windows 11", "macos", "ubuntu", "fedora"],
            priority=3,
        ),
        DeviceProfile(
            device_type="mobile",
            description="Mobile Device",
            common_ports=[62078, 5000],
            common_services=["iphone-sync"],
            vendor_patterns=["apple", "samsung", "google", "huawei", "xiaomi", 
                           "oneplus", "oppo", "vivo"],
            os_patterns=["ios", "android", "iphone", "ipad"],
            priority=3,
        ),
        DeviceProfile(
            device_type="iot_sensor",
            description="IoT Sensor/Device",
            common_ports=[80, 443, 1883, 8883],
            common_services=["http", "mqtt"],
            vendor_patterns=["espressif", "arduino", "particle", "nordic"],
            os_patterns=["freertos", "embedded", "esp"],
            priority=4,
        ),
        DeviceProfile(
            device_type="smart_plug",
            description="Smart Plug/Outlet",
            common_ports=[80, 443, 9999],
            common_services=["http"],
            vendor_patterns=["tp-link", "kasa", "wemo", "gosund", "wyze"],
            os_patterns=["embedded"],
            priority=3,
        ),
        DeviceProfile(
            device_type="raspberry_pi",
            description="Raspberry Pi",
            common_ports=[22, 80, 443],
            common_services=["ssh", "http"],
            vendor_patterns=["raspberry pi", "raspberry"],
            os_patterns=["raspbian", "raspberry pi os", "linux"],
            priority=5,
        ),
    ]
    
    def __init__(self):
        """Initialize the DeviceFingerprinter."""
        # Sort profiles by priority (higher priority first)
        self._profiles = sorted(
            self.DEVICE_PROFILES, 
            key=lambda p: p.priority, 
            reverse=True
        )
    
    def identify_device_type(self, device: "DeviceInfo") -> str:
        """
        Identify the type of a device.
        
        Args:
            device: DeviceInfo object with scan results.
        
        Returns:
            Device type string or 'unknown'.
        """
        scores: Dict[str, float] = {}
        
        for profile in self._profiles:
            score = self._calculate_profile_score(device, profile)
            if score > 0:
                scores[profile.device_type] = score
        
        if not scores:
            return "unknown"
        
        # Return the device type with the highest score
        best_match = max(scores.items(), key=lambda x: x[1])
        
        # Only return if confidence is reasonable
        if best_match[1] >= 2.0:
            logger.debug(f"Device {device.ip_address} identified as {best_match[0]} "
                        f"(score: {best_match[1]:.2f})")
            return best_match[0]
        
        return "unknown"
    
    def _calculate_profile_score(
        self, 
        device: "DeviceInfo", 
        profile: DeviceProfile
    ) -> float:
        """Calculate how well a device matches a profile."""
        score = 0.0
        
        # Check ports (weight: 1.0 per matching port)
        device_ports = set(device.get_open_ports())
        profile_ports = set(profile.common_ports)
        matching_ports = device_ports & profile_ports
        if matching_ports:
            score += len(matching_ports) * 1.0
        
        # Check services (weight: 1.5 per matching service)
        device_services = set(
            p.service.lower() for p in device.ports if p.service
        )
        profile_services = set(s.lower() for s in profile.common_services)
        matching_services = device_services & profile_services
        if matching_services:
            score += len(matching_services) * 1.5
        
        # Check vendor (weight: 3.0 for matching vendor)
        if device.vendor:
            vendor_lower = device.vendor.lower()
            for pattern in profile.vendor_patterns:
                if pattern.lower() in vendor_lower:
                    score += 3.0
                    break
        
        # Check manufacturer
        if device.manufacturer and device.manufacturer != device.vendor:
            mfr_lower = device.manufacturer.lower()
            for pattern in profile.vendor_patterns:
                if pattern.lower() in mfr_lower:
                    score += 2.0
                    break
        
        # Check OS info (weight: 2.5 for matching OS)
        if device.os_info:
            os_lower = device.os_info.lower()
            for pattern in profile.os_patterns:
                if pattern.lower() in os_lower:
                    score += 2.5
                    break
        
        # Check hostname/device name for clues
        name = device.device_name or device.hostname or ""
        if name:
            name_lower = name.lower()
            for pattern in profile.vendor_patterns + profile.os_patterns:
                if pattern.lower() in name_lower:
                    score += 1.5
                    break
        
        return score
    
    def get_device_profile(self, device_type: str) -> Optional[DeviceProfile]:
        """Get the profile for a device type."""
        for profile in self._profiles:
            if profile.device_type == device_type:
                return profile
        return None
    
    def get_all_device_types(self) -> List[str]:
        """Get list of all known device types."""
        return [p.device_type for p in self._profiles]
    
    def get_common_ports_for_type(self, device_type: str) -> List[int]:
        """Get common ports for a device type."""
        profile = self.get_device_profile(device_type)
        if profile:
            return profile.common_ports
        return []
    
    def analyze_device(self, device: "DeviceInfo") -> Dict[str, Any]:
        """
        Perform detailed device analysis.
        
        Args:
            device: DeviceInfo object to analyze.
        
        Returns:
            Dictionary with analysis results.
        """
        device_type = self.identify_device_type(device)
        profile = self.get_device_profile(device_type)
        
        # Calculate confidence scores for all types
        type_scores = {}
        for p in self._profiles:
            score = self._calculate_profile_score(device, p)
            if score > 0:
                type_scores[p.device_type] = score
        
        # Sort by score
        sorted_scores = sorted(type_scores.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "ip_address": device.ip_address,
            "identified_type": device_type,
            "confidence": type_scores.get(device_type, 0),
            "alternative_types": sorted_scores[:3],
            "open_ports": device.get_open_ports(),
            "services": [p.service for p in device.ports if p.service],
            "vendor": device.vendor,
            "os_info": device.os_info,
            "profile_description": profile.description if profile else None,
        }
    
    def classify_devices(
        self, 
        devices: List["DeviceInfo"]
    ) -> Dict[str, List["DeviceInfo"]]:
        """
        Classify a list of devices by type.
        
        Args:
            devices: List of DeviceInfo objects.
        
        Returns:
            Dictionary mapping device types to lists of devices.
        """
        classified: Dict[str, List["DeviceInfo"]] = {}
        
        for device in devices:
            device_type = self.identify_device_type(device)
            if device_type not in classified:
                classified[device_type] = []
            classified[device_type].append(device)
        
        return classified
    
    def get_classification_summary(
        self, 
        devices: List["DeviceInfo"]
    ) -> Dict[str, int]:
        """
        Get a summary count of device types.
        
        Args:
            devices: List of DeviceInfo objects.
        
        Returns:
            Dictionary mapping device types to counts.
        """
        classified = self.classify_devices(devices)
        return {k: len(v) for k, v in classified.items()}
