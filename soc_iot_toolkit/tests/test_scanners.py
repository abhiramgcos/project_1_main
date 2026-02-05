"""
Tests for scanner modules.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from soc_iot_toolkit.scanners.base_scanner import (
    BaseScanner, ScanResult, DeviceInfo, PortInfo, ScanType
)
from soc_iot_toolkit.scanners.vendor_lookup import VendorLookup
from soc_iot_toolkit.scanners.device_fingerprint import DeviceFingerprinter


class TestVendorLookup:
    """Tests for VendorLookup class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.lookup = VendorLookup()
    
    def test_normalize_mac(self):
        """Test MAC address normalization."""
        # Test various formats
        assert self.lookup._normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
        assert self.lookup._normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"
        assert self.lookup._normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"
    
    def test_get_oui(self):
        """Test OUI extraction."""
        oui = self.lookup._get_oui("AA:BB:CC:DD:EE:FF")
        assert oui == "AA:BB:CC"
    
    def test_known_vendor_lookup(self):
        """Test lookup of known vendors."""
        # Raspberry Pi
        vendor = self.lookup.get_vendor("B8:27:EB:00:00:00")
        assert "Raspberry Pi" in vendor
        
        # Apple
        vendor = self.lookup.get_vendor("18:AF:8F:00:00:00")
        assert "Apple" in vendor
    
    def test_unknown_vendor(self):
        """Test lookup of unknown vendor."""
        vendor = self.lookup.get_vendor("00:00:00:00:00:00")
        assert vendor == "Unknown"
    
    def test_empty_mac(self):
        """Test handling of empty MAC."""
        vendor = self.lookup.get_vendor("")
        assert vendor == "Unknown"
    
    def test_get_vendor_info(self):
        """Test vendor info retrieval."""
        info = self.lookup.get_vendor_info("B8:27:EB:00:00:00")
        assert "mac_address" in info
        assert "oui" in info
        assert "vendor" in info
        assert info["is_known"] is True


class TestDeviceFingerprinter:
    """Tests for DeviceFingerprinter class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.fingerprinter = DeviceFingerprinter()
    
    def test_identify_router(self):
        """Test router identification."""
        device = DeviceInfo(
            ip_address="192.168.1.1",
            vendor="Netgear",
            ports=[
                PortInfo(port_number=22, service="ssh"),
                PortInfo(port_number=80, service="http"),
                PortInfo(port_number=443, service="https"),
            ]
        )
        
        device_type = self.fingerprinter.identify_device_type(device)
        assert device_type == "router"
    
    def test_identify_camera(self):
        """Test camera identification."""
        device = DeviceInfo(
            ip_address="192.168.1.50",
            vendor="Hikvision",
            ports=[
                PortInfo(port_number=80, service="http"),
                PortInfo(port_number=554, service="rtsp"),
            ]
        )
        
        device_type = self.fingerprinter.identify_device_type(device)
        assert device_type == "camera"
    
    def test_identify_printer(self):
        """Test printer identification."""
        device = DeviceInfo(
            ip_address="192.168.1.100",
            vendor="HP",
            ports=[
                PortInfo(port_number=80, service="http"),
                PortInfo(port_number=9100, service="jetdirect"),
                PortInfo(port_number=631, service="ipp"),
            ]
        )
        
        device_type = self.fingerprinter.identify_device_type(device)
        assert device_type == "printer"
    
    def test_identify_unknown(self):
        """Test unknown device."""
        device = DeviceInfo(
            ip_address="192.168.1.200",
        )
        
        device_type = self.fingerprinter.identify_device_type(device)
        assert device_type == "unknown"
    
    def test_classify_devices(self):
        """Test device classification."""
        devices = [
            DeviceInfo(ip_address="192.168.1.1", vendor="Netgear"),
            DeviceInfo(ip_address="192.168.1.2", vendor="Netgear"),
            DeviceInfo(ip_address="192.168.1.3", vendor="HP"),
        ]
        
        classified = self.fingerprinter.classify_devices(devices)
        assert isinstance(classified, dict)


class TestScanResult:
    """Tests for ScanResult class."""
    
    def test_scan_result_creation(self):
        """Test ScanResult creation."""
        result = ScanResult(
            scan_id="SCAN_20240101_120000",
            cidr="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
        )
        
        assert result.scan_id == "SCAN_20240101_120000"
        assert result.cidr == "192.168.1.0/24"
        assert result.status == "completed"
    
    def test_scan_result_to_dict(self):
        """Test ScanResult serialization."""
        result = ScanResult(
            scan_id="SCAN_20240101_120000",
            cidr="192.168.1.0/24",
            interface="eth0",
            start_time=datetime.now(),
            end_time=datetime.now(),
        )
        
        data = result.to_dict()
        assert "scan_id" in data
        assert "cidr" in data
        assert "duration_seconds" in data
    
    def test_device_info_creation(self):
        """Test DeviceInfo creation."""
        device = DeviceInfo(
            ip_address="192.168.1.1",
            mac_address="AA:BB:CC:DD:EE:FF",
            vendor="TestVendor",
        )
        
        assert device.ip_address == "192.168.1.1"
        assert device.mac_address == "AA:BB:CC:DD:EE:FF"
    
    def test_port_info_creation(self):
        """Test PortInfo creation."""
        port = PortInfo(
            port_number=22,
            protocol="tcp",
            state="open",
            service="ssh",
        )
        
        assert port.port_number == 22
        assert port.service == "ssh"


class TestNmapScanner:
    """Tests for NmapScanner class."""
    
    def test_nmap_installed(self):
        """Test Nmap installation check."""
        from soc_iot_toolkit.scanners.nmap_scanner import NmapScanner
        
        # This test depends on system configuration
        result = NmapScanner.check_nmap_installed()
        assert isinstance(result, bool)
    
    def test_scan_arguments(self):
        """Test scan argument generation."""
        from soc_iot_toolkit.scanners.nmap_scanner import NmapScanner
        
        scanner = NmapScanner(
            cidr="192.168.1.0/24",
            interface="eth0",
            scan_type=ScanType.QUICK,
        )
        
        args = scanner.get_scan_arguments()
        assert "-e eth0" in args
        assert "-sn" in args  # Quick scan uses -sn
