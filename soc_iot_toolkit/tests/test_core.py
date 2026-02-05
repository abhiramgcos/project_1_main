"""
Tests for core modules.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from ipaddress import ip_network

from soc_iot_toolkit.core.cidr_manager import CIDRManager


class TestCIDRManager:
    """Tests for CIDRManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.manager = CIDRManager()
    
    def test_validate_cidr_valid(self):
        """Test valid CIDR validation."""
        assert self.manager.validate_cidr("192.168.1.0/24") is True
        assert self.manager.validate_cidr("10.0.0.0/8") is True
        assert self.manager.validate_cidr("172.16.0.0/16") is True
    
    def test_validate_cidr_invalid(self):
        """Test invalid CIDR validation."""
        assert self.manager.validate_cidr("invalid") is False
        assert self.manager.validate_cidr("192.168.1.0/33") is False
        assert self.manager.validate_cidr("") is False
    
    def test_get_host_count(self):
        """Test host count calculation."""
        assert self.manager.get_host_count("192.168.1.0/24") == 254
        assert self.manager.get_host_count("192.168.1.0/30") == 2
        assert self.manager.get_host_count("192.168.1.0/32") == 1
    
    def test_get_host_count_invalid(self):
        """Test host count with invalid CIDR."""
        assert self.manager.get_host_count("invalid") == 0
    
    def test_get_network_info(self):
        """Test network info retrieval."""
        info = self.manager.get_network_info("192.168.1.0/24")
        
        assert "network" in info
        assert "broadcast" in info
        assert "netmask" in info
        assert "host_count" in info
        assert info["host_count"] == 254
    
    def test_is_private_network(self):
        """Test private network detection."""
        assert self.manager.is_private_network("192.168.1.0/24") is True
        assert self.manager.is_private_network("10.0.0.0/8") is True
        assert self.manager.is_private_network("172.16.0.0/16") is True
        assert self.manager.is_private_network("8.8.8.0/24") is False


class TestInterfaceManager:
    """Tests for InterfaceManager class."""
    
    @patch("soc_iot_toolkit.core.interface_manager.netifaces")
    def test_get_available_interfaces(self, mock_netifaces):
        """Test interface detection."""
        from soc_iot_toolkit.core.interface_manager import InterfaceManager
        
        mock_netifaces.interfaces.return_value = ["eth0", "lo", "wlan0"]
        mock_netifaces.ifaddresses.return_value = {
            mock_netifaces.AF_INET: [{"addr": "192.168.1.100"}]
        }
        mock_netifaces.AF_INET = 2
        mock_netifaces.AF_LINK = 17
        
        manager = InterfaceManager()
        interfaces = manager.get_available_interfaces()
        
        assert isinstance(interfaces, list)
    
    @patch("soc_iot_toolkit.core.interface_manager.netifaces")
    def test_filter_loopback(self, mock_netifaces):
        """Test loopback filtering."""
        from soc_iot_toolkit.core.interface_manager import InterfaceManager
        
        mock_netifaces.interfaces.return_value = ["eth0", "lo"]
        mock_netifaces.AF_INET = 2
        mock_netifaces.AF_LINK = 17
        
        manager = InterfaceManager()
        scannable = manager.get_scannable_interfaces()
        
        # Should filter out loopback
        for iface in scannable:
            assert iface.get("name") != "lo"


class TestProcessManager:
    """Tests for ProcessManager class."""
    
    def test_initialization(self):
        """Test ProcessManager initialization."""
        from soc_iot_toolkit.core.process_manager import ProcessManager
        
        manager = ProcessManager()
        assert manager.running_processes == {}
    
    def test_is_running_not_started(self):
        """Test is_running for non-existent process."""
        from soc_iot_toolkit.core.process_manager import ProcessManager
        
        manager = ProcessManager()
        assert manager.is_running("nonexistent") is False
    
    @patch("subprocess.Popen")
    def test_start_process(self, mock_popen):
        """Test process starting."""
        from soc_iot_toolkit.core.process_manager import ProcessManager
        
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process
        
        manager = ProcessManager()
        result = manager.start_process("test", ["echo", "test"])
        
        assert result is True
        assert manager.is_running("test") is True
    
    def test_stop_nonexistent_process(self):
        """Test stopping non-existent process."""
        from soc_iot_toolkit.core.process_manager import ProcessManager
        
        manager = ProcessManager()
        # Should not raise exception
        manager.stop_process("nonexistent")


class TestValidators:
    """Tests for validator utilities."""
    
    def test_validate_ip_address(self):
        """Test IP address validation."""
        from soc_iot_toolkit.utils.validators import validate_ip_address
        
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("10.0.0.1") is True
        assert validate_ip_address("256.1.1.1") is False
        assert validate_ip_address("invalid") is False
    
    def test_validate_mac_address(self):
        """Test MAC address validation."""
        from soc_iot_toolkit.utils.validators import validate_mac_address
        
        assert validate_mac_address("AA:BB:CC:DD:EE:FF") is True
        assert validate_mac_address("aa:bb:cc:dd:ee:ff") is True
        assert validate_mac_address("AA-BB-CC-DD-EE-FF") is True
        assert validate_mac_address("invalid") is False
    
    def test_validate_port(self):
        """Test port number validation."""
        from soc_iot_toolkit.utils.validators import validate_port
        
        assert validate_port(22) is True
        assert validate_port(80) is True
        assert validate_port(65535) is True
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False


class TestLogger:
    """Tests for logger utility."""
    
    def test_logger_initialization(self):
        """Test logger initialization."""
        from soc_iot_toolkit.utils.logger import get_logger
        
        logger = get_logger("test")
        assert logger is not None
    
    def test_logger_levels(self):
        """Test logger level methods exist."""
        from soc_iot_toolkit.utils.logger import get_logger
        
        logger = get_logger("test")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")


class TestExporters:
    """Tests for export utilities."""
    
    def test_csv_export(self):
        """Test CSV export."""
        from soc_iot_toolkit.utils.exporters import export_to_csv
        
        devices = [
            {
                "ip_address": "192.168.1.1",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "vendor": "TestVendor",
            }
        ]
        
        csv_data = export_to_csv(devices)
        assert "ip_address" in csv_data
        assert "192.168.1.1" in csv_data
    
    def test_json_export(self):
        """Test JSON export."""
        from soc_iot_toolkit.utils.exporters import export_to_json
        
        devices = [
            {
                "ip_address": "192.168.1.1",
                "mac_address": "AA:BB:CC:DD:EE:FF",
            }
        ]
        
        json_data = export_to_json(devices)
        assert "192.168.1.1" in json_data
        assert "AA:BB:CC:DD:EE:FF" in json_data
