"""
Pytest configuration and fixtures.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def mock_nmap():
    """Mock nmap module."""
    mock = MagicMock()
    mock.PortScanner.return_value = MagicMock()
    return mock


@pytest.fixture
def mock_netifaces():
    """Mock netifaces module."""
    mock = MagicMock()
    mock.interfaces.return_value = ["eth0", "wlan0", "lo"]
    mock.AF_INET = 2
    mock.AF_LINK = 17
    return mock


@pytest.fixture
def sample_scan_result():
    """Sample scan result for testing."""
    return {
        "scan_id": "SCAN_20240101_120000",
        "cidr": "192.168.1.0/24",
        "interface": "eth0",
        "scan_type": "quick",
        "status": "completed",
        "devices": [
            {
                "ip_address": "192.168.1.1",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "vendor": "Netgear",
                "device_type": "router",
                "hostname": "router.local",
                "ports": [
                    {"port": 22, "service": "ssh", "state": "open"},
                    {"port": 80, "service": "http", "state": "open"},
                ],
            },
            {
                "ip_address": "192.168.1.100",
                "mac_address": "11:22:33:44:55:66",
                "vendor": "HP",
                "device_type": "printer",
                "hostname": "printer.local",
                "ports": [
                    {"port": 9100, "service": "jetdirect", "state": "open"},
                ],
            },
        ],
    }


@pytest.fixture
def sample_device_info():
    """Sample device info for testing."""
    from soc_iot_toolkit.scanners.base_scanner import DeviceInfo, PortInfo
    
    return DeviceInfo(
        ip_address="192.168.1.1",
        mac_address="AA:BB:CC:DD:EE:FF",
        vendor="TestVendor",
        hostname="test.local",
        ports=[
            PortInfo(port_number=22, service="ssh", state="open"),
            PortInfo(port_number=80, service="http", state="open"),
        ],
    )


@pytest.fixture
def temp_database(tmp_path):
    """Create temporary SQLite database for testing."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from soc_iot_toolkit.database.models import Base
    
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    
    Session = sessionmaker(bind=engine)
    session = Session()
    
    yield session
    
    session.close()
    engine.dispose()
