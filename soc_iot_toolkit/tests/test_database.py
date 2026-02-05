"""
Tests for database modules.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from soc_iot_toolkit.database.models import Base, Scan, Device, Port


class TestModels:
    """Tests for database models."""
    
    @pytest.fixture
    def engine(self):
        """Create test database engine."""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        return engine
    
    @pytest.fixture
    def session(self, engine):
        """Create test database session."""
        Session = sessionmaker(bind=engine)
        session = Session()
        yield session
        session.close()
    
    def test_scan_creation(self, session):
        """Test Scan model creation."""
        scan = Scan(
            scan_id="SCAN_20240101_120000",
            cidr="192.168.1.0/24",
            interface="eth0",
            scan_type="quick",
            status="completed",
            start_time=datetime.now(),
            end_time=datetime.now(),
        )
        
        session.add(scan)
        session.commit()
        
        retrieved = session.query(Scan).first()
        assert retrieved.scan_id == "SCAN_20240101_120000"
        assert retrieved.cidr == "192.168.1.0/24"
    
    def test_device_creation(self, session):
        """Test Device model creation."""
        scan = Scan(
            scan_id="SCAN_20240101_120000",
            cidr="192.168.1.0/24",
            interface="eth0",
            scan_type="quick",
            status="completed",
            start_time=datetime.now(),
        )
        session.add(scan)
        session.commit()
        
        device = Device(
            scan_id=scan.id,
            ip_address="192.168.1.1",
            mac_address="AA:BB:CC:DD:EE:FF",
            vendor="TestVendor",
            device_type="router",
        )
        
        session.add(device)
        session.commit()
        
        retrieved = session.query(Device).first()
        assert retrieved.ip_address == "192.168.1.1"
        assert retrieved.vendor == "TestVendor"
    
    def test_port_creation(self, session):
        """Test Port model creation."""
        scan = Scan(
            scan_id="SCAN_20240101_120000",
            cidr="192.168.1.0/24",
            interface="eth0",
            scan_type="quick",
            status="completed",
            start_time=datetime.now(),
        )
        session.add(scan)
        session.commit()
        
        device = Device(
            scan_id=scan.id,
            ip_address="192.168.1.1",
        )
        session.add(device)
        session.commit()
        
        port = Port(
            device_id=device.id,
            port_number=22,
            protocol="tcp",
            state="open",
            service="ssh",
        )
        
        session.add(port)
        session.commit()
        
        retrieved = session.query(Port).first()
        assert retrieved.port_number == 22
        assert retrieved.service == "ssh"
    
    def test_scan_device_relationship(self, session):
        """Test Scan-Device relationship."""
        scan = Scan(
            scan_id="SCAN_20240101_120000",
            cidr="192.168.1.0/24",
            interface="eth0",
            scan_type="quick",
            status="completed",
            start_time=datetime.now(),
        )
        session.add(scan)
        session.commit()
        
        device1 = Device(scan_id=scan.id, ip_address="192.168.1.1")
        device2 = Device(scan_id=scan.id, ip_address="192.168.1.2")
        
        session.add_all([device1, device2])
        session.commit()
        
        retrieved_scan = session.query(Scan).first()
        assert len(retrieved_scan.devices) == 2
    
    def test_device_port_relationship(self, session):
        """Test Device-Port relationship."""
        scan = Scan(
            scan_id="SCAN_20240101_120000",
            cidr="192.168.1.0/24",
            interface="eth0",
            scan_type="quick",
            status="completed",
            start_time=datetime.now(),
        )
        session.add(scan)
        session.commit()
        
        device = Device(scan_id=scan.id, ip_address="192.168.1.1")
        session.add(device)
        session.commit()
        
        port1 = Port(device_id=device.id, port_number=22, service="ssh")
        port2 = Port(device_id=device.id, port_number=80, service="http")
        
        session.add_all([port1, port2])
        session.commit()
        
        retrieved_device = session.query(Device).first()
        assert len(retrieved_device.ports) == 2


class TestDatabaseOperations:
    """Tests for database operations."""
    
    @pytest.fixture
    def mock_session(self):
        """Create mock session."""
        return MagicMock()
    
    def test_generate_scan_id(self):
        """Test scan ID generation."""
        from soc_iot_toolkit.database.operations import DatabaseOperations
        
        scan_id = DatabaseOperations.generate_scan_id()
        assert scan_id.startswith("SCAN_")
        assert len(scan_id) == 20  # SCAN_ + YYYYMMDD + _ + HHMMSS
    
    def test_scan_id_format(self):
        """Test scan ID format."""
        from soc_iot_toolkit.database.operations import DatabaseOperations
        
        scan_id = DatabaseOperations.generate_scan_id()
        parts = scan_id.split("_")
        
        assert len(parts) == 3
        assert parts[0] == "SCAN"
        assert len(parts[1]) == 8  # YYYYMMDD
        assert len(parts[2]) == 6  # HHMMSS


class TestDatabaseConnection:
    """Tests for database connection."""
    
    def test_connection_url_building(self):
        """Test connection URL building."""
        from soc_iot_toolkit.database.connection import DatabaseConnection
        
        # Test with SQLite
        conn = DatabaseConnection(
            database_url="sqlite:///test.db"
        )
        assert "sqlite" in conn.database_url
    
    def test_engine_creation(self):
        """Test engine creation."""
        from soc_iot_toolkit.database.connection import DatabaseConnection
        
        conn = DatabaseConnection(
            database_url="sqlite:///:memory:"
        )
        engine = conn.get_engine()
        assert engine is not None
