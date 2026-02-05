"""
Database Models Module.

SQLAlchemy ORM models for the SOC IoT Discovery Toolkit.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import (
    Column, String, Integer, DateTime, Text, Boolean, 
    Float, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.postgresql import INET, MACADDR, JSONB


Base = declarative_base()


class Scan(Base):
    """
    Represents a network scan session.
    
    Each scan has a unique ID based on timestamp and contains
    information about the scan parameters and results.
    """
    
    __tablename__ = "scans"
    
    # Primary key - format: SCAN_YYYYMMDD_HHMMSS
    scan_id = Column(String(50), primary_key=True)
    
    # Scan configuration
    interface = Column(String(50), nullable=False)
    cidr = Column(String(50), nullable=False)
    scan_type = Column(String(20), default="standard")
    scan_arguments = Column(Text, nullable=True)
    
    # Timing
    start_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    
    # Results summary
    status = Column(String(20), default="running")  # running, completed, failed, cancelled
    progress = Column(Float, default=0.0)  # Progress percentage (0-100)
    total_hosts_scanned = Column(Integer, default=0)
    hosts_up = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = Column(Text, nullable=True)
    
    # Relationships
    devices = relationship("Device", back_populates="scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_scan_start_time", "start_time"),
        Index("idx_scan_status", "status"),
        Index("idx_scan_cidr", "cidr"),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "scan_id": self.scan_id,
            "interface": self.interface,
            "cidr": self.cidr,
            "scan_type": self.scan_type,
            "scan_arguments": self.scan_arguments,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "total_hosts_scanned": self.total_hosts_scanned,
            "hosts_up": self.hosts_up,
            "error_message": self.error_message,
            "notes": self.notes,
            "device_count": len(self.devices) if self.devices else 0,
            "duration_seconds": self.get_duration(),
        }
    
    def get_duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    def __repr__(self) -> str:
        return f"<Scan(scan_id='{self.scan_id}', cidr='{self.cidr}', status='{self.status}')>"


class Device(Base):
    """
    Represents a discovered network device.
    
    Stores all information gathered about a device during scanning,
    including network addresses, vendor info, and OS details.
    """
    
    __tablename__ = "devices"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to scan
    scan_id = Column(String(50), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)
    
    # Network identifiers
    ip_address = Column(String(45), nullable=False)  # Support IPv6
    mac_address = Column(String(17), nullable=True)  # XX:XX:XX:XX:XX:XX format
    
    # Device identification
    hostname = Column(String(255), nullable=True)
    device_name = Column(String(255), nullable=True)
    device_type = Column(String(100), nullable=True)
    
    # Vendor information
    vendor = Column(String(255), nullable=True)
    manufacturer = Column(String(255), nullable=True)
    
    # OS information
    os_info = Column(String(255), nullable=True)
    os_accuracy = Column(Integer, default=0)
    
    # Status
    status = Column(String(20), default="up")
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Additional data (JSON)
    raw_data = Column(JSONB, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="devices")
    ports = relationship("Port", back_populates="device", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_device_ip", "ip_address"),
        Index("idx_device_mac", "mac_address"),
        Index("idx_device_type", "device_type"),
        Index("idx_device_scan", "scan_id"),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "manufacturer": self.manufacturer,
            "os_info": self.os_info,
            "os_accuracy": self.os_accuracy,
            "status": self.status,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "ports": [p.to_dict() for p in self.ports] if self.ports else [],
            "port_count": len(self.ports) if self.ports else 0,
        }
    
    def get_open_ports(self) -> List[int]:
        """Get list of open port numbers."""
        return [p.port_number for p in self.ports if p.state == "open"]
    
    def __repr__(self) -> str:
        return f"<Device(id={self.id}, ip='{self.ip_address}', type='{self.device_type}')>"


class Port(Base):
    """
    Represents an open port on a discovered device.
    
    Stores information about the port number, protocol,
    state, and detected services.
    """
    
    __tablename__ = "ports"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to device
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    
    # Port information
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")  # tcp, udp
    state = Column(String(20), default="open")  # open, closed, filtered
    
    # Service information
    service = Column(String(100), nullable=True)
    version = Column(String(255), nullable=True)
    product = Column(String(255), nullable=True)
    extra_info = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = relationship("Device", back_populates="ports")
    
    # Indexes and constraints
    __table_args__ = (
        Index("idx_port_number", "port_number"),
        Index("idx_port_device", "device_id"),
        UniqueConstraint("device_id", "port_number", "protocol", name="uq_device_port"),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "device_id": self.device_id,
            "port_number": self.port_number,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "product": self.product,
            "extra_info": self.extra_info,
        }
    
    def __repr__(self) -> str:
        return f"<Port(id={self.id}, port={self.port_number}/{self.protocol}, service='{self.service}')>"


# Additional utility models

class ScanTag(Base):
    """
    Tags for organizing and categorizing scans.
    """
    
    __tablename__ = "scan_tags"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(50), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)
    tag = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_tag_scan", "scan_id"),
        Index("idx_tag_name", "tag"),
        UniqueConstraint("scan_id", "tag", name="uq_scan_tag"),
    )


class DeviceHistory(Base):
    """
    Historical tracking of device appearances across scans.
    """
    
    __tablename__ = "device_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(17), nullable=False)
    ip_address = Column(String(45), nullable=False)
    scan_id = Column(String(50), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_history_mac", "mac_address"),
        Index("idx_history_ip", "ip_address"),
    )
