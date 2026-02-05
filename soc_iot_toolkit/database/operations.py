"""
Database Operations Module.

Provides CRUD operations for scans, devices, and ports.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple

from sqlalchemy import desc, func, and_, or_
from sqlalchemy.orm import Session, joinedload
from loguru import logger

from .models import Scan, Device, Port, ScanTag, DeviceHistory
from .connection import get_db_connection
from ..scanners.base_scanner import ScanResult, DeviceInfo, PortInfo


class DatabaseOperations:
    """
    Database operations for the SOC IoT Toolkit.
    
    Provides methods for creating, reading, updating, and deleting
    scans, devices, and ports in the PostgreSQL database.
    """
    
    def __init__(self, db_connection=None):
        """
        Initialize DatabaseOperations.
        
        Args:
            db_connection: Optional DatabaseConnection instance.
                          Uses singleton if not provided.
        """
        self._db = db_connection or get_db_connection()
    
    # ==================== Scan Operations ====================
    
    def create_scan(
        self,
        scan_id: str,
        interface: str,
        cidr: str,
        scan_type: str = "standard",
        scan_arguments: Optional[str] = None,
    ) -> Scan:
        """
        Create a new scan record.
        
        Args:
            scan_id: Unique scan identifier.
            interface: Network interface used.
            cidr: CIDR range scanned.
            scan_type: Type of scan performed.
            scan_arguments: Nmap arguments used.
        
        Returns:
            Created Scan object.
        """
        with self._db.session_scope() as session:
            scan = Scan(
                scan_id=scan_id,
                interface=interface,
                cidr=cidr,
                scan_type=scan_type,
                scan_arguments=scan_arguments,
                start_time=datetime.utcnow(),
                status="running",
            )
            session.add(scan)
            session.flush()
            logger.info(f"Created scan: {scan_id}")
            return scan
    
    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        hosts_up: int = 0,
        total_hosts_scanned: int = 0,
        error_message: Optional[str] = None,
    ) -> Optional[Scan]:
        """
        Update scan status.
        
        Args:
            scan_id: Scan identifier.
            status: New status.
            hosts_up: Number of hosts discovered.
            total_hosts_scanned: Total hosts scanned.
            error_message: Error message if failed.
        
        Returns:
            Updated Scan object or None.
        """
        with self._db.session_scope() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                scan.status = status
                scan.hosts_up = hosts_up
                scan.total_hosts_scanned = total_hosts_scanned
                scan.error_message = error_message
                if status in ("completed", "failed", "cancelled"):
                    scan.end_time = datetime.utcnow()
                logger.info(f"Updated scan status: {scan_id} -> {status}")
                return scan
            return None
    
    def update_scan_progress(
        self,
        scan_id: str,
        progress: float,
        scanned_hosts: int,
    ) -> Optional[Scan]:
        """
        Update scan progress in real-time.
        
        Args:
            scan_id: Scan identifier.
            progress: Progress percentage (0-100).
            scanned_hosts: Number of hosts scanned so far.
        
        Returns:
            Updated Scan object or None.
        """
        with self._db.session_scope() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                scan.progress = min(100.0, max(0.0, progress))  # Clamp progress to 0-100
                scan.hosts_up = scanned_hosts
                return scan
            return None
    
    def get_scan_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get current scan progress.
        
        Args:
            scan_id: Scan identifier.
        
        Returns:
            Dictionary with progress info or None.
        """
        with self._db.session_scope() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                return {
                    "scan_id": scan.scan_id,
                    "progress": scan.progress or 0.0,
                    "status": scan.status,
                    "hosts_up": scan.hosts_up or 0,
                    "total_hosts_scanned": scan.total_hosts_scanned or 0,
                    "cidr": scan.cidr,
                    "interface": scan.interface,
                    "start_time": scan.start_time,
                    "end_time": scan.end_time,
                }
            return None
    
    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Get a scan by ID."""
        with self._db.session_scope() as session:
            scan = session.query(Scan).options(
                joinedload(Scan.devices).joinedload(Device.ports)
            ).filter(Scan.scan_id == scan_id).first()
            if scan:
                session.expunge_all()
            return scan
    
    def get_scan_dict(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a scan as a dictionary."""
        with self._db.session_scope() as session:
            scan = session.query(Scan).options(
                joinedload(Scan.devices).joinedload(Device.ports)
            ).filter(Scan.scan_id == scan_id).first()
            if scan:
                return scan.to_dict()
            return None
    
    def get_all_scans(
        self,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get all scans with pagination.
        
        Args:
            limit: Maximum number of scans to return.
            offset: Number of scans to skip.
            status: Filter by status (optional).
        
        Returns:
            List of scan dictionaries.
        """
        with self._db.session_scope() as session:
            query = session.query(Scan).order_by(desc(Scan.start_time))
            
            if status:
                query = query.filter(Scan.status == status)
            
            scans = query.offset(offset).limit(limit).all()
            return [s.to_dict() for s in scans]
    
    def get_recent_scans(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get scans from the last N days."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        with self._db.session_scope() as session:
            scans = session.query(Scan).filter(
                Scan.start_time >= cutoff
            ).order_by(desc(Scan.start_time)).all()
            return [s.to_dict() for s in scans]
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all associated data."""
        with self._db.session_scope() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                session.delete(scan)
                logger.info(f"Deleted scan: {scan_id}")
                return True
            return False
    
    def get_scan_count(self, status: Optional[str] = None) -> int:
        """Get total number of scans."""
        with self._db.session_scope() as session:
            query = session.query(func.count(Scan.scan_id))
            if status:
                query = query.filter(Scan.status == status)
            return query.scalar() or 0
    
    # ==================== Device Operations ====================
    
    def add_device(
        self,
        scan_id: str,
        device_info: DeviceInfo,
    ) -> Optional[Device]:
        """
        Add a device to a scan.
        
        Args:
            scan_id: Parent scan ID.
            device_info: DeviceInfo object with device data.
        
        Returns:
            Created Device object or None.
        """
        with self._db.session_scope() as session:
            device = Device(
                scan_id=scan_id,
                ip_address=device_info.ip_address,
                mac_address=device_info.mac_address,
                hostname=device_info.hostname,
                device_name=device_info.device_name,
                device_type=device_info.device_type,
                vendor=device_info.vendor,
                manufacturer=device_info.manufacturer,
                os_info=device_info.os_info,
                os_accuracy=device_info.os_accuracy,
                status=device_info.status,
                last_seen=device_info.last_seen or datetime.utcnow(),
                raw_data=device_info.raw_data,
            )
            session.add(device)
            session.flush()
            
            # Add ports
            for port_info in device_info.ports:
                port = Port(
                    device_id=device.id,
                    port_number=port_info.port_number,
                    protocol=port_info.protocol,
                    state=port_info.state,
                    service=port_info.service,
                    version=port_info.version,
                    product=port_info.product,
                    extra_info=port_info.extra_info,
                )
                session.add(port)
            
            logger.debug(f"Added device: {device_info.ip_address}")
            return device
    
    def add_devices_bulk(
        self,
        scan_id: str,
        devices: List[DeviceInfo],
    ) -> int:
        """
        Add multiple devices to a scan (bulk insert).
        
        Args:
            scan_id: Parent scan ID.
            devices: List of DeviceInfo objects.
        
        Returns:
            Number of devices added.
        """
        count = 0
        with self._db.session_scope() as session:
            for device_info in devices:
                try:
                    device = Device(
                        scan_id=scan_id,
                        ip_address=device_info.ip_address,
                        mac_address=device_info.mac_address,
                        hostname=device_info.hostname,
                        device_name=device_info.device_name,
                        device_type=device_info.device_type,
                        vendor=device_info.vendor,
                        manufacturer=device_info.manufacturer,
                        os_info=device_info.os_info,
                        os_accuracy=device_info.os_accuracy,
                        status=device_info.status,
                        last_seen=device_info.last_seen or datetime.utcnow(),
                        raw_data=device_info.raw_data,
                    )
                    session.add(device)
                    session.flush()
                    
                    # Add ports
                    for port_info in device_info.ports:
                        port = Port(
                            device_id=device.id,
                            port_number=port_info.port_number,
                            protocol=port_info.protocol,
                            state=port_info.state,
                            service=port_info.service,
                            version=port_info.version,
                            product=port_info.product,
                            extra_info=port_info.extra_info,
                        )
                        session.add(port)
                    
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to add device {device_info.ip_address}: {e}")
        
        logger.info(f"Added {count} devices to scan {scan_id}")
        return count
    
    def get_devices_by_scan(
        self,
        scan_id: str,
        device_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get all devices for a scan.
        
        Args:
            scan_id: Scan identifier.
            device_type: Optional filter by device type.
        
        Returns:
            List of device dictionaries.
        """
        with self._db.session_scope() as session:
            query = session.query(Device).options(
                joinedload(Device.ports)
            ).filter(Device.scan_id == scan_id)
            
            if device_type:
                query = query.filter(Device.device_type == device_type)
            
            devices = query.all()
            return [d.to_dict() for d in devices]
    
    def get_device(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Get a device by ID."""
        with self._db.session_scope() as session:
            device = session.query(Device).options(
                joinedload(Device.ports)
            ).filter(Device.id == device_id).first()
            if device:
                return device.to_dict()
            return None
    
    def search_devices(
        self,
        ip_address: Optional[str] = None,
        mac_address: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search devices across all scans.
        
        Args:
            ip_address: Filter by IP (partial match).
            mac_address: Filter by MAC (partial match).
            vendor: Filter by vendor (partial match).
            device_type: Filter by device type.
            limit: Maximum results.
        
        Returns:
            List of matching device dictionaries.
        """
        with self._db.session_scope() as session:
            query = session.query(Device).options(joinedload(Device.ports))
            
            filters = []
            if ip_address:
                filters.append(Device.ip_address.ilike(f"%{ip_address}%"))
            if mac_address:
                filters.append(Device.mac_address.ilike(f"%{mac_address}%"))
            if vendor:
                filters.append(or_(
                    Device.vendor.ilike(f"%{vendor}%"),
                    Device.manufacturer.ilike(f"%{vendor}%")
                ))
            if device_type:
                filters.append(Device.device_type == device_type)
            
            if filters:
                query = query.filter(and_(*filters))
            
            devices = query.order_by(desc(Device.last_seen)).limit(limit).all()
            return [d.to_dict() for d in devices]
    
    def get_device_types_summary(self, scan_id: Optional[str] = None) -> Dict[str, int]:
        """Get count of devices by type."""
        with self._db.session_scope() as session:
            query = session.query(
                Device.device_type,
                func.count(Device.id)
            ).group_by(Device.device_type)
            
            if scan_id:
                query = query.filter(Device.scan_id == scan_id)
            
            results = query.all()
            return {dtype or "unknown": count for dtype, count in results}
    
    def get_vendors_summary(self, scan_id: Optional[str] = None) -> Dict[str, int]:
        """Get count of devices by vendor."""
        with self._db.session_scope() as session:
            query = session.query(
                Device.vendor,
                func.count(Device.id)
            ).group_by(Device.vendor)
            
            if scan_id:
                query = query.filter(Device.scan_id == scan_id)
            
            results = query.all()
            return {vendor or "Unknown": count for vendor, count in results}
    
    # ==================== Port Operations ====================
    
    def get_ports_by_device(self, device_id: int) -> List[Dict[str, Any]]:
        """Get all ports for a device."""
        with self._db.session_scope() as session:
            ports = session.query(Port).filter(
                Port.device_id == device_id
            ).order_by(Port.port_number).all()
            return [p.to_dict() for p in ports]
    
    def get_common_ports(
        self,
        scan_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[Tuple[int, int]]:
        """Get most common open ports."""
        with self._db.session_scope() as session:
            query = session.query(
                Port.port_number,
                func.count(Port.id).label("count")
            ).filter(Port.state == "open").group_by(
                Port.port_number
            ).order_by(desc("count")).limit(limit)
            
            if scan_id:
                query = query.join(Device).filter(Device.scan_id == scan_id)
            
            return query.all()
    
    # ==================== Scan Result Save ====================
    
    def save_scan_result(self, result: ScanResult) -> bool:
        """
        Save a complete scan result to the database.
        
        Args:
            result: ScanResult object with all scan data.
        
        Returns:
            True if successful, False otherwise.
        """
        try:
            # Create or update scan
            with self._db.session_scope() as session:
                scan = session.query(Scan).filter(
                    Scan.scan_id == result.scan_id
                ).first()
                
                if not scan:
                    scan = Scan(
                        scan_id=result.scan_id,
                        interface=result.interface,
                        cidr=result.cidr,
                        scan_type=result.scan_type.value,
                        scan_arguments=result.scan_arguments,
                        start_time=result.start_time,
                    )
                    session.add(scan)
                
                scan.end_time = result.end_time
                scan.status = result.status
                scan.progress = 100.0 if result.status == "completed" else (0.0 if result.status == "failed" else scan.progress)
                scan.hosts_up = result.hosts_up
                scan.total_hosts_scanned = result.total_hosts_scanned
                scan.error_message = result.error_message
                session.flush()
            
            # Add devices
            self.add_devices_bulk(result.scan_id, result.devices)
            
            logger.info(f"Saved scan result: {result.scan_id} ({len(result.devices)} devices)")
            return True
        
        except Exception as e:
            logger.error(f"Failed to save scan result: {e}")
            return False
    
    # ==================== Statistics ====================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall database statistics."""
        with self._db.session_scope() as session:
            total_scans = session.query(func.count(Scan.scan_id)).scalar() or 0
            total_devices = session.query(func.count(Device.id)).scalar() or 0
            total_ports = session.query(func.count(Port.id)).scalar() or 0
            
            completed_scans = session.query(func.count(Scan.scan_id)).filter(
                Scan.status == "completed"
            ).scalar() or 0
            
            unique_ips = session.query(
                func.count(func.distinct(Device.ip_address))
            ).scalar() or 0
            
            unique_macs = session.query(
                func.count(func.distinct(Device.mac_address))
            ).filter(Device.mac_address.isnot(None)).scalar() or 0
            
            return {
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "total_devices": total_devices,
                "total_ports": total_ports,
                "unique_ips": unique_ips,
                "unique_macs": unique_macs,
                "device_types": self.get_device_types_summary(),
                "vendors": self.get_vendors_summary(),
            }
    
    # ==================== Cleanup ====================
    
    def cleanup_old_scans(self, days: int = 90) -> int:
        """
        Delete scans older than specified days.
        
        Args:
            days: Age threshold in days.
        
        Returns:
            Number of scans deleted.
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        with self._db.session_scope() as session:
            result = session.query(Scan).filter(
                Scan.start_time < cutoff
            ).delete()
            logger.info(f"Cleaned up {result} old scans")
            return result
