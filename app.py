"""
SOC IoT Device Discovery Toolkit - Main Application

A modular Security Operations Center toolkit for discovering
and cataloging IoT devices on a network.

Run with: streamlit run app.py
Requires: sudo privileges for network scanning
"""

import streamlit as st
from datetime import datetime
from typing import Dict, Any, Optional, List
import threading
import time

# Configure page - must be first Streamlit command
st.set_page_config(
    page_title="SOC IoT Discovery Toolkit",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Import toolkit modules
from soc_iot_toolkit.config import get_settings
from soc_iot_toolkit.core import InterfaceManager, CIDRManager, ProcessManager
from soc_iot_toolkit.scanners import NmapScanner, ScanType
from soc_iot_toolkit.database import DatabaseOperations, get_db_connection, init_database
from soc_iot_toolkit.ui.components import (
    render_header,
    render_sidebar,
    render_error,
    render_success,
    render_warning,
)
from soc_iot_toolkit.ui.pages import (
    render_dashboard_page,
    render_scan_page,
    render_history_page,
    render_device_details_page,
    render_settings_page,
)
from soc_iot_toolkit.utils.logger import setup_logger
from loguru import logger


# Initialize logging
setup_logger()


def init_session_state():
    """Initialize Streamlit session state variables."""
    defaults = {
        "page": "dashboard",
        "selected_interface": None,
        "selected_cidr": None,
        "active_scan": None,
        "scan_result": None,
        "selected_scan_id": None,
        "scan_logs": None,  # For live terminal
        "db_initialized": False,
        "interface_manager": None,
        "cidr_manager": None,
        "process_manager": None,
        "db_ops": None,
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def init_managers():
    """Initialize core managers."""
    if st.session_state.interface_manager is None:
        st.session_state.interface_manager = InterfaceManager()
    
    if st.session_state.cidr_manager is None:
        st.session_state.cidr_manager = CIDRManager()
    
    if st.session_state.process_manager is None:
        settings = get_settings()
        st.session_state.process_manager = ProcessManager(
            max_concurrent=settings.app.max_concurrent_scans,
            timeout=settings.app.scan_timeout,
        )


def init_database_connection():
    """Initialize database connection."""
    if not st.session_state.db_initialized:
        try:
            init_database()
            st.session_state.db_ops = DatabaseOperations()
            st.session_state.db_initialized = True
        except Exception as e:
            st.session_state.db_initialized = False
            st.sidebar.error(f"Database connection failed: {str(e)[:50]}")


def get_interfaces() -> List[Dict[str, Any]]:
    """Get available network interfaces."""
    if st.session_state.interface_manager:
        interfaces = st.session_state.interface_manager.get_scannable_interfaces()
        return [i.to_dict() for i in interfaces]
    return []


def get_cidrs(interface: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get detected CIDR ranges."""
    if st.session_state.cidr_manager:
        cidrs = st.session_state.cidr_manager.detect_cidrs(interface)
        return [c.to_dict() for c in cidrs]
    return []


def _scan_worker(
    scanner: NmapScanner,
    scan_id: str,
    db_ops: Optional[DatabaseOperations],
):
    """
    Background worker function to execute scan asynchronously.
    
    Args:
        scanner: NmapScanner instance.
        scan_id: Scan identifier.
        db_ops: DatabaseOperations instance for progress updates.
    """
    def progress_callback(progress: float, scanned: int):
        """Update progress in database."""
        if db_ops:
            try:
                db_ops.update_scan_progress(
                    scan_id=scan_id,
                    progress=progress,
                    scanned_hosts=scanned,
                )
            except Exception as e:
                logger.error(f"Failed to update progress: {e}")
    
    def log_callback(message: str):
        """Log callback (could be extended to store logs in DB)."""
        logger.debug(f"[{scan_id}] {message}")
    
    try:
        result = scanner.execute_scan(
            progress_callback=progress_callback,
            log_callback=log_callback,
            scan_id=scan_id,
        )
        
        # Save results to database
        if db_ops:
            db_ops.save_scan_result(result)
            # Update final progress to 100%
            db_ops.update_scan_progress(
                scan_id=scan_id,
                progress=100.0,
                scanned_hosts=result.hosts_up,
            )
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        
        # Update database with failure
        if db_ops:
            db_ops.update_scan_status(
                scan_id=scan_id,
                status="failed",
                error_message=str(e),
            )


def start_scan(config: Dict[str, Any]):
    """Start a network scan asynchronously."""
    interface = config.get("interface")
    cidr = config.get("cidr")
    scan_type_str = config.get("scan_type", "standard")
    
    if not interface or not cidr:
        render_error("Please select an interface and network.")
        return
    
    # Map scan type
    scan_type_map = {
        "quick": ScanType.QUICK,
        "standard": ScanType.STANDARD,
        "deep": ScanType.DEEP,
        "full": ScanType.FULL,
    }
    scan_type = scan_type_map.get(scan_type_str, ScanType.STANDARD)
    
    # Generate scan ID
    scan_id = f"SCAN_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Create scanner
    scanner = NmapScanner(
        cidr=cidr,
        interface=interface,
        scan_type=scan_type,
    )
    
    # Create database record
    if st.session_state.db_ops:
        try:
            st.session_state.db_ops.create_scan(
                scan_id=scan_id,
                interface=interface,
                cidr=cidr,
                scan_type=scan_type_str,
                scan_arguments=scanner.get_scan_arguments(),
            )
        except Exception as e:
            render_warning(f"Could not save to database: {e}")
            return
    
    # Start scan in background thread
    scan_thread = threading.Thread(
        target=_scan_worker,
        args=(scanner, scan_id, st.session_state.db_ops),
        daemon=True,
    )
    scan_thread.start()
    
    # Get initial host count for progress calculation
    total_hosts = scanner.get_host_count()
    
    # Store scan ID in session state for navigation
    st.session_state.selected_scan_id = scan_id
    st.session_state.active_scan = {
        "scan_id": scan_id,
        "cidr": cidr,
        "interface": interface,
        "progress": 0,
        "status": "running",
        "scanned_hosts": 0,
        "total_hosts": total_hosts,
    }
    
    # Navigate to scan progress page
    st.success(f"Scan {scan_id} started successfully!")
    time.sleep(0.5)  # Brief pause to show success message
    st.rerun()


def update_scan_progress(progress: float, scanned: int):
    """Update scan progress in session state (deprecated - now using database)."""
    # This function is kept for backward compatibility but is no longer used
    # Progress is now tracked in the database via _scan_worker
    pass


def refresh_active_scan_progress():
    """Refresh active scan progress from database and update session state."""
    if st.session_state.active_scan and st.session_state.db_ops:
        scan_id = st.session_state.active_scan.get("scan_id")
        if scan_id:
            try:
                scan_progress = st.session_state.db_ops.get_scan_progress(scan_id)
                if scan_progress:
                    # Update active scan with latest progress
                    st.session_state.active_scan["progress"] = scan_progress.get("progress", 0)
                    st.session_state.active_scan["status"] = scan_progress.get("status", "running")
                    st.session_state.active_scan["scanned_hosts"] = scan_progress.get("hosts_up", 0)
                    # Keep total_hosts from initial state if available
                    if "total_hosts" not in st.session_state.active_scan:
                        st.session_state.active_scan["total_hosts"] = 0
                    
                    # If scan is completed, load results
                    if scan_progress.get("status") in ["completed", "failed", "cancelled"]:
                        st.session_state.scan_result = st.session_state.db_ops.get_scan_dict(scan_id)
                        if st.session_state.scan_result:
                            devices = st.session_state.db_ops.get_devices_by_scan(scan_id)
                            st.session_state.scan_result["devices"] = devices
                        st.session_state.active_scan = None
            except Exception as e:
                logger.debug(f"Failed to refresh scan progress: {e}")


def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    if st.session_state.process_manager:
        st.session_state.process_manager.cancel_process(scan_id)
    
    # Update database
    if st.session_state.db_ops:
        st.session_state.db_ops.update_scan_status(
            scan_id=scan_id,
            status="cancelled",
        )
    
    st.session_state.active_scan = None
    st.session_state.selected_scan_id = None
    render_warning("Scan cancelled.")


def get_statistics() -> Dict[str, Any]:
    """Get database statistics."""
    if st.session_state.db_ops:
        try:
            return st.session_state.db_ops.get_statistics()
        except:
            pass
    
    return {
        "total_scans": 0,
        "completed_scans": 0,
        "total_devices": 0,
        "total_ports": 0,
        "unique_ips": 0,
        "unique_macs": 0,
        "device_types": {},
        "vendors": {},
    }


def get_recent_scans() -> List[Dict[str, Any]]:
    """Get recent scans from database."""
    if st.session_state.db_ops:
        try:
            return st.session_state.db_ops.get_recent_scans(days=30)
        except:
            pass
    return []


def get_all_scans() -> List[Dict[str, Any]]:
    """Get all scans from database."""
    if st.session_state.db_ops:
        try:
            return st.session_state.db_ops.get_all_scans(limit=100)
        except:
            pass
    return []


def get_scan_details(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get detailed scan information."""
    if st.session_state.db_ops:
        try:
            scan = st.session_state.db_ops.get_scan_dict(scan_id)
            if scan:
                devices = st.session_state.db_ops.get_devices_by_scan(scan_id)
                scan["devices"] = devices
                return scan
        except:
            pass
    return None


def delete_scan(scan_id: str):
    """Delete a scan from database."""
    if st.session_state.db_ops:
        try:
            st.session_state.db_ops.delete_scan(scan_id)
            render_success(f"Scan {scan_id} deleted.")
            st.session_state.selected_scan_id = None
            time.sleep(1) # Give time for user to see success message
            st.rerun()
        except Exception as e:
            render_error(f"Failed to delete scan: {e}")


def main():
    """Main application entry point."""
    # Initialize
    init_session_state()
    init_managers()
    init_database_connection()
    
    # Render header
    render_header()
    
    # Render sidebar and get selected page
    page = render_sidebar()
    st.session_state.page = page
    
    # Display database status
    if st.session_state.db_initialized:
        st.sidebar.success("Database: Connected")
    else:
        st.sidebar.warning("Database: Not connected")
    
    # Display Nmap status
    if NmapScanner.check_nmap_installed():
        version = NmapScanner.get_nmap_version()
        st.sidebar.success(f"Nmap: v{version}")
    else:
        st.sidebar.error("Nmap: Not found")
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Version:** 1.0.0")
    
    # Render selected page
    if page == "dashboard":
        stats = get_statistics()
        recent_scans = get_recent_scans()
        active_scans = []
        
        if st.session_state.active_scan:
            active_scans.append(st.session_state.active_scan)
        
        selected = render_dashboard_page(stats, recent_scans, active_scans)
        
        if selected:
            st.session_state.selected_scan_id = selected
            st.session_state.page = "history"
            st.rerun()
    
    elif page == "scan":
        interfaces = get_interfaces()
        
        # Get CIDRs based on selected interface
        selected_interface = st.session_state.get("selected_interface")
        cidrs = get_cidrs(selected_interface)
        
        # Refresh progress if scan is running
        if st.session_state.active_scan:
            refresh_active_scan_progress()
            # Auto-rerun every 1 second to update progress
            time.sleep(1)
            st.rerun()
        
        render_scan_page(
            interfaces=interfaces,
            cidrs=cidrs,
            active_scan=st.session_state.active_scan,
            scan_result=st.session_state.scan_result,
            scan_logs=st.session_state.scan_logs,
            on_start_scan=start_scan,
            on_cancel_scan=cancel_scan,
        )
    
    elif page == "history":
        scans = get_all_scans()
        
        # Get selected scan details
        selected_details = None
        if st.session_state.selected_scan_id:
            selected_details = get_scan_details(st.session_state.selected_scan_id)
        
        def on_select(scan_id):
            st.session_state.selected_scan_id = scan_id
        
        render_history_page(
            scans=scans,
            selected_scan_details=selected_details,
            on_select_scan=on_select,
            on_delete_scan=delete_scan,
        )
    
    elif page == "search":
        st.markdown("## Device Search")
        
        # Search form
        col1, col2, col3 = st.columns(3)
        
        with col1:
            search_ip = st.text_input("IP Address", key="search_ip")
        
        with col2:
            search_vendor = st.text_input("Vendor", key="search_vendor")
        
        with col3:
            search_type = st.selectbox(
                "Device Type",
                ["All", "router", "camera", "printer", "smart_tv", "nas", 
                 "access_point", "iot_sensor", "server", "workstation", "unknown"],
                key="search_type"
            )
        
        if st.button("Search", key="search_btn"):
            if st.session_state.db_ops:
                results = st.session_state.db_ops.search_devices(
                    ip_address=search_ip if search_ip else None,
                    vendor=search_vendor if search_vendor else None,
                    device_type=search_type if search_type != "All" else None,
                )
                
                if results:
                    st.markdown(f"### Found {len(results)} devices")
                    from soc_iot_toolkit.ui.components import render_device_table
                    render_device_table(results)
                else:
                    st.info("No devices found matching the criteria.")
    
    elif page == "settings":
        settings = get_settings()
        
        current = {
            "database": {
                "host": settings.database.host,
                "port": settings.database.port,
                "name": settings.database.name,
                "user": settings.database.user,
            },
            "app": {
                "scan_timeout": settings.app.scan_timeout,
                "max_concurrent_scans": settings.app.max_concurrent_scans,
                "data_retention_days": settings.app.data_retention_days,
            },
            "nmap": {
                "path": settings.nmap.path,
            },
        }
        
        def test_db():
            try:
                db = get_db_connection()
                return db.test_connection()
            except:
                return False
        
        def update_vendors():
            from soc_iot_toolkit.scanners import VendorLookup
            lookup = VendorLookup()
            return lookup.update_database()
        
        render_settings_page(
            current_settings=current,
            on_test_connection=test_db,
            on_update_vendors=update_vendors,
        )


if __name__ == "__main__":
    main()
