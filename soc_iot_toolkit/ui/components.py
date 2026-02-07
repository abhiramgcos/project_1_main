"""
UI Components Module.

Reusable Streamlit components for the SOC IoT Toolkit.
"""

import streamlit as st
import pandas as pd
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime


def render_header(title: str = "SOC IoT Device Discovery Toolkit") -> None:
    """Render the application header."""
    st.markdown(
        f"""
        <div style="padding: 1rem 0; border-bottom: 2px solid #ddd; margin-bottom: 1rem;">
            <h1 style="margin: 0; color: #1f2937;">{title}</h1>
            <p style="margin: 0.5rem 0 0 0; color: #6b7280;">
                Network Scanner and IoT Device Inventory System
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_sidebar_navigation() -> str:
    """
    Render sidebar navigation.
    
    Returns:
        Selected page name.
    """
    st.sidebar.markdown("### Navigation")
    
    pages = {
        "Dashboard": "dashboard",
        "New Scan": "scan",
        "Scan History": "history",
        "Device Search": "search",
        "Settings": "settings",
    }
    
    selected = st.sidebar.radio(
        "Select Page",
        list(pages.keys()),
        label_visibility="collapsed"
    )
    
    return pages[selected]


def render_interface_selector(
    interfaces: List[Dict[str, Any]],
    current_interface: Optional[str] = None,
) -> Optional[str]:
    """
    Render network interface selector.
    
    Args:
        interfaces: List of interface dictionaries.
        current_interface: Currently selected interface.
    
    Returns:
        Selected interface name.
    """
    st.markdown("#### Network Interface")
    
    if not interfaces:
        st.warning("No network interfaces detected.")
        return None
    
    # Create options with details
    options = []
    interface_map = {}
    
    for iface in interfaces:
        if iface.get("is_up") and not iface.get("is_loopback"):
            name = iface["name"]
            ip = iface.get("ip_address", "No IP")
            iface_type = iface.get("interface_type", "unknown")
            label = f"{name} ({ip}) - {iface_type}"
            options.append(label)
            interface_map[label] = name
    
    if not options:
        st.warning("No active network interfaces found.")
        return None
    
    # Set default index
    default_idx = 0
    if current_interface:
        for idx, label in enumerate(options):
            if interface_map[label] == current_interface:
                default_idx = idx
                break
    
    selected_label = st.selectbox(
        "Select Interface",
        options,
        index=default_idx,
        key="interface_selector"
    )
    
    return interface_map.get(selected_label)


def render_cidr_selector(
    cidrs: List[Dict[str, Any]],
    current_cidr: Optional[str] = None,
) -> Optional[str]:
    """
    Render CIDR range selector.
    
    Args:
        cidrs: List of CIDR dictionaries.
        current_cidr: Currently selected CIDR.
    
    Returns:
        Selected CIDR string.
    """
    st.markdown("#### Target Network")
    
    if not cidrs:
        # Allow manual entry
        custom_cidr = st.text_input(
            "Enter CIDR Range",
            placeholder="e.g., 192.168.1.0/24",
            key="custom_cidr"
        )
        return custom_cidr if custom_cidr else None
    
    # Create options
    options = ["-- Select Network --"]
    cidr_map = {"-- Select Network --": None}
    
    for cidr in cidrs:
        cidr_str = cidr["cidr"]
        host_count = cidr.get("host_count", 0)
        gateway = cidr.get("gateway", "")
        label = f"{cidr_str} ({host_count} hosts)"
        if gateway:
            label += f" - Gateway: {gateway}"
        options.append(label)
        cidr_map[label] = cidr_str
    
    options.append("-- Custom CIDR --")
    cidr_map["-- Custom CIDR --"] = "custom"
    
    # Set default index
    default_idx = 0
    if current_cidr:
        for idx, label in enumerate(options):
            if cidr_map[label] == current_cidr:
                default_idx = idx
                break
    
    selected_label = st.selectbox(
        "Select Network Range",
        options,
        index=default_idx,
        key="cidr_selector"
    )
    
    selected = cidr_map.get(selected_label)
    
    if selected == "custom":
        custom_cidr = st.text_input(
            "Enter Custom CIDR",
            placeholder="e.g., 10.0.0.0/24",
            key="custom_cidr_input"
        )
        return custom_cidr if custom_cidr else None
    
    return selected


def render_scan_options() -> Dict[str, Any]:
    """
    Render scan configuration options.
    
    Returns:
        Dictionary of scan options.
    """
    st.markdown("#### Scan Options")
    
    col1, col2 = st.columns(2)
    
    with col1:
        scan_type = st.selectbox(
            "Scan Type",
            ["Quick (Host Discovery)", "Standard", "Deep", "Full"],
            index=1,
            key="scan_type"
        )
    
    with col2:
        port_range = st.selectbox(
            "Port Range",
            ["Top 100", "Top 1000", "All Ports", "Custom"],
            index=1,
            key="port_range"
        )
    
    # Performance options
    st.markdown("#### Performance")
    
    col3, col4 = st.columns(2)
    
    with col3:
        parallel_threads = st.slider(
            "Parallel Threads",
            min_value=1,
            max_value=64,
            value=16,
            step=1,
            key="parallel_threads",
            help="Number of parallel scanning threads. Higher values = faster scans but may trigger IDS/IPS."
        )
    
    with col4:
        st.info(f"🚀 Using {parallel_threads} parallel threads for faster scanning")
    
    # Map scan type
    scan_type_map = {
        "Quick (Host Discovery)": "quick",
        "Standard": "standard",
        "Deep": "deep",
        "Full": "full",
    }
    
    options = {
        "scan_type": scan_type_map.get(scan_type, "standard"),
        "port_range": port_range,
        "parallel_threads": parallel_threads,
    }
    
    if port_range == "Custom":
        options["custom_ports"] = st.text_input(
            "Custom Port Range",
            placeholder="e.g., 22,80,443,8080 or 1-1024",
            key="custom_ports"
        )
    
    return options


def render_scan_progress(
    progress: float,
    status: str,
    hosts_scanned: int = 0,
    total_hosts: int = 0,
) -> None:
    """
    Render scan progress bar.
    
    Args:
        progress: Progress percentage (0-100).
        status: Current status message.
        hosts_scanned: Number of hosts scanned.
        total_hosts: Total hosts to scan.
    """
    st.markdown("#### Scan Progress")
    
    # Progress bar
    st.progress(min(1.0, progress / 100.0))
    
    # Status text
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Progress", f"{progress:.1f}%")
    
    with col2:
        st.metric("Status", status.capitalize())
    
    with col3:
        if total_hosts > 0:
            st.metric("Hosts", f"{hosts_scanned} / {total_hosts}")
        else:
            st.metric("Hosts Found", str(hosts_scanned))


def render_device_table(
    devices: List[Dict[str, Any]],
    show_actions: bool = True,
) -> Optional[int]:
    """
    Render device table.
    
    Args:
        devices: List of device dictionaries.
        show_actions: Whether to show action buttons.
    
    Returns:
        Selected device ID if any.
    """
    if not devices:
        st.info("No devices found.")
        return None
    
    # Prepare data for table
    table_data = []
    for device in devices:
        table_data.append({
            "IP Address": device.get("ip_address", ""),
            "MAC Address": device.get("mac_address", "") or "-",
            "Vendor": device.get("vendor", "") or "-",
            "Device Type": (device.get("device_type", "") or "unknown").replace("_", " ").title(),
            "Hostname": device.get("hostname", "") or device.get("device_name", "") or "-",
            "OS": device.get("os_info", "") or "-",
            "Ports": device.get("port_count", 0),
        })
    
    df = pd.DataFrame(table_data)
    
    # Display table with selection
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "IP Address": st.column_config.TextColumn(width="medium"),
            "MAC Address": st.column_config.TextColumn(width="medium"),
            "Vendor": st.column_config.TextColumn(width="medium"),
            "Device Type": st.column_config.TextColumn(width="small"),
            "Hostname": st.column_config.TextColumn(width="medium"),
            "OS": st.column_config.TextColumn(width="large"),
            "Ports": st.column_config.NumberColumn(width="small"),
        }
    )
    
    return None


def render_device_card(device: Dict[str, Any]) -> None:
    """
    Render detailed device information card.
    
    Args:
        device: Device dictionary.
    """
    st.markdown("---")
    
    # Header
    device_type = (device.get("device_type", "") or "unknown").replace("_", " ").title()
    st.markdown(f"### Device: {device.get('ip_address', 'Unknown')}")
    st.markdown(f"**Type:** {device_type}")
    
    # Main info
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Network Information**")
        st.text(f"IP Address: {device.get('ip_address', '-')}")
        st.text(f"MAC Address: {device.get('mac_address', '-') or '-'}")
        st.text(f"Hostname: {device.get('hostname', '-') or '-'}")
        st.text(f"Device Name: {device.get('device_name', '-') or '-'}")
    
    with col2:
        st.markdown("**Identification**")
        st.text(f"Vendor: {device.get('vendor', '-') or '-'}")
        st.text(f"Manufacturer: {device.get('manufacturer', '-') or '-'}")
        st.text(f"OS: {device.get('os_info', '-') or '-'}")
        st.text(f"OS Accuracy: {device.get('os_accuracy', 0)}%")
    
    # Ports
    ports = device.get("ports", [])
    if ports:
        st.markdown("**Open Ports**")
        
        port_data = []
        for port in ports:
            port_data.append({
                "Port": port.get("port_number", 0),
                "Protocol": port.get("protocol", "tcp").upper(),
                "State": port.get("state", "unknown"),
                "Service": port.get("service", "-") or "-",
                "Version": port.get("version", "-") or "-",
                "Product": port.get("product", "-") or "-",
            })
        
        if port_data:
            st.dataframe(
                pd.DataFrame(port_data),
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.info("No open ports detected.")


def render_scan_history_table(
    scans: List[Dict[str, Any]],
) -> Optional[str]:
    """
    Render scan history table.
    
    Args:
        scans: List of scan dictionaries.
    
    Returns:
        Selected scan ID if any.
    """
    if not scans:
        st.info("No scans found.")
        return None
    
    # Prepare data
    table_data = []
    for scan in scans:
        start_time = scan.get("start_time", "")
        if start_time:
            try:
                dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                start_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        
        duration = scan.get("duration_seconds")
        if duration:
            duration = f"{duration:.1f}s"
        else:
            duration = "-"
        
        table_data.append({
            "Scan ID": scan.get("scan_id", ""),
            "Network": scan.get("cidr", ""),
            "Interface": scan.get("interface", ""),
            "Status": scan.get("status", "").capitalize(),
            "Devices": scan.get("hosts_up", 0),
            "Start Time": start_time,
            "Duration": duration,
        })
    
    df = pd.DataFrame(table_data)
    
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Scan ID": st.column_config.TextColumn(width="large"),
            "Network": st.column_config.TextColumn(width="medium"),
            "Interface": st.column_config.TextColumn(width="small"),
            "Status": st.column_config.TextColumn(width="small"),
            "Devices": st.column_config.NumberColumn(width="small"),
            "Start Time": st.column_config.TextColumn(width="medium"),
            "Duration": st.column_config.TextColumn(width="small"),
        }
    )
    
    # Scan selector
    scan_ids = [s.get("scan_id", "") for s in scans]
    selected_scan = st.selectbox(
        "Select Scan to View Details",
        ["-- Select Scan --"] + scan_ids,
        key="scan_selector"
    )
    
    if selected_scan and selected_scan != "-- Select Scan --":
        return selected_scan
    
    return None


def render_statistics(stats: Dict[str, Any]) -> None:
    """
    Render statistics dashboard.
    
    Args:
        stats: Statistics dictionary.
    """
    st.markdown("### Statistics Overview")
    
    # Main metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Scans", stats.get("total_scans", 0))
    
    with col2:
        st.metric("Completed Scans", stats.get("completed_scans", 0))
    
    with col3:
        st.metric("Total Devices", stats.get("total_devices", 0))
    
    with col4:
        st.metric("Unique IPs", stats.get("unique_ips", 0))
    
    st.markdown("---")
    
    # Device types
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Devices by Type")
        device_types = stats.get("device_types", {})
        if device_types:
            df = pd.DataFrame([
                {"Type": k.replace("_", " ").title(), "Count": v}
                for k, v in sorted(device_types.items(), key=lambda x: x[1], reverse=True)
            ])
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No device data available.")
    
    with col2:
        st.markdown("#### Devices by Vendor")
        vendors = stats.get("vendors", {})
        if vendors:
            # Show top 10
            sorted_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]
            df = pd.DataFrame([
                {"Vendor": k, "Count": v}
                for k, v in sorted_vendors
            ])
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No vendor data available.")


def render_sidebar() -> str:
    """
    Render complete sidebar with navigation and info.
    
    Returns:
        Selected page name.
    """
    st.sidebar.markdown(
        """
        <div style="text-align: center; padding: 1rem 0;">
            <h2 style="margin: 0;">SOC Toolkit</h2>
            <p style="color: #6b7280; margin: 0;">IoT Discovery</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.sidebar.markdown("---")
    
    page = render_sidebar_navigation()
    
    st.sidebar.markdown("---")
    
    # System info
    st.sidebar.markdown("### System Status")
    
    return page


def render_error(message: str) -> None:
    """Render error message."""
    st.error(f"Error: {message}")


def render_success(message: str) -> None:
    """Render success message."""
    st.success(message)


def render_warning(message: str) -> None:
    """Render warning message."""
    st.warning(message)


def render_info(message: str) -> None:
    """Render info message."""
    st.info(message)
