"""
Device Details Page Module.

Page for viewing detailed information about a specific device.
"""

import streamlit as st
from typing import Dict, Any, Optional, List
from datetime import datetime
import pandas as pd

from ..components import render_device_card


def render_device_details_page(
    device: Optional[Dict[str, Any]] = None,
    device_history: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    Render the device details page.
    
    Args:
        device: Device details dictionary.
        device_history: Historical appearances of this device.
    """
    st.markdown("## Device Details")
    
    if not device:
        st.info("Select a device to view its details.")
        return
    
    # Device header
    ip_address = device.get("ip_address", "Unknown")
    device_type = (device.get("device_type", "") or "unknown").replace("_", " ").title()
    
    st.markdown(f"### {ip_address}")
    st.markdown(f"**Type:** {device_type}")
    
    st.markdown("---")
    
    # Main info tabs
    tab1, tab2, tab3 = st.tabs(["Overview", "Ports & Services", "History"])
    
    with tab1:
        render_device_overview(device)
    
    with tab2:
        render_device_ports(device)
    
    with tab3:
        render_device_history(device, device_history)


def render_device_overview(device: Dict[str, Any]) -> None:
    """Render device overview section."""
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Network Information")
        
        info_table = [
            ("IP Address", device.get("ip_address", "-")),
            ("MAC Address", device.get("mac_address", "-") or "-"),
            ("Hostname", device.get("hostname", "-") or "-"),
            ("Device Name", device.get("device_name", "-") or "-"),
            ("Status", device.get("status", "-")),
        ]
        
        for label, value in info_table:
            st.markdown(f"**{label}:** {value}")
    
    with col2:
        st.markdown("#### Identification")
        
        info_table = [
            ("Device Type", (device.get("device_type", "") or "unknown").replace("_", " ").title()),
            ("Vendor", device.get("vendor", "-") or "-"),
            ("Manufacturer", device.get("manufacturer", "-") or "-"),
            ("Operating System", device.get("os_info", "-") or "-"),
            ("OS Accuracy", f"{device.get('os_accuracy', 0)}%"),
        ]
        
        for label, value in info_table:
            st.markdown(f"**{label}:** {value}")
    
    # Last seen
    st.markdown("---")
    
    last_seen = device.get("last_seen", "")
    if last_seen:
        try:
            dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            last_seen = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
    
    st.markdown(f"**Last Seen:** {last_seen or 'Unknown'}")
    st.markdown(f"**Scan ID:** {device.get('scan_id', 'Unknown')}")


def render_device_ports(device: Dict[str, Any]) -> None:
    """Render device ports section."""
    ports = device.get("ports", [])
    
    if not ports:
        st.info("No open ports detected for this device.")
        return
    
    st.markdown(f"#### Open Ports ({len(ports)})")
    
    # Summary stats
    col1, col2, col3 = st.columns(3)
    
    tcp_count = sum(1 for p in ports if p.get("protocol", "").lower() == "tcp")
    udp_count = sum(1 for p in ports if p.get("protocol", "").lower() == "udp")
    
    with col1:
        st.metric("Total Ports", len(ports))
    
    with col2:
        st.metric("TCP Ports", tcp_count)
    
    with col3:
        st.metric("UDP Ports", udp_count)
    
    st.markdown("---")
    
    # Port table
    port_data = []
    for port in sorted(ports, key=lambda x: x.get("port_number", 0)):
        port_data.append({
            "Port": port.get("port_number", 0),
            "Protocol": port.get("protocol", "tcp").upper(),
            "State": port.get("state", "unknown"),
            "Service": port.get("service", "-") or "-",
            "Product": port.get("product", "-") or "-",
            "Version": port.get("version", "-") or "-",
            "Extra Info": port.get("extra_info", "-") or "-",
        })
    
    df = pd.DataFrame(port_data)
    
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Port": st.column_config.NumberColumn(width="small"),
            "Protocol": st.column_config.TextColumn(width="small"),
            "State": st.column_config.TextColumn(width="small"),
            "Service": st.column_config.TextColumn(width="medium"),
            "Product": st.column_config.TextColumn(width="medium"),
            "Version": st.column_config.TextColumn(width="medium"),
            "Extra Info": st.column_config.TextColumn(width="large"),
        }
    )
    
    # Common port analysis
    st.markdown("---")
    st.markdown("#### Port Analysis")
    
    common_ports = {
        22: ("SSH", "Remote access - verify if needed"),
        23: ("Telnet", "Insecure - should be disabled"),
        80: ("HTTP", "Web interface - check for updates"),
        443: ("HTTPS", "Secure web interface"),
        445: ("SMB", "File sharing - verify security"),
        554: ("RTSP", "Video streaming - common on cameras"),
        1883: ("MQTT", "IoT messaging protocol"),
        8080: ("HTTP-Alt", "Alternative web interface"),
        8443: ("HTTPS-Alt", "Alternative secure web interface"),
    }
    
    findings = []
    for port in ports:
        port_num = port.get("port_number", 0)
        if port_num in common_ports:
            name, note = common_ports[port_num]
            findings.append(f"- **Port {port_num} ({name}):** {note}")
    
    if findings:
        for finding in findings:
            st.markdown(finding)
    else:
        st.info("No specific port findings.")


def render_device_history(
    device: Dict[str, Any],
    history: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Render device history section."""
    st.markdown("#### Device History")
    
    if not history:
        st.info("No historical data available for this device.")
        st.markdown("Device history tracking shows when this device was detected across multiple scans.")
        return
    
    # History table
    history_data = []
    for entry in history:
        scan_time = entry.get("scan_time", "")
        if scan_time:
            try:
                dt = datetime.fromisoformat(scan_time.replace("Z", "+00:00"))
                scan_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        
        history_data.append({
            "Scan ID": entry.get("scan_id", "-"),
            "Scan Time": scan_time,
            "IP Address": entry.get("ip_address", "-"),
            "Status": entry.get("status", "-"),
        })
    
    if history_data:
        df = pd.DataFrame(history_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    
    # First/Last seen
    st.markdown("---")
    
    if history:
        first_seen = min(h.get("scan_time", "") for h in history)
        last_seen = max(h.get("scan_time", "") for h in history)
        total_appearances = len(history)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("First Seen", first_seen[:10] if first_seen else "-")
        
        with col2:
            st.metric("Last Seen", last_seen[:10] if last_seen else "-")
        
        with col3:
            st.metric("Total Appearances", total_appearances)
