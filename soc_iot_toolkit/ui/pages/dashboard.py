"""
Dashboard Page Module.

Main dashboard showing overview and statistics.
"""

import streamlit as st
from typing import Dict, Any, Optional
from datetime import datetime

from ..components import render_statistics, render_scan_history_table


def render_dashboard_page(
    stats: Dict[str, Any],
    recent_scans: list,
    active_scans: list,
) -> Optional[str]:
    """
    Render the main dashboard page.
    
    Args:
        stats: Statistics dictionary.
        recent_scans: List of recent scans.
        active_scans: List of currently running scans.
    
    Returns:
        Selected scan ID if user clicks on a scan.
    """
    st.markdown("## Dashboard")
    
    # Active scans alert
    if active_scans:
        st.markdown("### Active Scans")
        for scan in active_scans:
            progress = scan.get("progress", 0)
            scan_id = scan.get("scan_id", "Unknown")
            cidr = scan.get("cidr", "Unknown")
            
            col1, col2 = st.columns([3, 1])
            with col1:
                st.progress(progress / 100.0, text=f"{scan_id} - {cidr}")
            with col2:
                st.text(f"{progress:.1f}%")
        
        st.markdown("---")
    
    # Statistics
    render_statistics(stats)
    
    st.markdown("---")
    
    # Recent scans
    st.markdown("### Recent Scans")
    selected_scan = render_scan_history_table(recent_scans[:10])
    
    return selected_scan


def render_quick_stats(stats: Dict[str, Any]) -> None:
    """Render quick stats row."""
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            "Total Scans",
            stats.get("total_scans", 0),
            help="Total number of scans performed"
        )
    
    with col2:
        st.metric(
            "Devices Found",
            stats.get("total_devices", 0),
            help="Total devices discovered across all scans"
        )
    
    with col3:
        st.metric(
            "Unique MACs",
            stats.get("unique_macs", 0),
            help="Unique MAC addresses detected"
        )
    
    with col4:
        st.metric(
            "Open Ports",
            stats.get("total_ports", 0),
            help="Total open ports discovered"
        )
    
    with col5:
        device_types = stats.get("device_types", {})
        iot_count = sum(
            v for k, v in device_types.items()
            if k not in ("workstation", "server", "unknown", "mobile")
        )
        st.metric(
            "IoT Devices",
            iot_count,
            help="Identified IoT devices"
        )
