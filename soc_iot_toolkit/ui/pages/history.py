"""
History Page Module.

Page for viewing scan history and past results.
"""

import streamlit as st
from typing import Dict, Any, Optional, List
from datetime import datetime
import pandas as pd

from ..components import (
    render_scan_history_table,
    render_device_table,
    render_device_card,
)


def render_history_page(
    scans: List[Dict[str, Any]],
    selected_scan_details: Optional[Dict[str, Any]] = None,
    on_select_scan: Optional[callable] = None,
    on_delete_scan: Optional[callable] = None,
) -> Optional[str]:
    """
    Render the scan history page.
    
    Args:
        scans: List of all scans.
        selected_scan_details: Details of selected scan.
        on_select_scan: Callback when scan is selected.
        on_delete_scan: Callback when scan is deleted.
    
    Returns:
        Selected scan ID.
    """
    st.markdown("## Scan History")
    
    # Filters
    with st.expander("Filters", expanded=False):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status_filter = st.selectbox(
                "Status",
                ["All", "Completed", "Failed", "Running", "Cancelled"],
                key="history_status_filter"
            )
        
        with col2:
            date_filter = st.date_input(
                "From Date",
                value=None,
                key="history_date_filter"
            )
        
        with col3:
            cidr_filter = st.text_input(
                "Network (CIDR)",
                placeholder="e.g., 192.168.1.0",
                key="history_cidr_filter"
            )
    
    # Apply filters
    filtered_scans = scans
    
    if status_filter != "All":
        filtered_scans = [
            s for s in filtered_scans 
            if s.get("status", "").lower() == status_filter.lower()
        ]
    
    if cidr_filter:
        filtered_scans = [
            s for s in filtered_scans 
            if cidr_filter.lower() in s.get("cidr", "").lower()
        ]
    
    st.markdown(f"**Showing {len(filtered_scans)} of {len(scans)} scans**")
    
    st.markdown("---")
    
    # Scan list
    selected_scan_id = render_scan_history_table(filtered_scans)
    
    # If a scan is selected, update state and trigger rerun to show details
    if selected_scan_id and on_select_scan:
        # Check if this is a new selection (different from current state)
        if st.session_state.get("selected_scan_id") != selected_scan_id:
            on_select_scan(selected_scan_id)
            st.rerun()  # Trigger rerun to fetch and display details immediately
    
    if selected_scan_details:
        render_scan_details(selected_scan_details, on_delete_scan)
    
    return selected_scan_id


def render_scan_details(
    scan: Dict[str, Any],
    on_delete: Optional[callable] = None,
) -> None:
    """
    Render detailed scan information.
    
    Args:
        scan: Scan details dictionary.
        on_delete: Callback for delete action.
    """
    st.markdown("---")
    st.markdown("### Scan Details")
    
    scan_id = scan.get("scan_id", "Unknown")
    status = scan.get("status", "unknown")
    
    # Header with actions
    # NOTE: Delete button is intentionally visible for ALL scan statuses (completed, failed, running, cancelled)
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown(f"#### {scan_id}")
    
    with col2:
        # Status-aware button text for better clarity
        button_text = "🗑️ Delete Scan"
        if status == "failed":
            button_text = "🗑️ Delete Failed Scan"
        elif status == "running":
            button_text = "🗑️ Cancel & Delete"
        
        if st.button(button_text, type="secondary", key="delete_scan_btn", use_container_width=True):
            if on_delete:
                on_delete(scan_id)
    
    # Scan info
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("**Network**")
        st.text(scan.get("cidr", "-"))
    
    with col2:
        st.markdown("**Interface**")
        st.text(scan.get("interface", "-"))
    
    with col3:
        st.markdown("**Status**")
        status = scan.get("status", "unknown")
        if status == "completed":
            st.success(status.capitalize())
        elif status == "failed":
            st.error(status.capitalize())
        elif status == "running":
            st.info(status.capitalize())
        else:
            st.text(status.capitalize())
    
    with col4:
        st.markdown("**Devices Found**")
        st.text(str(scan.get("hosts_up", 0)))
    
    # Error message for failed scans - displayed prominently
    if scan.get("error_message"):
        st.markdown("")  # Add spacing
        st.error(f"**Scan Error:** {scan['error_message']}")
    
    # Timing
    col1, col2, col3 = st.columns(3)
    
    with col1:
        start_time = scan.get("start_time", "")
        if start_time:
            try:
                dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                start_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        st.markdown("**Start Time**")
        st.text(start_time or "-")
    
    with col2:
        end_time = scan.get("end_time", "")
        if end_time:
            try:
                dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
                end_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        st.markdown("**End Time**")
        st.text(end_time or "-")
    
    with col3:
        duration = scan.get("duration_seconds")
        st.markdown("**Duration**")
        st.text(f"{duration:.1f}s" if duration else "-")
    
    # Scan arguments
    if scan.get("scan_arguments"):
        with st.expander("Scan Arguments"):
            st.code(scan["scan_arguments"], language="bash")
    
    # Devices
    st.markdown("---")
    st.markdown("### Discovered Devices")
    
    devices = scan.get("devices", [])
    if devices:
        # Device type summary
        type_counts = {}
        for d in devices:
            dtype = d.get("device_type", "unknown") or "unknown"
            type_counts[dtype] = type_counts.get(dtype, 0) + 1
        
        st.markdown("**Device Types:**")
        cols = st.columns(min(len(type_counts), 6))
        for idx, (dtype, count) in enumerate(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)):
            with cols[idx % 6]:
                st.metric(dtype.replace("_", " ").title(), count)
        
        st.markdown("---")
        
        # Device table
        render_device_table(devices)
        
        # Individual device details
        st.markdown("---")
        st.markdown("### Device Details")
        
        device_options = [f"{d.get('ip_address', '')} - {d.get('device_type', 'unknown')}" for d in devices]
        selected_device = st.selectbox(
            "Select Device",
            ["-- Select Device --"] + device_options,
            key="device_detail_selector"
        )
        
        if selected_device != "-- Select Device --":
            idx = device_options.index(selected_device)
            render_device_card(devices[idx])
    else:
        st.info("No devices were discovered in this scan.")
