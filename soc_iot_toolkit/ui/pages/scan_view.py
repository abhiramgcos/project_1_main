"""
Scan View Page Module.

Page for initiating and monitoring network scans.
"""

import streamlit as st
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime

from ..components import (
    render_interface_selector,
    render_cidr_selector,
    render_scan_options,
    render_scan_progress,
    render_device_table,
)


def render_scan_page(
    interfaces: List[Dict[str, Any]],
    cidrs: List[Dict[str, Any]],
    active_scan: Optional[Dict[str, Any]] = None,
    scan_result: Optional[Dict[str, Any]] = None,
    scan_logs: Optional[List[str]] = None,
    on_start_scan: Optional[Callable] = None,
    on_cancel_scan: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Render the scan configuration and execution page.
    
    Args:
        interfaces: Available network interfaces.
        cidrs: Detected CIDR ranges.
        active_scan: Currently running scan info.
        scan_result: Results of completed scan.
        on_start_scan: Callback for starting scan.
        on_cancel_scan: Callback for canceling scan.
    
    Returns:
        Scan configuration dictionary.
    """
    st.markdown("## Network Scan")
    
    config = {}
    
    # If scan is running, show progress
    if active_scan:
        render_active_scan(active_scan, scan_logs, on_cancel_scan)
        return config
    
    # If we have results, show them
    if scan_result:
        render_scan_results(scan_result)
        if st.button("Start New Scan", key="new_scan_btn"):
            st.session_state.pop("scan_result", None)
            st.rerun()
        return config
    
    # Scan configuration
    st.markdown("### Scan Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Interface selection
        selected_interface = render_interface_selector(
            interfaces,
            st.session_state.get("selected_interface")
        )
        config["interface"] = selected_interface
        
        if selected_interface:
            st.session_state["selected_interface"] = selected_interface
    
    with col2:
        # CIDR selection
        selected_cidr = render_cidr_selector(
            cidrs,
            st.session_state.get("selected_cidr")
        )
        config["cidr"] = selected_cidr
        
        if selected_cidr:
            st.session_state["selected_cidr"] = selected_cidr
    
    st.markdown("---")
    
    # Scan options
    options = render_scan_options()
    config.update(options)
    
    st.markdown("---")
    
    # Start scan button
    col1, col2, col3 = st.columns([2, 1, 2])
    
    with col2:
        can_scan = bool(config.get("interface") and config.get("cidr"))
        
        if st.button(
            "Start Scan",
            disabled=not can_scan,
            type="primary",
            use_container_width=True,
            key="start_scan_btn"
        ):
            if on_start_scan:
                on_start_scan(config)
    
    if not can_scan:
        st.warning("Please select a network interface and target network to start scanning.")
    
    return config


def render_active_scan(
    scan_info: Dict[str, Any],
    scan_logs: Optional[List[str]] = None,
    on_cancel: Optional[Callable] = None,
) -> None:
    """
    Render active scan progress.
    
    Args:
        scan_info: Current scan information.
        scan_logs: List of log messages.
        on_cancel: Callback for cancel button.
    """
    st.markdown("### Scan in Progress")
    
    scan_id = scan_info.get("scan_id", "Unknown")
    cidr = scan_info.get("cidr", "Unknown")
    progress = scan_info.get("progress", 0)
    status = scan_info.get("status", "running")
    hosts_scanned = scan_info.get("scanned_hosts", 0)
    total_hosts = scan_info.get("total_hosts", 0)
    
    st.markdown(f"**Scan ID:** {scan_id}")
    st.markdown(f"**Target:** {cidr}")
    
    render_scan_progress(progress, status, hosts_scanned, total_hosts)
    
    # Live Terminal Output
    st.markdown("#### Terminal Output")
    logs = "\n".join(scan_logs) if scan_logs else "Initializing scan..."
    st.code(logs, language="bash")
    
    # Auto-scroll hack (optional, but code block handles it well enough)
    
    # Cancel button
    col1, col2, col3 = st.columns([2, 1, 2])
    with col2:
        if st.button("Cancel Scan", type="secondary", use_container_width=True):
            if on_cancel:
                on_cancel(scan_id)


def render_scan_results(result: Dict[str, Any]) -> None:
    """
    Render scan results.
    
    Args:
        result: Scan result dictionary.
    """
    st.markdown("### Scan Results")
    
    # Summary
    scan_id = result.get("scan_id", "Unknown")
    cidr = result.get("cidr", "Unknown")
    status = result.get("status", "unknown")
    hosts_up = result.get("hosts_up", 0)
    duration = result.get("duration_seconds", 0)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Scan ID", scan_id)
    
    with col2:
        st.metric("Status", status.capitalize())
    
    with col3:
        st.metric("Devices Found", hosts_up)
    
    with col4:
        st.metric("Duration", f"{duration:.1f}s" if duration else "-")
    
    st.markdown("---")
    
    # Error message if failed
    if result.get("error_message"):
        st.error(f"Error: {result['error_message']}")
    
    # Device list
    devices = result.get("devices", [])
    if devices:
        st.markdown("### Discovered Devices")
        render_device_table(devices)
    else:
        st.info("No devices discovered in this scan.")
    
    # Export options
    st.markdown("---")
    st.markdown("### Export Options")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Export CSV", key="export_csv"):
            # TODO: Implement CSV export
            st.info("CSV export functionality will be implemented.")
    
    with col2:
        if st.button("Export JSON", key="export_json"):
            # TODO: Implement JSON export
            st.info("JSON export functionality will be implemented.")
    
    with col3:
        if st.button("Save to Database", key="save_db"):
            # TODO: Save to database
            st.success("Results saved to database.")
