"""
Settings Page Module.

Page for application configuration and settings.
"""

import streamlit as st
from typing import Dict, Any, Optional
from datetime import datetime


def render_settings_page(
    current_settings: Dict[str, Any],
    on_save: Optional[callable] = None,
    on_test_connection: Optional[callable] = None,
    on_update_vendors: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Render the settings page.
    
    Args:
        current_settings: Current application settings.
        on_save: Callback for saving settings.
        on_test_connection: Callback for testing database connection.
        on_update_vendors: Callback for updating vendor database.
    
    Returns:
        Updated settings dictionary.
    """
    st.markdown("## Settings")
    
    settings = {}
    
    # Database settings
    st.markdown("### Database Configuration")
    
    with st.expander("Database Settings", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            db_host = st.text_input(
                "Database Host",
                value=current_settings.get("database", {}).get("host", "localhost"),
                key="db_host"
            )
            
            db_port = st.number_input(
                "Database Port",
                value=current_settings.get("database", {}).get("port", 5432),
                min_value=1,
                max_value=65535,
                key="db_port"
            )
            
            db_name = st.text_input(
                "Database Name",
                value=current_settings.get("database", {}).get("name", "soc_iot_db"),
                key="db_name"
            )
        
        with col2:
            db_user = st.text_input(
                "Database User",
                value=current_settings.get("database", {}).get("user", "soc_toolkit"),
                key="db_user"
            )
            
            db_password = st.text_input(
                "Database Password",
                type="password",
                key="db_password"
            )
            
            if st.button("Test Connection", key="test_db_btn"):
                if on_test_connection:
                    success = on_test_connection()
                    if success:
                        st.success("Connection successful!")
                    else:
                        st.error("Connection failed!")
        
        settings["database"] = {
            "host": db_host,
            "port": int(db_port),
            "name": db_name,
            "user": db_user,
            "password": db_password,
        }
    
    st.markdown("---")
    
    # Scan settings
    st.markdown("### Scan Configuration")
    
    with st.expander("Scan Settings", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            scan_timeout = st.number_input(
                "Scan Timeout (seconds)",
                value=current_settings.get("app", {}).get("scan_timeout", 300),
                min_value=60,
                max_value=3600,
                step=30,
                key="scan_timeout"
            )
            
            max_concurrent = st.number_input(
                "Max Concurrent Scans",
                value=current_settings.get("app", {}).get("max_concurrent_scans", 3),
                min_value=1,
                max_value=10,
                key="max_concurrent"
            )
        
        with col2:
            nmap_path = st.text_input(
                "Nmap Path",
                value=current_settings.get("nmap", {}).get("path", "/usr/bin/nmap"),
                key="nmap_path"
            )
            
            default_scan_type = st.selectbox(
                "Default Scan Type",
                ["Quick", "Standard", "Deep", "Full"],
                index=1,
                key="default_scan_type"
            )
        
        settings["scan"] = {
            "timeout": scan_timeout,
            "max_concurrent": max_concurrent,
            "nmap_path": nmap_path,
            "default_type": default_scan_type.lower(),
        }
    
    st.markdown("---")
    
    # Vendor database
    st.markdown("### Vendor Database")
    
    with st.expander("Vendor Settings", expanded=False):
        st.markdown("The vendor database is used to identify device manufacturers from MAC addresses.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Update Vendor Database", key="update_vendors_btn"):
                if on_update_vendors:
                    with st.spinner("Updating vendor database..."):
                        success = on_update_vendors()
                        if success:
                            st.success("Vendor database updated successfully!")
                        else:
                            st.error("Failed to update vendor database.")
        
        with col2:
            st.markdown("Last updated: Unknown")
    
    st.markdown("---")
    
    # Data retention
    st.markdown("### Data Management")
    
    with st.expander("Data Retention", expanded=False):
        retention_days = st.number_input(
            "Keep scan data for (days)",
            value=current_settings.get("app", {}).get("data_retention_days", 90),
            min_value=7,
            max_value=365,
            step=7,
            key="retention_days"
        )
        
        settings["retention"] = {
            "days": retention_days,
        }
        
        st.warning(f"Scans older than {retention_days} days will be automatically deleted.")
        
        if st.button("Clean Up Old Data Now", key="cleanup_btn"):
            st.info("Cleanup functionality will be implemented.")
    
    st.markdown("---")
    
    # Logging
    st.markdown("### Logging")
    
    with st.expander("Log Settings", expanded=False):
        log_level = st.selectbox(
            "Log Level",
            ["DEBUG", "INFO", "WARNING", "ERROR"],
            index=1,
            key="log_level"
        )
        
        settings["logging"] = {
            "level": log_level,
        }
    
    st.markdown("---")
    
    # Save button
    col1, col2, col3 = st.columns([2, 1, 2])
    
    with col2:
        if st.button("Save Settings", type="primary", use_container_width=True, key="save_settings_btn"):
            if on_save:
                on_save(settings)
                st.success("Settings saved successfully!")
    
    return settings


def render_system_info() -> None:
    """Render system information section."""
    st.markdown("### System Information")
    
    import platform
    import sys
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**System**")
        st.text(f"OS: {platform.system()} {platform.release()}")
        st.text(f"Python: {sys.version.split()[0]}")
        st.text(f"Architecture: {platform.machine()}")
    
    with col2:
        st.markdown("**Application**")
        st.text("Version: 1.0.0")
        st.text(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
