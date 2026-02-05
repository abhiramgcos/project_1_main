"""
UI Pages module for SOC IoT Toolkit.
"""

from .dashboard import render_dashboard_page
from .scan_view import render_scan_page
from .history import render_history_page
from .device_details import render_device_details_page
from .settings import render_settings_page

__all__ = [
    "render_dashboard_page",
    "render_scan_page",
    "render_history_page",
    "render_device_details_page",
    "render_settings_page",
]
