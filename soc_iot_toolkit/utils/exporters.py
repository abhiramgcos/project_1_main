"""
Data Export Module.

Provides functions for exporting scan results to various formats.
"""

import csv
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from loguru import logger


def export_to_csv(
    data: List[Dict[str, Any]],
    filepath: Union[str, Path],
    fields: Optional[List[str]] = None,
) -> bool:
    """
    Export data to CSV file.
    
    Args:
        data: List of dictionaries to export.
        filepath: Output file path.
        fields: Optional list of fields to include (uses all if not specified).
    
    Returns:
        True if export successful, False otherwise.
    """
    if not data:
        logger.warning("No data to export")
        return False
    
    try:
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Determine fields
        if fields is None:
            fields = list(data[0].keys())
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            
            for row in data:
                # Flatten nested data
                flat_row = flatten_dict(row)
                writer.writerow(flat_row)
        
        logger.info(f"Exported {len(data)} records to {filepath}")
        return True
    
    except Exception as e:
        logger.error(f"CSV export failed: {e}")
        return False


def export_to_json(
    data: Union[Dict, List],
    filepath: Union[str, Path],
    indent: int = 2,
) -> bool:
    """
    Export data to JSON file.
    
    Args:
        data: Data to export.
        filepath: Output file path.
        indent: JSON indentation level.
    
    Returns:
        True if export successful, False otherwise.
    """
    try:
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, default=json_serializer)
        
        logger.info(f"Exported data to {filepath}")
        return True
    
    except Exception as e:
        logger.error(f"JSON export failed: {e}")
        return False


def export_scan_results(
    scan_result: Dict[str, Any],
    output_dir: Union[str, Path],
    formats: List[str] = ["csv", "json"],
) -> Dict[str, str]:
    """
    Export scan results to multiple formats.
    
    Args:
        scan_result: Scan result dictionary.
        output_dir: Output directory.
        formats: List of formats to export (csv, json).
    
    Returns:
        Dictionary mapping format to output filepath.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    scan_id = scan_result.get("scan_id", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    exported_files = {}
    
    if "csv" in formats:
        # Export devices to CSV
        devices = scan_result.get("devices", [])
        if devices:
            device_data = []
            for device in devices:
                flat = {
                    "ip_address": device.get("ip_address", ""),
                    "mac_address": device.get("mac_address", ""),
                    "vendor": device.get("vendor", ""),
                    "manufacturer": device.get("manufacturer", ""),
                    "device_name": device.get("device_name", ""),
                    "device_type": device.get("device_type", ""),
                    "hostname": device.get("hostname", ""),
                    "os_info": device.get("os_info", ""),
                    "os_accuracy": device.get("os_accuracy", 0),
                    "status": device.get("status", ""),
                    "port_count": device.get("port_count", 0),
                    "open_ports": ",".join(str(p.get("port_number", "")) for p in device.get("ports", [])),
                }
                device_data.append(flat)
            
            csv_path = output_dir / f"{scan_id}_devices_{timestamp}.csv"
            if export_to_csv(device_data, csv_path):
                exported_files["csv"] = str(csv_path)
    
    if "json" in formats:
        json_path = output_dir / f"{scan_id}_full_{timestamp}.json"
        if export_to_json(scan_result, json_path):
            exported_files["json"] = str(json_path)
    
    return exported_files


def export_devices_summary(
    devices: List[Dict[str, Any]],
    filepath: Union[str, Path],
) -> bool:
    """
    Export a summary of devices to CSV.
    
    Args:
        devices: List of device dictionaries.
        filepath: Output file path.
    
    Returns:
        True if export successful.
    """
    if not devices:
        return False
    
    summary_data = []
    for device in devices:
        summary_data.append({
            "IP Address": device.get("ip_address", ""),
            "MAC Address": device.get("mac_address", ""),
            "Vendor": device.get("vendor", ""),
            "Device Type": device.get("device_type", ""),
            "Hostname": device.get("hostname", "") or device.get("device_name", ""),
            "OS": device.get("os_info", ""),
            "Open Ports": len(device.get("ports", [])),
        })
    
    return export_to_csv(summary_data, filepath, list(summary_data[0].keys()))


def flatten_dict(
    d: Dict[str, Any],
    parent_key: str = '',
    separator: str = '_'
) -> Dict[str, Any]:
    """
    Flatten a nested dictionary.
    
    Args:
        d: Dictionary to flatten.
        parent_key: Parent key prefix.
        separator: Key separator.
    
    Returns:
        Flattened dictionary.
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{separator}{k}" if parent_key else k
        
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, separator).items())
        elif isinstance(v, list):
            # Convert lists to comma-separated strings
            if v and isinstance(v[0], dict):
                # Skip nested list of dicts
                items.append((new_key + "_count", len(v)))
            else:
                items.append((new_key, ",".join(str(x) for x in v)))
        else:
            items.append((new_key, v))
    
    return dict(items)


def json_serializer(obj: Any) -> str:
    """
    JSON serializer for objects not serializable by default.
    
    Args:
        obj: Object to serialize.
    
    Returns:
        Serialized string representation.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, 'to_dict'):
        return obj.to_dict()
    elif hasattr(obj, '__dict__'):
        return obj.__dict__
    else:
        return str(obj)


def generate_html_report(
    scan_result: Dict[str, Any],
    filepath: Union[str, Path],
) -> bool:
    """
    Generate an HTML report for scan results.
    
    Args:
        scan_result: Scan result dictionary.
        filepath: Output file path.
    
    Returns:
        True if export successful.
    """
    try:
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = generate_html_content(scan_result)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML report: {filepath}")
        return True
    
    except Exception as e:
        logger.error(f"HTML report generation failed: {e}")
        return False


def generate_html_content(scan_result: Dict[str, Any]) -> str:
    """Generate HTML content for scan report."""
    scan_id = scan_result.get("scan_id", "Unknown")
    cidr = scan_result.get("cidr", "Unknown")
    devices = scan_result.get("devices", [])
    
    device_rows = ""
    for device in devices:
        ports = ", ".join(str(p.get("port_number", "")) for p in device.get("ports", [])[:10])
        if len(device.get("ports", [])) > 10:
            ports += "..."
        
        device_rows += f"""
        <tr>
            <td>{device.get("ip_address", "-")}</td>
            <td>{device.get("mac_address", "-") or "-"}</td>
            <td>{device.get("vendor", "-") or "-"}</td>
            <td>{(device.get("device_type", "") or "unknown").replace("_", " ").title()}</td>
            <td>{device.get("hostname", "-") or "-"}</td>
            <td>{ports or "-"}</td>
        </tr>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Scan Report - {scan_id}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .summary {{ margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <h1>Network Scan Report</h1>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Scan ID:</strong> {scan_id}</p>
            <p><strong>Network:</strong> {cidr}</p>
            <p><strong>Status:</strong> {scan_result.get("status", "Unknown")}</p>
            <p><strong>Devices Found:</strong> {len(devices)}</p>
            <p><strong>Start Time:</strong> {scan_result.get("start_time", "Unknown")}</p>
            <p><strong>Duration:</strong> {scan_result.get("duration_seconds", 0):.1f} seconds</p>
        </div>
        
        <h2>Discovered Devices</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Vendor</th>
                <th>Type</th>
                <th>Hostname</th>
                <th>Open Ports</th>
            </tr>
            {device_rows}
        </table>
        
        <footer style="margin-top: 30px; color: #666;">
            <p>Generated by SOC IoT Discovery Toolkit</p>
            <p>Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </footer>
    </body>
    </html>
    """
    
    return html
