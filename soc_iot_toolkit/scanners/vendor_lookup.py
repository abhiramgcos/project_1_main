"""
Vendor Lookup Module.

Provides MAC address to vendor/manufacturer resolution
using OUI (Organizationally Unique Identifier) database.
"""

import os
import re
from typing import Optional, Dict
from pathlib import Path
from loguru import logger

try:
    from mac_vendor_lookup import MacLookup
    MAC_VENDOR_AVAILABLE = True
except ImportError:
    MAC_VENDOR_AVAILABLE = False
    logger.warning("mac-vendor-lookup not available, using fallback")


class VendorLookup:
    """
    Resolves MAC addresses to vendor/manufacturer information.
    
    Uses OUI database for accurate vendor identification.
    Supports both online and offline lookup.
    """
    
    # Common IoT device manufacturers (fallback database)
    COMMON_VENDORS = {
        "00:1A:79": "Allied Telesis",
        "00:50:C2": "IEEE Registration Authority",
        "08:00:27": "Oracle VirtualBox",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:15:5D": "Microsoft Hyper-V",
        "52:54:00": "QEMU/KVM",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Foundation",
        "E4:5F:01": "Raspberry Pi Foundation",
        "28:CD:C1": "Raspberry Pi Foundation",
        "00:17:88": "Philips Lighting",
        "00:1E:C0": "Philips Electronics",
        "EC:FA:BC": "Philips",
        "78:11:DC": "Xiaomi",
        "64:09:80": "Xiaomi",
        "28:6C:07": "Xiaomi",
        "F8:A4:5F": "Xiaomi",
        "50:EC:50": "Samsung Electronics",
        "BC:14:85": "Samsung Electronics",
        "F0:25:B7": "Samsung Electronics",
        "40:4E:36": "HTC",
        "18:AF:8F": "Apple",
        "3C:06:30": "Apple",
        "F0:18:98": "Apple",
        "48:D7:05": "Apple",
        "00:1C:B3": "Apple",
        "AC:BC:32": "Apple",
        "00:1E:7D": "D-Link",
        "1C:7E:E5": "D-Link",
        "28:10:7B": "D-Link",
        "00:1F:33": "Netgear",
        "20:4E:7F": "Netgear",
        "00:24:B2": "Netgear",
        "00:18:0A": "Cisco/Linksys",
        "C0:56:27": "Belkin",
        "94:10:3E": "Belkin",
        "24:F5:A2": "Belkin",
        "00:23:EB": "TP-Link",
        "50:C7:BF": "TP-Link",
        "60:E3:27": "TP-Link",
        "F4:F2:6D": "TP-Link",
        "00:23:24": "ASUS",
        "54:04:A6": "ASUS",
        "1C:87:2C": "ASUS",
        "00:08:9B": "ICP Electronics",
        "00:60:52": "Realtek",
        "00:E0:4C": "Realtek",
        "52:54:AB": "Realtek",
        "B0:6E:BF": "Espressif (ESP8266/ESP32)",
        "5C:CF:7F": "Espressif (ESP8266/ESP32)",
        "EC:FA:BC": "Espressif (ESP8266/ESP32)",
        "24:62:AB": "Espressif (ESP8266/ESP32)",
        "A4:CF:12": "Espressif (ESP8266/ESP32)",
        "00:1D:AA": "Technicolor",
        "00:14:BF": "Cisco-Linksys",
        "20:89:84": "Comtrend",
        "FC:94:E3": "Amazon Technologies",
        "F0:27:2D": "Amazon Technologies",
        "00:BB:3A": "Amazon Technologies",
        "74:C2:46": "Amazon Technologies",
        "44:65:0D": "Amazon Technologies",
        "84:D6:D0": "Amazon Technologies",
        "B4:7C:9C": "Amazon Technologies",
        "68:54:FD": "Amazon Technologies",
        "A0:02:DC": "Amazon Technologies",
        "18:B4:30": "Nest Labs",
        "64:16:66": "Nest Labs",
        "18:C0:FF": "Google",
        "00:1A:11": "Google",
        "94:EB:2C": "Google",
        "F4:F5:D8": "Google",
        "00:09:2D": "HTC",
        "38:E7:D8": "HTC",
        "7C:61:93": "HTC",
        "18:2A:D3": "Ubiquiti Networks",
        "04:18:D6": "Ubiquiti Networks",
        "24:A4:3C": "Ubiquiti Networks",
        "44:D9:E7": "Ubiquiti Networks",
        "78:8A:20": "Ubiquiti Networks",
        "80:2A:A8": "Ubiquiti Networks",
        "B4:FB:E4": "Ubiquiti Networks",
        "DC:9F:DB": "Ubiquiti Networks",
        "F0:9F:C2": "Ubiquiti Networks",
        "FC:EC:DA": "Ubiquiti Networks",
        "24:05:0F": "Ubiquiti Networks",
        "68:D7:9A": "Ubiquiti Networks",
        "00:27:22": "Ubiquiti Networks",
        "00:15:6D": "Ubiquiti Networks",
        "00:0D:B9": "PC Engines",
        "00:0D:B9": "PC Engines",
    }
    
    def __init__(self, update_on_init: bool = False):
        """
        Initialize the VendorLookup.
        
        Args:
            update_on_init: Whether to update the OUI database on initialization.
        """
        self._mac_lookup = None
        self._cache: Dict[str, str] = {}
        
        if MAC_VENDOR_AVAILABLE:
            try:
                self._mac_lookup = MacLookup()
                if update_on_init:
                    self.update_database()
            except Exception as e:
                logger.warning(f"Failed to initialize MacLookup: {e}")
    
    def _normalize_mac(self, mac_address: str) -> str:
        """Normalize MAC address format."""
        if not mac_address:
            return ""
        
        # Remove common separators and convert to uppercase
        mac = mac_address.upper()
        mac = re.sub(r'[.:-]', '', mac)
        
        # Ensure proper format (XX:XX:XX:XX:XX:XX)
        if len(mac) == 12:
            mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        
        return mac
    
    def _get_oui(self, mac_address: str) -> str:
        """Extract OUI (first 3 octets) from MAC address."""
        normalized = self._normalize_mac(mac_address)
        if len(normalized) >= 8:
            return normalized[:8]  # XX:XX:XX
        return ""
    
    def get_vendor(self, mac_address: str) -> str:
        """
        Get the vendor for a MAC address.
        
        Args:
            mac_address: MAC address in any common format.
        
        Returns:
            Vendor name or 'Unknown' if not found.
        """
        if not mac_address:
            return "Unknown"
        
        oui = self._get_oui(mac_address)
        
        # Check cache first
        if oui in self._cache:
            return self._cache[oui]
        
        vendor = self._lookup_vendor(mac_address)
        
        # Cache the result
        self._cache[oui] = vendor
        
        return vendor
    
    def _lookup_vendor(self, mac_address: str) -> str:
        """Perform the actual vendor lookup."""
        # Try mac-vendor-lookup library first
        if self._mac_lookup:
            try:
                vendor = self._mac_lookup.lookup(mac_address)
                if vendor:
                    return vendor
            except Exception as e:
                logger.debug(f"MacLookup failed for {mac_address}: {e}")
        
        # Fallback to built-in database
        oui = self._get_oui(mac_address)
        if oui in self.COMMON_VENDORS:
            return self.COMMON_VENDORS[oui]
        
        return "Unknown"
    
    def get_manufacturer(self, mac_address: str) -> str:
        """
        Get the manufacturer for a MAC address.
        
        Alias for get_vendor for compatibility.
        """
        return self.get_vendor(mac_address)
    
    def is_known_vendor(self, mac_address: str) -> bool:
        """Check if the MAC address has a known vendor."""
        return self.get_vendor(mac_address) != "Unknown"
    
    def get_vendor_info(self, mac_address: str) -> Dict[str, str]:
        """
        Get detailed vendor information.
        
        Returns:
            Dictionary with vendor details.
        """
        vendor = self.get_vendor(mac_address)
        oui = self._get_oui(mac_address)
        
        return {
            "mac_address": self._normalize_mac(mac_address),
            "oui": oui,
            "vendor": vendor,
            "manufacturer": vendor,
            "is_known": vendor != "Unknown",
        }
    
    def update_database(self) -> bool:
        """
        Update the OUI database.
        
        Returns:
            True if update successful, False otherwise.
        """
        if not self._mac_lookup:
            logger.warning("MacLookup not available, cannot update database")
            return False
        
        try:
            logger.info("Updating OUI database...")
            self._mac_lookup.update_vendors()
            self._cache.clear()  # Clear cache after update
            logger.info("OUI database updated successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to update OUI database: {e}")
            return False
    
    def batch_lookup(self, mac_addresses: list) -> Dict[str, str]:
        """
        Perform batch vendor lookup.
        
        Args:
            mac_addresses: List of MAC addresses.
        
        Returns:
            Dictionary mapping MAC addresses to vendors.
        """
        results = {}
        for mac in mac_addresses:
            results[mac] = self.get_vendor(mac)
        return results
    
    def clear_cache(self) -> None:
        """Clear the vendor lookup cache."""
        self._cache.clear()
        logger.debug("Vendor lookup cache cleared")
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "cached_entries": len(self._cache),
            "known_vendors": sum(1 for v in self._cache.values() if v != "Unknown"),
            "unknown_vendors": sum(1 for v in self._cache.values() if v == "Unknown"),
        }
