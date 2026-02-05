
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.getcwd()))

from soc_iot_toolkit.scanners.nmap_scanner import NmapScanner, ScanType
from soc_iot_toolkit.config import Settings, NmapConfig

def test_sudo_escalation():
    print(f"Current UID: {os.geteuid()}")
    
    # Mock settings to have sudo password
    scanner = NmapScanner(cidr="192.168.1.0/24", scan_type=ScanType.STANDARD)
    scanner._sudo_password = "test_password" # Manually inject for test
    
    args = scanner.get_scan_arguments()
    print(f"Generated Arguments with Password: {args}")
    
    if "-sS" not in args:
        print("FAIL: Did not find -sS (SYN scan) when password provided")
        sys.exit(1)
        
    print("SUCCESS: Arguments preserved for privileged mode")

if __name__ == "__main__":
    test_sudo_escalation()
