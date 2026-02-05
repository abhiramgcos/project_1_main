"""
Nmap Scanner Module.

Provides comprehensive network scanning using Nmap.
"""

import subprocess
import threading
import re
import os
from datetime import datetime
from typing import Optional, Callable, Dict, Any, List
from loguru import logger

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap not available, using subprocess fallback")

from .base_scanner import BaseScanner, ScanResult, DeviceInfo, PortInfo, ScanType
from .vendor_lookup import VendorLookup
from .device_fingerprint import DeviceFingerprinter


class NmapScanner(BaseScanner):
    """
    Network scanner implementation using Nmap.
    
    Provides comprehensive host discovery, port scanning,
    service detection, and OS fingerprinting capabilities.
    """
    
    # Scan profile definitions
    SCAN_PROFILES = {
        ScanType.QUICK: "-sn -T4 --max-retries 1",
        ScanType.STANDARD: "-sS -sV -T4 --top-ports 1000",
        ScanType.DEEP: "-sS -sV -sC -O -T4 --top-ports 1000",
        ScanType.FULL: "-sS -sV -sC -O -A -T4 -p-",
    }
    
    def __init__(
        self,
        cidr: str,
        interface: Optional[str] = None,
        scan_type: ScanType = ScanType.STANDARD,
        custom_arguments: Optional[str] = None,
        timeout: int = 300,
    ):
        """
        Initialize the Nmap scanner.
        
        Args:
            cidr: CIDR range to scan.
            interface: Network interface to use.
            scan_type: Type of scan to perform.
            custom_arguments: Custom Nmap arguments (overrides scan_type).
            timeout: Scan timeout in seconds.
        """
        super().__init__(cidr, interface, scan_type)
        
        self._custom_arguments = custom_arguments
        self._timeout = timeout
        
        # Get sudo password from settings or env
        from ..config import get_settings
        settings = get_settings()
        self._sudo_password = settings.nmap.sudo_password or os.getenv("SUDO_PASSWORD")
        
        self._nmap_path = self._find_nmap()
        self._vendor_lookup = VendorLookup()
        self._fingerprinter = DeviceFingerprinter()
        self._cancel_event = threading.Event()
        self._current_process: Optional[subprocess.Popen] = None
        
        if NMAP_AVAILABLE:
            self._scanner = nmap.PortScanner()
        else:
            self._scanner = None
    
    def _find_nmap(self) -> str:
        """Find the Nmap executable path."""
        paths = ["/usr/bin/nmap", "/usr/local/bin/nmap", "nmap"]
        
        for path in paths:
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    version_match = re.search(r"Nmap version (\d+\.\d+)", result.stdout)
                    if version_match:
                        logger.info(f"Found Nmap {version_match.group(1)} at {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        logger.warning("Nmap not found in standard locations")
        return "nmap"
    
    def _is_root(self) -> bool:
        """Check if running with root privileges."""
        return os.geteuid() == 0
    
    def _requires_root_privileges(self, arguments: str) -> bool:
        """
        Check if the scan arguments require root privileges.
        
        Args:
            arguments: Nmap command line arguments
            
        Returns:
            True if root privileges are required, False otherwise
        """
        # Flags that require root/elevated privileges
        privileged_flags = [
            '-sS',  # SYN scan
            '-sU',  # UDP scan
            '-sO',  # IP protocol scan
            '-sA',  # ACK scan
            '-sW',  # Window scan
            '-sM',  # Maimon scan
            '-O',   # OS detection
            '-A',   # Aggressive scan (includes OS detection)
            '--traceroute',  # Traceroute
        ]
        
        for flag in privileged_flags:
            if flag in arguments:
                return True
        
        return False

    def get_scan_arguments(self) -> str:
        """
        Get the Nmap arguments for the current scan configuration.
        Adjusts automatically for unprivileged execution.
        """
        if self._custom_arguments:
            args = self._custom_arguments
        else:
            args = self.SCAN_PROFILES.get(self._scan_type, self.SCAN_PROFILES[ScanType.STANDARD])
        
        # Check privileges and adjust arguments if necessary
        # We only fallback if we are NOT root AND we don't have a sudo password
        if not self._is_root() and not self._sudo_password:
            if "-sS" in args:
                logger.warning("Running without root privileges: Switching from SYN scan (-sS) to Connect scan (-sT)")
                args = args.replace("-sS", "-sT")
            
            if "-O" in args:
                logger.warning("Running without root privileges: Disabling OS detection (-O)")
                args = args.replace("-O", "")
        
        # Add interface if specified
        if self._interface:
            args = f"-e {self._interface} {args}"
        
        return args
    
    def execute_scan(
        self,
        progress_callback: Optional[Callable[[float, int], None]] = None,
        log_callback: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> ScanResult:
        """
        Execute the network scan using Nmap.
        
        Args:
            progress_callback: Callback for progress updates.
            log_callback: Callback for log updates (terminal output).
            **kwargs: Additional scan options.
        
        Returns:
            ScanResult with discovered devices.
        """
        self._progress_callback = progress_callback
        self._log_callback = log_callback
        self._is_running = True
        self._is_cancelled = False
        self._cancel_event.clear()
        
        scan_id = kwargs.get("scan_id", f"SCAN_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        result = ScanResult(
            scan_id=scan_id,
            cidr=self._cidr,
            interface=self._interface or "default",
            start_time=datetime.now(),
            scan_type=self._scan_type,
            scan_arguments=self.get_scan_arguments(),
        )
        
        try:
            if not self.validate_cidr():
                raise ValueError(f"Invalid CIDR range: {self._cidr}")
            
            total_hosts = self.get_host_count()
            result.total_hosts_scanned = total_hosts
            
            logger.info(f"Starting Nmap scan: {self._cidr} ({total_hosts} hosts)")
            self._update_progress(5, 0)
            
            # Determine which scan method to use
            arguments = self.get_scan_arguments()
            needs_sudo = (not self._is_root() and 
                         self._sudo_password and 
                         self._requires_root_privileges(arguments))
            
            # Use subprocess if:
            # 1. python-nmap is not available, OR
            # 2. We need to use sudo (library doesn't support sudo)
            if needs_sudo or not (NMAP_AVAILABLE and self._scanner):
                if needs_sudo:
                    logger.debug("Using subprocess method for sudo-elevated scan")
                devices = self._scan_with_subprocess(progress_callback, log_callback)
            else:
                devices = self._scan_with_library(progress_callback)
            
            result.devices = devices
            result.hosts_up = len(devices)
            result.status = "completed"
            
            self._update_progress(100, len(devices))
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            result.status = "failed"
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now()
            self._is_running = False
        
        logger.info(
            f"Scan completed: {result.hosts_up} devices found in "
            f"{result.get_duration():.2f} seconds"
        )
        
        return result
    
    def _scan_with_library(
        self,
        progress_callback: Optional[Callable] = None
    ) -> List[DeviceInfo]:
        """Execute scan using python-nmap library."""
        devices = []
        
        try:
            arguments = self.get_scan_arguments()
            
            # Update progress to show scan is starting
            self._update_progress(7, 0)
            
            # Execute scan
            self._scanner.scan(
                hosts=self._cidr,
                arguments=arguments,
                timeout=self._timeout
            )
            
            all_hosts = self._scanner.all_hosts()
            total = len(all_hosts)
            
            # Update to show hosts discovered
            self._update_progress(10, 0)
            
            for idx, host in enumerate(all_hosts):
                if self._cancel_event.is_set():
                    logger.info("Scan cancelled")
                    break
                
                device = self._parse_host_result(host, self._scanner[host])
                if device:
                    devices.append(device)
                
                progress = 10 + (idx + 1) / max(total, 1) * 85
                self._update_progress(progress, len(devices))
        
        except Exception as e:
            logger.error(f"Library scan error: {e}")
            raise
        
        return devices
    
    def _scan_with_subprocess(
        self,
        progress_callback: Optional[Callable] = None,
        log_callback: Optional[Callable] = None,
    ) -> List[DeviceInfo]:
        """Execute scan using subprocess (fallback method)."""
        devices = []
        
        try:
            arguments = self.get_scan_arguments()
            cmd = [self._nmap_path] + arguments.split() + ["-oX", "-", self._cidr]
            
            input_password = None
            # Only use sudo if:
            # 1. We're not already root
            # 2. We have a sudo password configured
            # 3. The scan arguments require root privileges
            if not self._is_root() and self._sudo_password and self._requires_root_privileges(arguments):
                cmd = ["sudo", "-S", "-p", ""] + cmd
                input_password = self._sudo_password + "\n"
                logger.debug("Using sudo for privileged scan")
            
            cmd_str = ' '.join(cmd).replace(self._sudo_password, '********') if self._sudo_password else ' '.join(cmd)
            logger.debug(f"Running command: {cmd_str}")
            
            if log_callback:
                try:
                    log_callback(f"[CMD] {cmd_str}")
                except:
                    pass
            
            self._current_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if input_password else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            # If we have a password, we need to send it first
            stdin_data = None
            if input_password:
                stdin_data = input_password
            
            # Read all output using communicate to avoid deadlocks
            try:
                stdout, stderr = self._current_process.communicate(input=stdin_data, timeout=self._timeout)
            except subprocess.TimeoutExpired:
                logger.warning("Nmap scan timed out, killing process")
                self._current_process.kill()
                try:
                    stdout, stderr = self._current_process.communicate(timeout=5)
                except:
                    stdout, stderr = "", ""
                
                if log_callback:
                    try:
                        log_callback("[ERROR] Scan timed out")
                    except:
                        pass
                raise TimeoutError(f"Scan timed out after {self._timeout} seconds")
            except Exception as e:
                logger.error(f"Error during communicate: {e}")
                raise
            
            # Process stdout for progress and results
            if stdout:
                hosts_found = 0
                total_hosts = self.get_host_count()
                
                for line in stdout.split('\n'):
                    try:
                        if line and log_callback:
                            log_callback(line)
                    except:
                        pass
                    
                    # Track progress by counting discovered hosts
                    if line and '<host ' in line:
                        hosts_found += 1
                        # Progress from 10% to 95% based on hosts scanned
                        progress = 10 + (hosts_found / max(total_hosts, 1)) * 85
                        progress = min(progress, 95)  # Cap at 95% until scan completes
                        self._update_progress(progress, hosts_found)
            
            if stderr:
                try:
                    if log_callback:
                        log_callback(f"[STDERR] {stderr[:500]}")  # Log first 500 chars only
                except:
                    pass
                
                if self._current_process.returncode != 0:
                    logger.warning(f"Nmap returned non-zero: {stderr[:200]}")
            
            # Parse XML output
            devices = self._parse_xml_output(stdout) if stdout else []
            
        except TimeoutError:
            logger.error("Scan timed out")
            raise
        except Exception as e:
            logger.error(f"Subprocess scan error: {e}")
            if log_callback:
                try:
                    log_callback(f"[ERROR] {str(e)[:100]}")
                except:
                    pass
            raise
        finally:
            self._current_process = None
        
        return devices
    
    def _parse_host_result(
        self,
        host: str,
        host_data: Dict[str, Any]
    ) -> Optional[DeviceInfo]:
        """Parse host result from python-nmap."""
        try:
            device = DeviceInfo(
                ip_address=host,
                status=host_data.get("status", {}).get("state", "unknown"),
                last_seen=datetime.now(),
            )
            
            # Extract hostname
            hostnames = host_data.get("hostnames", [])
            if hostnames and hostnames[0].get("name"):
                device.hostname = hostnames[0]["name"]
                device.device_name = device.hostname
            
            # Extract MAC address and vendor
            addresses = host_data.get("addresses", {})
            if "mac" in addresses:
                device.mac_address = addresses["mac"]
                # Get vendor from Nmap
                device.vendor = host_data.get("vendor", {}).get(device.mac_address, "")
                # Fallback to our vendor lookup
                if not device.vendor:
                    device.vendor = self._vendor_lookup.get_vendor(device.mac_address)
                device.manufacturer = device.vendor
            
            # Extract OS information
            if "osmatch" in host_data and host_data["osmatch"]:
                best_match = host_data["osmatch"][0]
                device.os_info = best_match.get("name", "")
                device.os_accuracy = int(best_match.get("accuracy", 0))
            
            # Extract ports
            for proto in ["tcp", "udp"]:
                if proto in host_data:
                    for port_num, port_data in host_data[proto].items():
                        port_info = PortInfo(
                            port_number=int(port_num),
                            protocol=proto,
                            state=port_data.get("state", "unknown"),
                            service=port_data.get("name", ""),
                            version=port_data.get("version", ""),
                            product=port_data.get("product", ""),
                            extra_info=port_data.get("extrainfo", ""),
                        )
                        device.ports.append(port_info)
            
            # Fingerprint device type
            device.device_type = self._fingerprinter.identify_device_type(device)
            
            device.raw_data = dict(host_data)
            
            return device
        
        except Exception as e:
            logger.error(f"Error parsing host {host}: {e}")
            return None
    
    def _parse_xml_output(self, xml_output: str) -> List[DeviceInfo]:
        """Parse Nmap XML output."""
        import xml.etree.ElementTree as ET
        
        devices = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall(".//host"):
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue
                
                # Get IP address
                address = host.find("address[@addrtype='ipv4']")
                if address is None:
                    continue
                
                device = DeviceInfo(
                    ip_address=address.get("addr", ""),
                    status="up",
                    last_seen=datetime.now(),
                )
                
                # Get MAC address
                mac_addr = host.find("address[@addrtype='mac']")
                if mac_addr is not None:
                    device.mac_address = mac_addr.get("addr", "")
                    device.vendor = mac_addr.get("vendor", "")
                    if not device.vendor:
                        device.vendor = self._vendor_lookup.get_vendor(device.mac_address)
                    device.manufacturer = device.vendor
                
                # Get hostname
                hostname = host.find(".//hostname")
                if hostname is not None:
                    device.hostname = hostname.get("name", "")
                    device.device_name = device.hostname
                
                # Get OS info
                osmatch = host.find(".//osmatch")
                if osmatch is not None:
                    device.os_info = osmatch.get("name", "")
                    device.os_accuracy = int(osmatch.get("accuracy", 0))
                
                # Get ports
                for port in host.findall(".//port"):
                    state = port.find("state")
                    service = port.find("service")
                    
                    port_info = PortInfo(
                        port_number=int(port.get("portid", 0)),
                        protocol=port.get("protocol", "tcp"),
                        state=state.get("state", "unknown") if state is not None else "unknown",
                        service=service.get("name", "") if service is not None else "",
                        version=service.get("version", "") if service is not None else "",
                        product=service.get("product", "") if service is not None else "",
                    )
                    device.ports.append(port_info)
                
                # Fingerprint device type
                device.device_type = self._fingerprinter.identify_device_type(device)
                
                devices.append(device)
        
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
        
        return devices
    
    def cancel_scan(self) -> bool:
        """Cancel the running scan."""
        self._is_cancelled = True
        self._cancel_event.set()
        
        if self._current_process:
            try:
                self._current_process.terminate()
                self._current_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._current_process.kill()
            self._current_process = None
        
        self._is_running = False
        logger.info("Scan cancelled")
        return True
    
    def quick_host_discovery(self) -> List[str]:
        """
        Perform quick host discovery (ping scan).
        
        Returns:
            List of live host IP addresses.
        """
        live_hosts = []
        
        try:
            cmd = [self._nmap_path, "-sn", "-T4", self._cidr]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse output for IP addresses
            ip_pattern = r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)"
            matches = re.findall(ip_pattern, result.stdout)
            live_hosts = matches
            
        except Exception as e:
            logger.error(f"Host discovery failed: {e}")
        
        return live_hosts
    
    @staticmethod
    def check_nmap_installed() -> bool:
        """Check if Nmap is installed and accessible."""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    @staticmethod
    def get_nmap_version() -> Optional[str]:
        """Get the installed Nmap version."""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(r"Nmap version (\d+\.\d+)", result.stdout)
                if match:
                    return match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None
