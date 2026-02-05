"""
Process Manager Module.

Handles scan process lifecycle, monitoring, and management
for concurrent network scanning operations.
"""

import os
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Callable, Any
from concurrent.futures import ThreadPoolExecutor, Future
from loguru import logger

import psutil


class ProcessState(Enum):
    """Enumeration of process states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class ScanProcess:
    """Represents a scan process with its metadata."""
    process_id: str
    scan_id: str
    state: ProcessState = ProcessState.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    progress: float = 0.0
    total_hosts: int = 0
    scanned_hosts: int = 0
    error_message: Optional[str] = None
    pid: Optional[int] = None
    thread_id: Optional[int] = None
    future: Optional[Future] = field(default=None, repr=False)
    callback: Optional[Callable] = field(default=None, repr=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "process_id": self.process_id,
            "scan_id": self.scan_id,
            "state": self.state.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "progress": self.progress,
            "total_hosts": self.total_hosts,
            "scanned_hosts": self.scanned_hosts,
            "error_message": self.error_message,
            "duration_seconds": self.get_duration(),
        }
    
    def get_duration(self) -> Optional[float]:
        """Get the duration of the scan in seconds."""
        if not self.start_time:
            return None
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()


class ProcessManager:
    """
    Manages scan process lifecycle and monitoring.
    
    Provides methods for:
    - Starting and stopping scan processes
    - Monitoring process progress
    - Managing concurrent scans
    - Process cleanup and resource management
    """
    
    def __init__(self, max_concurrent: int = 3, timeout: int = 300):
        """
        Initialize the ProcessManager.
        
        Args:
            max_concurrent: Maximum number of concurrent scans.
            timeout: Default timeout for scans in seconds.
        """
        self._max_concurrent = max_concurrent
        self._timeout = timeout
        self._processes: Dict[str, ScanProcess] = {}
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        
        self._initialize_executor()
        self._start_monitor()
    
    def _initialize_executor(self) -> None:
        """Initialize the thread pool executor."""
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_concurrent,
            thread_name_prefix="scan_worker"
        )
        logger.info(f"Process executor initialized with {self._max_concurrent} workers")
    
    def _start_monitor(self) -> None:
        """Start the background monitoring thread."""
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="process_monitor",
            daemon=True
        )
        self._monitor_thread.start()
        logger.debug("Process monitor thread started")
    
    def _monitor_loop(self) -> None:
        """Background loop for monitoring process states."""
        while not self._shutdown_event.is_set():
            try:
                self._check_timeouts()
                self._cleanup_completed()
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
            
            time.sleep(5)  # Check every 5 seconds
    
    def _check_timeouts(self) -> None:
        """Check for and handle timed out processes."""
        with self._lock:
            current_time = datetime.now()
            for process in self._processes.values():
                if process.state == ProcessState.RUNNING and process.start_time:
                    duration = (current_time - process.start_time).total_seconds()
                    if duration > self._timeout:
                        logger.warning(f"Process {process.process_id} timed out")
                        self._handle_timeout(process)
    
    def _handle_timeout(self, process: ScanProcess) -> None:
        """Handle a timed out process."""
        process.state = ProcessState.TIMEOUT
        process.end_time = datetime.now()
        process.error_message = f"Scan timed out after {self._timeout} seconds"
        
        if process.future and not process.future.done():
            process.future.cancel()
    
    def _cleanup_completed(self) -> None:
        """Cleanup old completed processes."""
        with self._lock:
            current_time = datetime.now()
            to_remove = []
            
            for pid, process in self._processes.items():
                if process.state in (ProcessState.COMPLETED, ProcessState.FAILED, 
                                    ProcessState.CANCELLED, ProcessState.TIMEOUT):
                    if process.end_time:
                        age = (current_time - process.end_time).total_seconds()
                        # Keep completed processes for 1 hour
                        if age > 3600:
                            to_remove.append(pid)
            
            for pid in to_remove:
                del self._processes[pid]
                logger.debug(f"Cleaned up old process: {pid}")
    
    def generate_process_id(self) -> str:
        """Generate a unique process ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return f"PROC_{timestamp}"
    
    def generate_scan_id(self) -> str:
        """Generate a unique scan ID based on timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"SCAN_{timestamp}"
    
    def submit_scan(
        self,
        scan_function: Callable,
        scan_id: Optional[str] = None,
        total_hosts: int = 0,
        callback: Optional[Callable] = None,
        **kwargs
    ) -> Optional[ScanProcess]:
        """
        Submit a new scan for execution.
        
        Args:
            scan_function: The scanning function to execute.
            scan_id: Optional scan ID (generated if not provided).
            total_hosts: Expected total number of hosts to scan.
            callback: Optional callback function for completion.
            **kwargs: Additional arguments for the scan function.
        
        Returns:
            ScanProcess object or None if submission failed.
        """
        with self._lock:
            # Check concurrent limit
            running_count = sum(
                1 for p in self._processes.values() 
                if p.state == ProcessState.RUNNING
            )
            
            if running_count >= self._max_concurrent:
                logger.warning("Maximum concurrent scans reached")
                return None
            
            # Create process record
            process_id = self.generate_process_id()
            scan_id = scan_id or self.generate_scan_id()
            
            process = ScanProcess(
                process_id=process_id,
                scan_id=scan_id,
                total_hosts=total_hosts,
                callback=callback,
            )
            
            # Submit to executor
            try:
                future = self._executor.submit(
                    self._execute_scan,
                    process,
                    scan_function,
                    **kwargs
                )
                process.future = future
                self._processes[process_id] = process
                
                logger.info(f"Scan submitted: {scan_id} (Process: {process_id})")
                return process
            
            except Exception as e:
                logger.error(f"Failed to submit scan: {e}")
                return None
    
    def _execute_scan(
        self,
        process: ScanProcess,
        scan_function: Callable,
        **kwargs
    ) -> Any:
        """Execute a scan function with process tracking."""
        process.state = ProcessState.RUNNING
        process.start_time = datetime.now()
        process.thread_id = threading.current_thread().ident
        
        try:
            # Execute the scan function
            result = scan_function(
                progress_callback=lambda p, s: self._update_progress(process, p, s),
                **kwargs
            )
            
            process.state = ProcessState.COMPLETED
            process.progress = 100.0
            
            logger.info(f"Scan completed: {process.scan_id}")
            
            # Call completion callback
            if process.callback:
                try:
                    process.callback(process, result)
                except Exception as e:
                    logger.error(f"Error in scan callback: {e}")
            
            return result
        
        except Exception as e:
            process.state = ProcessState.FAILED
            process.error_message = str(e)
            logger.error(f"Scan failed: {process.scan_id} - {e}")
            raise
        
        finally:
            process.end_time = datetime.now()
    
    def _update_progress(
        self, 
        process: ScanProcess, 
        progress: float, 
        scanned: int
    ) -> None:
        """Update process progress."""
        process.progress = min(100.0, max(0.0, progress))
        process.scanned_hosts = scanned
    
    def get_process(self, process_id: str) -> Optional[ScanProcess]:
        """Get a process by its ID."""
        return self._processes.get(process_id)
    
    def get_process_by_scan_id(self, scan_id: str) -> Optional[ScanProcess]:
        """Get a process by its scan ID."""
        for process in self._processes.values():
            if process.scan_id == scan_id:
                return process
        return None
    
    def get_active_processes(self) -> List[ScanProcess]:
        """Get all currently running processes."""
        with self._lock:
            return [
                p for p in self._processes.values()
                if p.state == ProcessState.RUNNING
            ]
    
    def get_all_processes(self) -> List[ScanProcess]:
        """Get all processes."""
        with self._lock:
            return list(self._processes.values())
    
    def cancel_process(self, process_id: str) -> bool:
        """
        Cancel a running process.
        
        Args:
            process_id: ID of the process to cancel.
        
        Returns:
            True if cancellation successful, False otherwise.
        """
        with self._lock:
            process = self._processes.get(process_id)
            
            if not process:
                logger.warning(f"Process not found: {process_id}")
                return False
            
            if process.state != ProcessState.RUNNING:
                logger.warning(f"Process not running: {process_id}")
                return False
            
            process.state = ProcessState.CANCELLED
            process.end_time = datetime.now()
            
            if process.future and not process.future.done():
                process.future.cancel()
            
            logger.info(f"Process cancelled: {process_id}")
            return True
    
    def cancel_all(self) -> int:
        """
        Cancel all running processes.
        
        Returns:
            Number of processes cancelled.
        """
        cancelled = 0
        with self._lock:
            for process in self._processes.values():
                if process.state == ProcessState.RUNNING:
                    if self.cancel_process(process.process_id):
                        cancelled += 1
        
        logger.info(f"Cancelled {cancelled} processes")
        return cancelled
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of process statuses."""
        with self._lock:
            states = {}
            for state in ProcessState:
                states[state.value] = sum(
                    1 for p in self._processes.values() 
                    if p.state == state
                )
            
            return {
                "total": len(self._processes),
                "max_concurrent": self._max_concurrent,
                "states": states,
                "active": [p.to_dict() for p in self.get_active_processes()],
            }
    
    def shutdown(self, wait: bool = True, timeout: float = 30.0) -> None:
        """
        Shutdown the process manager.
        
        Args:
            wait: Whether to wait for running processes.
            timeout: Maximum time to wait for shutdown.
        """
        logger.info("Shutting down process manager")
        
        self._shutdown_event.set()
        
        if not wait:
            self.cancel_all()
        
        if self._executor:
            self._executor.shutdown(wait=wait, cancel_futures=not wait)
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
        
        logger.info("Process manager shutdown complete")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
        return False
