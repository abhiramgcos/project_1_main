"""
Logging Configuration Module.

Provides consistent logging across the application.
"""

import sys
from pathlib import Path
from typing import Optional
from loguru import logger

from ..config import get_settings


def setup_logger(
    level: Optional[str] = None,
    log_dir: Optional[str] = None,
    rotation: str = "10 MB",
    retention: str = "30 days",
) -> None:
    """
    Configure the application logger.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
        log_dir: Directory for log files.
        rotation: When to rotate log files.
        retention: How long to keep log files.
    """
    settings = get_settings()
    
    level = level or settings.app.log_level
    log_dir = log_dir or settings.app.log_dir
    
    # Remove default handler
    logger.remove()
    
    # Console handler with formatting
    logger.add(
        sys.stderr,
        level=level,
        format="<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
               "<level>{message}</level>",
        colorize=True,
    )
    
    # Create log directory
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    
    # File handler for all logs
    logger.add(
        log_path / "soc_toolkit_{time:YYYY-MM-DD}.log",
        level=level,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
               "{name}:{function}:{line} | {message}",
        rotation=rotation,
        retention=retention,
        compression="gz",
    )
    
    # Separate error log
    logger.add(
        log_path / "errors_{time:YYYY-MM-DD}.log",
        level="ERROR",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
               "{name}:{function}:{line} | {message}\n{exception}",
        rotation=rotation,
        retention=retention,
        compression="gz",
    )
    
    logger.info(f"Logger initialized with level: {level}")


def get_logger(name: str = None):
    """
    Get a logger instance.
    
    Args:
        name: Optional logger name for context.
    
    Returns:
        Logger instance.
    """
    if name:
        return logger.bind(name=name)
    return logger


class LoggerContext:
    """Context manager for logging operations."""
    
    def __init__(self, operation: str, **kwargs):
        """
        Initialize logger context.
        
        Args:
            operation: Name of the operation being logged.
            **kwargs: Additional context to include in logs.
        """
        self.operation = operation
        self.context = kwargs
    
    def __enter__(self):
        logger.info(f"Starting {self.operation}", **self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            logger.error(
                f"Failed {self.operation}: {exc_val}",
                exc_info=(exc_type, exc_val, exc_tb),
                **self.context
            )
        else:
            logger.info(f"Completed {self.operation}", **self.context)
        return False
