"""
Configuration settings management for SOC IoT Toolkit.

Handles loading configuration from environment variables and config files.
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    host: str = "localhost"
    port: int = 5432
    name: str = "soc_iot_db"
    user: str = "soc_toolkit"
    password: str = ""
    pool_size: int = 5
    max_overflow: int = 10
    
    @property
    def connection_string(self) -> str:
        """Generate SQLAlchemy connection string."""
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
    
    @property
    def async_connection_string(self) -> str:
        """Generate async SQLAlchemy connection string."""
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


@dataclass
class NmapConfig:
    """Nmap scanner configuration settings."""
    path: str = "/usr/bin/nmap"
    arguments: str = "-sS -sV -O -T4"
    timeout: int = 300
    max_retries: int = 3
    sudo_password: Optional[str] = None
    
    # Scan profiles
    quick_scan: str = "-sn -T4"
    standard_scan: str = "-sS -sV -T4"
    deep_scan: str = "-sS -sV -sC -O -T4"
    full_scan: str = "-sS -sV -sC -O -A -T4"


@dataclass
class AppConfig:
    """Application configuration settings."""
    log_level: str = "INFO"
    log_dir: str = "logs"
    scan_timeout: int = 300
    max_concurrent_scans: int = 3
    data_retention_days: int = 90


@dataclass
class UIConfig:
    """Streamlit UI configuration settings."""
    port: int = 8501
    theme: str = "light"
    page_title: str = "SOC IoT Discovery Toolkit"
    page_icon: str = ""
    layout: str = "wide"


@dataclass
class Settings:
    """Main settings container for the application."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    nmap: NmapConfig = field(default_factory=NmapConfig)
    app: AppConfig = field(default_factory=AppConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    
    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables."""
        return cls(
            database=DatabaseConfig(
                host=os.getenv("DB_HOST", "localhost"),
                port=int(os.getenv("DB_PORT", "5432")),
                name=os.getenv("DB_NAME", "soc_iot_db"),
                user=os.getenv("DB_USER", "soc_toolkit"),
                password=os.getenv("DB_PASSWORD", ""),
                pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
                max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
            ),
            nmap=NmapConfig(
                path=os.getenv("NMAP_PATH", "/usr/bin/nmap"),
                arguments=os.getenv("NMAP_ARGUMENTS", "-sS -sV -O -T4"),
                timeout=int(os.getenv("NMAP_TIMEOUT", "300")),
                sudo_password=os.getenv("SUDO_PASSWORD"),
            ),
            app=AppConfig(
                log_level=os.getenv("LOG_LEVEL", "INFO"),
                log_dir=os.getenv("LOG_DIR", "logs"),
                scan_timeout=int(os.getenv("SCAN_TIMEOUT", "300")),
                max_concurrent_scans=int(os.getenv("MAX_CONCURRENT_SCANS", "3")),
            ),
            ui=UIConfig(
                port=int(os.getenv("STREAMLIT_PORT", "8501")),
                theme=os.getenv("UI_THEME", "light"),
            ),
        )


# Singleton instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the singleton settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings


def reload_settings() -> Settings:
    """Reload settings from environment."""
    global _settings
    load_dotenv(override=True)
    _settings = Settings.from_env()
    return _settings
