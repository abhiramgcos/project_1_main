
"""
Database Initialization Script.

Run this script to initialize the database schema.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger
from soc_iot_toolkit.database.connection import init_database, get_db_connection
from soc_iot_toolkit.config import get_settings


def main():
    """Initialize the database."""
    print("=" * 60)
    print("SOC IoT Toolkit - Database Initialization")
    print("=" * 60)
    
    settings = get_settings()
    
    print(f"\nDatabase Configuration:")
    print(f"  Host: {settings.database.host}")
    print(f"  Port: {settings.database.port}")
    print(f"  Database: {settings.database.name}")
    print(f"  User: {settings.database.user}")
    
    try:
        # Initialize database and create tables
        print("\nInitializing database connection...")
        db = init_database()
        
        # Test connection
        print("Testing connection...")
        if db.test_connection():
            print("Connection successful!")
        else:
            print("Connection failed!")
            sys.exit(1)
        
        print("\nDatabase tables created successfully!")
        print("\nInitialization complete.")
        
    except Exception as e:
        print(f"\nError: {e}")
        print("\nPlease ensure:")
        print("  1. PostgreSQL is running")
        print("  2. Database exists")
        print("  3. User has proper permissions")
        print("  4. Connection settings in .env are correct")
        sys.exit(1)


if __name__ == "__main__":
    main()
