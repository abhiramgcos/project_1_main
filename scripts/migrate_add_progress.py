#!/usr/bin/env python3
"""
Migration script to add progress column to scans table.

Run this script to update an existing database with the new progress tracking feature.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_iot_toolkit.database.connection import get_db_connection
from sqlalchemy import text
from loguru import logger


def migrate():
    """Add progress column to scans table if it doesn't exist."""
    db = get_db_connection()
    
    try:
        with db.session_scope() as session:
            # Check if progress column exists
            result = session.execute(
                text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='scans' AND column_name='progress'
                """)
            )
            
            if result.fetchone():
                logger.info("Progress column already exists in scans table")
                return True
            
            # Add progress column
            logger.info("Adding progress column to scans table...")
            session.execute(
                text("ALTER TABLE scans ADD COLUMN progress NUMERIC DEFAULT 0.0")
            )
            logger.info("Successfully added progress column")
            return True
            
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return False


if __name__ == "__main__":
    if migrate():
        logger.info("Migration completed successfully")
        sys.exit(0)
    else:
        logger.error("Migration failed")
        sys.exit(1)
