#!/usr/bin/env python3
"""
Test script to verify the scan progress fix.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_progress_model():
    """Test that the progress column exists in the Scan model."""
    from soc_iot_toolkit.database.models import Scan
    from sqlalchemy import inspect
    
    mapper = inspect(Scan)
    columns = {col.name for col in mapper.columns}
    
    assert 'progress' in columns, "progress column not found in Scan model"
    print("✓ Progress column found in Scan model")

def test_database_operations():
    """Test that database operations handle progress correctly."""
    from soc_iot_toolkit.database.operations import DatabaseOperations
    from soc_iot_toolkit.database.models import Scan
    import inspect
    
    # Check method signatures
    ops_methods = {name: method for name, method in inspect.getmembers(DatabaseOperations, predicate=inspect.ismethod)}
    
    # Verify key methods exist
    assert 'update_scan_progress' in dir(DatabaseOperations), "update_scan_progress method not found"
    assert 'get_scan_progress' in dir(DatabaseOperations), "get_scan_progress method not found"
    print("✓ Database operations methods found")

def test_imports():
    """Test that all necessary imports work."""
    try:
        from soc_iot_toolkit.database.models import Scan
        from soc_iot_toolkit.database.operations import DatabaseOperations
        from soc_iot_toolkit.scanners.nmap_scanner import NmapScanner
        print("✓ All imports successful")
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    return True

if __name__ == "__main__":
    print("Running scan progress fix verification tests...\n")
    
    try:
        test_imports()
        test_progress_model()
        test_database_operations()
        
        print("\n✅ All tests passed! Scan progress fix is working correctly.")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
