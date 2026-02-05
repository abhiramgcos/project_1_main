# Scan Progress Bug Fix

## Overview

Fixed an issue where network scans would sometimes get stuck at 0% or 7% progress and never update, making it difficult to track scan completion.

## Root Causes Identified

### 1. **Progress Not Displayed in UI**
The scan progress was being calculated and stored in the database, but the UI was never retrieving or displaying it. The `st.session_state.active_scan` dict was initialized with basic info but never updated with progress information.

### 2. **Missing Progress Column in Database**
The database had no dedicated `progress` field to store the progress percentage. Code was attempting to reuse other fields inappropriately.

### 3. **Initialization Phase Stuck**
During Nmap's initialization phase (before any hosts are discovered), no progress updates were sent, causing the progress bar to remain at the initial value.

### 4. **No Auto-Completion Detection**
The UI didn't check for scan completion, so scans would appear as "running" indefinitely.

## Changes Made

### Database Layer

#### `soc_iot_toolkit/database/models.py`
- Added `progress` column (Float) to the Scan model
```python
progress = Column(Float, default=0.0)  # Progress percentage (0-100)
```

#### `soc_iot_toolkit/database/operations.py`
- Fixed `update_scan_progress()` method to properly use the progress field
- Updated `get_scan_progress()` to return the progress value
- Enhanced `save_scan_result()` to set progress to 100% on completion

### Application Layer

#### `app.py`
- Enhanced `start_scan()` to initialize all progress fields:
  - `progress`: 0 (initial)
  - `status`: "running"
  - `scanned_hosts`: 0
  - `total_hosts`: calculated from CIDR range

- Added `refresh_active_scan_progress()` function:
  - Fetches latest progress from database
  - Updates session state with new values
  - Detects scan completion and loads results

- Updated `_scan_worker()` callback:
  - Sets progress to 100% when scan completes
  - Properly handles failed scans

- Added auto-refresh loop in scan page:
  - Refreshes progress every 1 second
  - Automatically detects completion

### Scanner Layer

#### `soc_iot_toolkit/scanners/nmap_scanner.py`
- Improved subprocess-based progress tracking:
  - Detects initialization phase vs scanning phase
  - Gradually increments progress during init (5-10%)
  - Provides accurate progress during scanning (10-95%)
  - Prevents progress from getting stuck

- Enhanced library-based progress tracking:
  - Added initialization phase indicators
  - Better granular updates

## Progress Scale

The progress is divided into phases:

- **0-5%**: Pre-scan initialization
- **5-10%**: Nmap initialization (gradually increasing)
- **10-95%**: Active scanning (based on hosts discovered)
- **95-100%**: Final processing and results
- **100%**: Scan complete

## Database Migration

### For New Installations
The progress column will be created automatically when the database is initialized.

### For Existing Installations
Run the migration script:
```bash
python scripts/migrate_add_progress.py
```

Or manually execute:
```sql
ALTER TABLE scans ADD COLUMN progress NUMERIC DEFAULT 0.0;
```

## Files Modified

1. `soc_iot_toolkit/database/models.py` - Added progress column
2. `soc_iot_toolkit/database/operations.py` - Fixed progress handling
3. `app.py` - Added progress refresh and auto-update
4. `soc_iot_toolkit/scanners/nmap_scanner.py` - Improved progress tracking

## Files Created

1. `scripts/migrate_add_progress.py` - Database migration script
2. `test_progress_fix.py` - Verification test script
3. `SCAN_PROGRESS_FIX.md` - Technical summary

## Testing

### Verify the Fix

1. Start the application:
   ```bash
   streamlit run app.py
   ```

2. Start a network scan and observe:
   - Progress bar updates smoothly from 0% to 100%
   - No stuck progress at 0% or 7%
   - Progress reflects actual scanning activity
   - Scan automatically transitions to results when complete

3. For existing databases, run:
   ```bash
   python scripts/migrate_add_progress.py
   ```

### Unit Tests

Run the verification script:
```bash
python test_progress_fix.py
```

Expected output:
```
✓ Progress column found in Scan model
✓ Database operations methods found
✓ All imports successful
✅ All tests passed!
```

## Benefits

- **Accurate Progress Tracking**: Real-time progress updates without getting stuck
- **Better UX**: Users can see scan is progressing
- **Automatic Completion**: Scans automatically transition to results
- **Data Integrity**: Progress is stored persistently in database
- **Backward Compatible**: Existing functionality preserved

## Technical Details

### Progress Update Flow
1. Scanner calls `progress_callback()` with percentage and hosts scanned
2. Callback in `_scan_worker()` calls `db_ops.update_scan_progress()`
3. Progress is stored in database
4. UI calls `refresh_active_scan_progress()` every second
5. Session state is updated with latest progress
6. Page rerenders with new progress value

### Initialization Phase Handling
- Before first host is found, progress gradually increases from 5% to 9%
- This shows user that scanning is active, preventing appearance of stuck progress
- Once hosts are found, progress is calculated based on actual discovery

### Completion Detection
- When status changes to "completed", "failed", or "cancelled"
- Results are automatically loaded from database
- UI transitions from progress view to results view
- No manual refresh needed

## Troubleshooting

### Progress Not Updating

1. Check database connection is working
2. Verify progress column exists in scans table
3. Check application logs for errors
4. Restart the application

### Progress Stuck at Low Value

This should no longer happen. If it does:
1. Check Nmap is installed and working: `nmap --version`
2. Check network connectivity for target CIDR
3. Review application logs for scan errors

### Missing Progress Column

Run migration script:
```bash
python scripts/migrate_add_progress.py
```

Or manually add column to existing database:
```sql
ALTER TABLE scans ADD COLUMN progress NUMERIC DEFAULT 0.0;
```

## Performance Impact

- Minimal: One additional database query per second during active scans
- Cache-friendly: Progress updates are lightweight
- No impact on scan performance
- Optional auto-refresh can be disabled if needed

## Future Improvements

- Add configurable progress refresh interval
- Store progress history for analysis
- Implement exponential backoff for progress queries
- Add progress prediction based on host count
