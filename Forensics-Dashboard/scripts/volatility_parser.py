# Volatility 3 Parser - Extract artifacts from Volatility memory analysis
# Parses CSV files generated from Volatility 3 plugins (pslist, netscan, handles, services, etc.)


import sys
import csv
import sqlite3
import os
import logging
from datetime import datetime

# ─── Config ───────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def find_db(start_dir, filename='database.db', max_levels=5):
    # Walk up the directory tree until database.db with evidence table is found
    current = start_dir
    for _ in range(max_levels):
        candidate = os.path.join(current, filename)
        if os.path.exists(candidate):
            # Validate that this database has the evidence table
            try:
                test_conn = sqlite3.connect(candidate, timeout=5)
                cursor = test_conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence'")
                has_table = cursor.fetchone() is not None
                test_conn.close()
                if has_table:
                    return candidate
            except Exception:
                pass
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    raise FileNotFoundError(
        f"Could not find '{filename}' with 'evidence' table within {max_levels} levels above: {start_dir}"
    )

DB_PATH      = "../../database.db"
PROJECT_ROOT = os.path.dirname(DB_PATH)
print(f"[volatility_parser] DB path     : {DB_PATH}")
print(f"[volatility_parser] Project root: {PROJECT_ROOT}")

# Setup logging with error handling
log_dir = os.path.join(PROJECT_ROOT, 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'parser.log')
handlers = [logging.StreamHandler()]
try:
    handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
except (PermissionError, OSError):
    print(f"Warning: Could not write to {log_file}", file=sys.stderr)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [Volatility] %(message)s',
    handlers=handlers
)
logger = logging.getLogger(__name__)

def resolve_path(stored_path):
    # Find the uploaded file regardless of how PHP stored the path.
    # Already absolute and exists — use it directly
    if os.path.isabs(stored_path) and os.path.exists(stored_path):
        return stored_path

    # Extract the meaningful tail: e.g. "uploads/case_51/1234_file.csv"
    normalized = stored_path.replace('\\', '/')
    parts = [p for p in normalized.split('/') if p not in ('..', '.', '')]
    tail = os.path.join(*parts) if parts else stored_path

    # Walk up from SCRIPT_DIR and try joining tail at each level
    current = SCRIPT_DIR
    for _ in range(6):
        candidate = os.path.join(current, tail)
        if os.path.exists(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    
    # Fallback: return the normalized path even if not found
    # (error will be caught in main parse function)
    return os.path.join(PROJECT_ROOT, tail)

def get_evidence_details(conn, evidence_id):
    # Get evidence file path and case_id from database
    cursor = conn.cursor()
    cursor.execute("SELECT file_path, case_id FROM evidence WHERE id = ?", (evidence_id,))
    result = cursor.fetchone()
    if result:
        return result[0], result[1]
    return None, None

def parse_volatility_csv(file_path, case_id, evidence_id, conn):
    # Parse Volatility 3 CSV export and extract memory artifacts
    # Resolve the file path
    resolved_path = resolve_path(file_path)
    logger.info(f"Stored path: {file_path}")
    logger.info(f"Resolved path: {resolved_path}")
    
    if not os.path.exists(resolved_path):
        raise FileNotFoundError(f"Evidence file not found at: {resolved_path}")
    
    logger.info(f"Opening file: {resolved_path} (size: {os.path.getsize(resolved_path)} bytes)")
    file_path = resolved_path
    artifacts = []
    artifact_count = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("CSV file is empty or has no headers")
            
            for row in reader:
                # Skip empty rows
                if not any(row.values()):
                    continue
                
                # Determine artifact type and severity based on Volatility plugin output
                # Support both old-style and new-style volatility CSV formats
                
                plugin = row.get('Plugin', '').strip()
                pid = row.get('PID', '')
                ppid = row.get('PPID', '')
                process_name = row.get('Process Name', '')
                artifact_type_col = row.get('Artifact', '')
                value_col = row.get('Value', '')
                severity_col = row.get('Severity', '')
                notes = row.get('Notes', '')
                creation_time = row.get('Creation Time', '')
                
                # Default to provided values if available
                artifact_type = artifact_type_col if artifact_type_col else "Unknown"
                value = value_col if value_col else ""
                severity = severity_col if severity_col else "Medium"
                
                # Enhanced extraction based on plugin type
                value_parts = []
                
                # pslist - Process listing
                if plugin == 'pslist' or ('PID' in row and 'Process Name' in row):
                    if not value:
                        if ppid:
                            value_parts.append(f"PID: {pid}")
                            value_parts.append(f"Parent PID: {ppid}")
                        value_parts.append(f"Process: {process_name}")
                        if creation_time:
                            value_parts.append(f"Created: {creation_time}")
                        if row.get('Threads'):
                            value_parts.append(f"Threads: {row.get('Threads')}")
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                    if not artifact_type_col:
                        artifact_type = "Process"
                
                # netscan - Network connections
                elif plugin == 'netscan' or 'Network Connection' in value_col:
                    if not artifact_type_col:
                        artifact_type = "Network Connection"
                    if process_name:
                        value_parts.append(f"Process: {process_name}")
                    if pid:
                        value_parts.append(f"PID: {pid}")
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                
                # cmdline - Command line arguments
                elif plugin == 'cmdline' or 'Command' in artifact_type_col:
                    if not artifact_type_col:
                        artifact_type = "Command Line"
                    if process_name:
                        value_parts.append(f"Process: {process_name}")
                    if pid:
                        value_parts.append(f"PID: {pid}")
                    if creation_time:
                        value_parts.append(f"Time: {creation_time}")
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                
                # dlllist - Loaded DLLs
                elif plugin == 'dlllist' or 'DLL' in artifact_type_col:
                    if not artifact_type_col:
                        artifact_type = "Loaded DLL"
                    if process_name:
                        value_parts.append(f"Process: {process_name}")
                    if pid:
                        value_parts.append(f"PID: {pid}")
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                
                # malfind - Injected memory/shellcode
                elif plugin == 'malfind' or 'Memory Injection' in artifact_type_col:
                    if not artifact_type_col:
                        artifact_type = "Memory Injection"
                    if process_name:
                        value_parts.append(f"Process: {process_name}")
                    if pid:
                        value_parts.append(f"PID: {pid}")
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                    severity = "Critical"
                
                # hashdump - Extracted credentials
                elif plugin == 'hashdump' or 'Credential' in artifact_type_col:
                    if not artifact_type_col:
                        artifact_type = "Credential Dump"
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                    severity = "Critical"
                
                # shimcache - Execution history
                elif plugin == 'shimcache' or 'Execution History' in artifact_type_col:
                    if not artifact_type_col:
                        artifact_type = "Execution History"
                    if creation_time:
                        value_parts.append(f"Time: {creation_time}")
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                
                # userassist - User activity
                elif plugin == 'userassist' or 'User Activity' in artifact_type_col:
                    if not artifact_type_col:
                        artifact_type = "User Activity"
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                
                # Registry persistence
                elif plugin == 'printkey' or 'Registry' in artifact_type_col or 'Persistence' in artifact_type_col:
                    if not artifact_type_col:
                        artifact_type = "Registry"
                    if notes:
                        value_parts.append(f"Analysis: {notes}")
                    if 'persistence' in notes.lower() or 'persistence' in value.lower() or 'run' in value.lower():
                        severity = "Critical"
                
                # Append any extra analysis notes
                if value_parts:
                    value = " | ".join(value_parts) if not value else f"{value} | {' | '.join(value_parts)}"
                
                if value.strip():
                    artifacts.append({
                        'tool': 'Volatility',
                        'artifact_type': artifact_type,
                        'value': value[:500],  # Limit to 500 chars
                        'severity': severity,
                        'evidence_id': evidence_id,
                        'case_id': case_id
                    })
                    artifact_count += 1
    
    except csv.Error as e:
        raise ValueError(f"CSV parsing error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Error parsing file: {str(e)}")
    
    return artifacts

def save_artifacts(conn, artifacts):
    # Save extracted artifacts to database
    cursor = conn.cursor()
    for artifact in artifacts:
        cursor.execute("""
            INSERT INTO artifacts (tool, artifact_type, value, severity, timestamp, evidence_id, case_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            artifact['tool'],
            artifact['artifact_type'],
            artifact['value'],
            artifact['severity'],
            datetime.now().isoformat(),
            artifact['evidence_id'],
            artifact['case_id']
        ))
    conn.commit()

def update_evidence_status(conn, evidence_id, status, artifact_count):
    # Update evidence parsing status and artifact count
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE evidence SET parse_status = ?, artifact_count = ? WHERE id = ?",
        (status, artifact_count, evidence_id)
    )
    conn.commit()

def main():
    if len(sys.argv) < 2:
        logger.error("Usage: volatility_parser.py <evidence_id>")
        sys.exit(1)
    
    evidence_id = sys.argv[1]
    logger.info(f"Starting Volatility parser for evidence_id: {evidence_id}")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        
        # Get evidence file details
        file_path, case_id = get_evidence_details(conn, evidence_id)
        if not file_path or not case_id:
            logger.error(f"Evidence ID {evidence_id} not found in database")
            update_evidence_status(conn, evidence_id, 'error', 0)
            sys.exit(1)
        
        resolved_path = resolve_path(file_path)
        print(f"[volatility_parser] Evidence ID   : {evidence_id}")
        print(f"[volatility_parser] Case ID       : {case_id}")
        print(f"[volatility_parser] Stored path   : {file_path}")
        print(f"[volatility_parser] Resolved to   : {resolved_path}")
        print(f"[volatility_parser] File exists   : {os.path.exists(resolved_path)}")
        
        logger.info(f"Found evidence file: {file_path} (case: {case_id})")
        
        # Update status to processing
        update_evidence_status(conn, evidence_id, 'processing', 0)
        logger.info(f"Updated evidence status to: processing")
        
        # Parse the file
        logger.info(f"Starting to parse Volatility CSV file...")
        artifacts = parse_volatility_csv(file_path, case_id, evidence_id, conn)
        logger.info(f"Successfully parsed {len(artifacts)} artifacts")
        
        # Save artifacts
        logger.info(f"Saving {len(artifacts)} artifacts to database...")
        save_artifacts(conn, artifacts)
        logger.info(f"Artifacts saved successfully")
        
        # Update status to done
        update_evidence_status(conn, evidence_id, 'done', len(artifacts))
        logger.info(f"Updated evidence status to: done with {len(artifacts)} artifacts")
        
    except FileNotFoundError as e:
        logger.error(f"File error: {str(e)}")
        try:
            update_evidence_status(conn, evidence_id, 'error', 0)
        except:
            pass
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Parse error: {str(e)}")
        try:
            update_evidence_status(conn, evidence_id, 'error', 0)
        except:
            pass
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        try:
            update_evidence_status(conn, evidence_id, 'error', 0)
        except:
            pass
        sys.exit(1)
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    main()
