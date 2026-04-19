# Autopsy Parser - Extract artifacts from Autopsy CSV exports
# Parses CSV files generated from Autopsy (file system artifacts, timeline data, keyword hits)

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
print(f"[autopsy_parser] DB path     : {DB_PATH}")
print(f"[autopsy_parser] Project root: {PROJECT_ROOT}")

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
    format='[%(asctime)s] [%(levelname)s] [Autopsy] %(message)s',
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

def parse_autopsy_csv(file_path, case_id, evidence_id, conn):
    # Parse Autopsy CSV export and extract artifacts
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
                
                # Determine artifact type based on columns present
                file_name = row.get('File Name', '')
                file_path_val = row.get('File Path', '')
                file_size = row.get('File Size (Bytes)', '')
                md5_hash = row.get('MD5 Hash', '')
                sha256_hash = row.get('SHA-256 Hash', '')
                modified_date = row.get('Modified Date', '')
                tags = row.get('Tags', '')
                comments = row.get('Comments', '')
                flagged = row.get('Flagged', 'No')
                deleted = row.get('Deleted', 'No')
                
                # Determine severity based on tags and flags
                severity = "Low"
                if flagged == 'Yes':
                    severity = "High"
                elif tags:
                    tag_list = tags.lower()
                    if any(s in tag_list for s in ['malware', 'suspicious', 'exfiltration', 'credentials']):
                        severity = "High"
                    elif any(s in tag_list for s in ['deleted', 'recovered']):
                        severity = "Medium"
                
                # Build comprehensive artifact value
                value_parts = []
                
                # File location and metadata
                if file_path_val:
                    value_parts.append(f"Path: {file_path_val}")
                if file_size:
                    try:
                        size_mb = float(file_size) / (1024*1024)
                        value_parts.append(f"Size: {size_mb:.2f}MB")
                    except:
                        value_parts.append(f"Size: {file_size} bytes")
                
                # Hashes for integrity verification
                if md5_hash:
                    value_parts.append(f"MD5: {md5_hash}")
                if sha256_hash:
                    value_parts.append(f"SHA256: {sha256_hash}")
                
                # Timeline information
                if modified_date:
                    value_parts.append(f"Modified: {modified_date}")
                if deleted == 'Yes':
                    value_parts.append("DELETED")
                
                # Forensic tags and analyst notes
                if tags:
                    value_parts.append(f"Tags: {tags}")
                if comments:
                    value_parts.append(f"Notes: {comments}")
                
                artifact_type = "File"
                if deleted == 'Yes':
                    artifact_type = "Deleted File"
                
                value = " | ".join(value_parts)
                
                if value.strip():
                    artifacts.append({
                        'tool': 'Autopsy',
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
        logger.error("Usage: autopsy_parser.py <evidence_id>")
        sys.exit(1)
    
    evidence_id = sys.argv[1]
    logger.info(f"Starting Autopsy parser for evidence_id: {evidence_id}")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        
        # Get evidence file details
        file_path, case_id = get_evidence_details(conn, evidence_id)
        if not file_path or not case_id:
            logger.error(f"Evidence ID {evidence_id} not found in database")
            update_evidence_status(conn, evidence_id, 'error', 0)
            sys.exit(1)
        
        resolved_path = resolve_path(file_path)
        print(f"[autopsy_parser] Evidence ID   : {evidence_id}")
        print(f"[autopsy_parser] Case ID       : {case_id}")
        print(f"[autopsy_parser] Stored path   : {file_path}")
        print(f"[autopsy_parser] Resolved to   : {resolved_path}")
        print(f"[autopsy_parser] File exists   : {os.path.exists(resolved_path)}")
        
        logger.info(f"Found evidence file: {file_path} (case: {case_id})")
        
        # Update status to processing
        update_evidence_status(conn, evidence_id, 'processing', 0)
        logger.info(f"Updated evidence status to: processing")
        
        # Parse the file
        logger.info(f"Starting to parse Autopsy CSV file...")
        artifacts = parse_autopsy_csv(file_path, case_id, evidence_id, conn)
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
