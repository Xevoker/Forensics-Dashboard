import sys
import sqlite3
import csv
import os

# Fix Windows console encoding issues with Unicode characters
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ─── Config ───────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BATCH_SIZE = 200

def find_db(start_dir, filename='database.db', max_levels=5):
    """Walk up the directory tree until database.db is found.
    Handles mismatched nesting (e.g. htdocs/Forensics-Dashboard/Forensics-Dashboard/scripts/).
    """
    current = start_dir
    for _ in range(max_levels):
        candidate = os.path.join(current, filename)
        if os.path.exists(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break  # reached filesystem root
        current = parent
    raise FileNotFoundError(
        f"Could not find '{filename}' within {max_levels} levels above:\n  {start_dir}\n"
        f"Make sure the database exists and this script is inside your project folder."
    )

DB_PATH      = find_db(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(DB_PATH)
print(f"[wireshark_parser] DB path     : {DB_PATH}")
print(f"[wireshark_parser] Project root: {PROJECT_ROOT}")
# ──────────────────────────────────────────────────────────────────────────────

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=8000;")
    return conn

def get_evidence_details(conn, evidence_id):
    cur = conn.execute(
        """SELECT id, case_id, file_path FROM evidence WHERE id = ?""",
        (evidence_id,)
    )
    return cur.fetchone()

def already_parsed(conn, evidence_id):
    cur = conn.execute(
        "SELECT COUNT(*) FROM artifacts WHERE evidence_id = ?",
        (evidence_id,)
    )
    return cur.fetchone()[0] > 0

def resolve_path(stored_path):
    """
    Find the uploaded file regardless of how PHP stored the path.
    PHP stores a path relative to includes/ (e.g. ../uploads/file.csv).
    We strip the relative prefix and search every parent directory of the
    script for a matching uploads/filename, so nested folder structures
    (e.g. htdocs/Forensics-Dashboard/Foresics-Dashboard/) work automatically.
    """
    # Already absolute and exists — use it directly
    if os.path.isabs(stored_path) and os.path.exists(stored_path):
        return stored_path

    # Extract just the meaningful tail: e.g. "uploads/1234_file.csv"
    normalized = stored_path.replace('\\', '/')
    parts = [p for p in normalized.split('/') if p not in ('..', '.', '')]
    tail = os.path.join(*parts)  # e.g. "uploads\1234_file.csv"

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

    # Last resort: return PROJECT_ROOT join so error message shows a useful path
    return os.path.join(PROJECT_ROOT, tail)

def detect_columns(header_row):
    """
    Auto-detect Wireshark column names — exports differ slightly depending
    on Wireshark version and whether the user customised columns.
    Returns a dict mapping our internal keys to the actual CSV column name.
    """
    h = {col.strip().strip('"').lower(): col for col in header_row}

    def find(candidates):
        for c in candidates:
            if c in h:
                return h[c]
        return None

    return {
        'source':      find(['source', 'src', 'ip src']),
        'destination': find(['destination', 'dst', 'dest', 'ip dst']),
        'protocol':    find(['protocol', 'proto']),
        'info':        find(['info', 'description']),
        'time':        find(['time', 'timestamp', 'relative time']),
    }

def parse_wireshark_csv(file_path, case_id, evidence_id):
    # Check if file is binary PCAP format
    with open(file_path, 'rb') as f:
        header = f.read(4)
        if header == b'\xa1\xb2\xc3\xd4' or header == b'\xd4\xc3\xb2\xa1':
            # This is a PCAP binary file, not CSV
            raise ValueError(
                "File is a binary PCAP file, not a CSV export. "
                "Please export from Wireshark as CSV (File > Export Packet List > CSV) "
                "or use tshark to convert: tshark -r file.pcap -T csv > file.csv"
            )
    
    with open(file_path, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        cols = detect_columns(reader.fieldnames or [])

        print(f"[wireshark_parser] CSV columns detected: {reader.fieldnames}")
        print(f"[wireshark_parser] Mapped to: {cols}")

        for row in reader:
            src   = row.get(cols['source']      or '', '').strip()
            dst   = row.get(cols['destination'] or '', '').strip()
            proto = row.get(cols['protocol']    or '', '').strip()
            info  = row.get(cols['info']        or '', '').strip()
            ts    = row.get(cols['time']        or '', '').strip()

            if not src and not dst:
                continue

            if proto in ('DNS', 'HTTP', 'MDNS', 'SSDP'):
                severity = 'Low'
            elif proto in ('TLS', 'HTTPS', 'FTP', 'TELNET', 'SSH'):
                severity = 'Medium'
            elif proto in ('TCP', 'UDP', 'ICMP'):
                severity = 'Low'
            else:
                severity = 'High'

            yield {
                'tool':          'Wireshark',
                'artifact_type': proto or 'Network Packet',
                'value':         f"{src} → {dst} | {info[:200]}",
                'severity':      severity,
                'timestamp':     ts,
                'evidence_id':   evidence_id,
                'case_id':       case_id,
            }

def insert_batch(conn, batch):
    conn.executemany(
        """INSERT INTO artifacts
               (tool, artifact_type, value, severity, timestamp, evidence_id, case_id)
           VALUES (:tool, :artifact_type, :value, :severity, :timestamp, :evidence_id, :case_id)""",
        batch
    )
    conn.commit()

def set_status(conn, evidence_id, status, artifact_count=None):
    if artifact_count is not None:
        conn.execute(
            "UPDATE evidence SET parse_status = ?, artifact_count = ? WHERE id = ?",
            (status, artifact_count, evidence_id)
        )
    else:
        conn.execute(
            "UPDATE evidence SET parse_status = ? WHERE id = ?",
            (status, evidence_id)
        )
    conn.commit()

def run(evidence_id):
    conn = get_connection()

    # Ensure status columns exist (safe migration)
    try:
        conn.execute("ALTER TABLE evidence ADD COLUMN parse_status TEXT DEFAULT 'pending';")
        conn.commit()
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE evidence ADD COLUMN artifact_count INTEGER DEFAULT 0;")
        conn.commit()
    except Exception:
        pass

    row = get_evidence_details(conn, evidence_id)
    if not row:
        print(f"[wireshark_parser] No evidence found with ID '{evidence_id}'.")
        conn.close()
        return

    evidence_id_val, case_id, stored_path = row
    file_path = resolve_path(stored_path)

    print(f"[wireshark_parser] Evidence ID   : {evidence_id_val}")
    print(f"[wireshark_parser] Case ID       : {case_id}")
    print(f"[wireshark_parser] Stored path   : {stored_path}")
    print(f"[wireshark_parser] Resolved to   : {file_path}")
    print(f"[wireshark_parser] File exists   : {os.path.exists(file_path)}")

    if already_parsed(conn, evidence_id_val):
        print(f"[wireshark_parser] Evidence ID {evidence_id_val} already parsed. Skipping.")
        conn.close()
        return

    if not os.path.exists(file_path):
        set_status(conn, evidence_id_val, 'error')
        print(f"[wireshark_parser] ERROR: File not found at resolved path: {file_path}")
        conn.close()
        return

    print(f"[wireshark_parser] Parsing for case '{case_id}'...")
    set_status(conn, evidence_id_val, 'processing', 0)

    total = 0
    try:
        batch = []
        for artifact in parse_wireshark_csv(file_path, case_id, evidence_id_val):
            batch.append(artifact)
            if len(batch) >= BATCH_SIZE:
                insert_batch(conn, batch)
                total += len(batch)
                batch.clear()
                set_status(conn, evidence_id_val, 'processing', total)
                print(f"[wireshark_parser] {total} rows inserted...")

        if batch:
            insert_batch(conn, batch)
            total += len(batch)

        set_status(conn, evidence_id_val, 'done', total)
        print(f"[wireshark_parser] Done. {total} artifacts inserted for case '{case_id}'.")

    except Exception as e:
        set_status(conn, evidence_id_val, 'error', total)
        print(f"[wireshark_parser] ERROR: {e}")
        import traceback
        traceback.print_exc()

    finally:
        conn.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 wireshark_parser.py <evidence_id>")
        sys.exit(1)
    run(sys.argv[1])