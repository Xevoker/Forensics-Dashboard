import csv
import sqlite3
import sys
import os

def parse_wireshark(case_id):
    db_path = os.path.join(os.path.dirname(__file__), '../database.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Find file info
    cursor.execute("SELECT id, file_path FROM evidence WHERE case_id = ? AND source_program = 'Wireshark' ORDER BY id DESC LIMIT 1", (case_id,))
    file_data = cursor.fetchone()

    if not file_data:
        return

    evidence_id, file_path = file_data
    abs_path = os.path.join(os.path.dirname(__file__), '..', file_path.replace('../', ''))

    try:
        with open(abs_path, mode='r', encoding='utf-8') as csvfile:
                    reader = csv.reader(csvfile)
                    headers = next(reader) # Skips: "No.","Time","Source","Destination", etc.
                    
                    count = 0
                    for row in reader:
                        if count > 100: break
                        
                        # Mapping your specific Wireshark columns by index:
                        # 2=Source, 3=Destination, 4=Protocol, 6=Info
                        try:
                            src  = row[2]
                            dest = row[3]
                            prot = row[4]
                            info = row[6]
                        except IndexError:
                            continue

                        # UNIVERSALIZING: We combine multiple columns into one 'value' string
                        summary = f"[{prot}] {src} -> {dest} | {info}"
                        
                        cursor.execute("""
                            INSERT INTO artifacts (tool, artifact_type, value, severity, case_id, evidence_id) 
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, ('Wireshark', 'Network Packet', summary, 'Low', case_id, evidence_id))
                        count += 1
                
        conn.commit()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    parse_wireshark(sys.argv[1])