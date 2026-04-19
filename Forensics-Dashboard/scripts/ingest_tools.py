#Exports data from csv files and slaps it into the pages when run.
import sqlite3
import csv
import os

# Find th eos by going up two levels from the scripts folder.
db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'database.db')

def ingest_csv(tool_name, file_path):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    with open(file_path, mode='r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Map CSV columns to DB columns
            # Assumes CSV file has 'Type' and 'Detail' columns
            cursor.execute("INSERT INTO artifacts (tool, artifact_type, value, severity) VALUES (?, ?, ?, ?)", (tool_name, row['Type'], row['Detail'], 'Medium'))
    conn.commit()
    conn.close()
    print(f"Success! {tool_name} data moved to Dashboard.")