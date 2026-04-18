<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

try {
    $db_path = __DIR__ . '/../database.db';
    $db = new PDO("sqlite:" . $db_path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Prevent DB hanging when PHP and Python access simultaneously:
    // Reference 1: https://x.com/meln1k/status/1813314113705062774
    // Reference 2: https://sqlite.org/wal.html
    // Reference 3: Wherever Chelle got her information from
    // Reference 4: https://mohit-bhalla.medium.com/understanding-wal-mode-in-sqlite-boosting-performance-in-sql-crud-operations-for-ios-5a8bd8be93d2
    // WAL mode allows concurrent reads during Python's writes
    $db->exec("PRAGMA journal_mode=WAL;");
    // Wait up to 8 seconds instead of immediately failing with SQLITE_BUSY
    $db->exec("PRAGMA busy_timeout=8000;");


    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );");

    $db->exec("CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE NOT NULL,
        case_password TEXT NOT NULL,
        case_name TEXT NOT NULL,
        investigator TEXT NOT NULL,
        status TEXT DEFAULT 'Open', -- 'Open' or 'Closed'
        date_created DATETIME DEFAULT CURRENT_TIMESTAMP
    );");

    // A shared table that holds forensic results
    $db->exec("CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool TEXT,           -- Autopsy, Wireshark, etc.
        artifact_type TEXT,  -- IP Address, File Name, Registry Key
        value TEXT,          -- The actual data found
        severity TEXT,       -- High, Medium, Low
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        evidence_id INTEGER, -- Links to evidence.id
        case_id TEXT         -- Links to cases.case_id
    );");

    // Evidence Table to track files
    $db->exec("CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        source_program TEXT NOT NULL, -- Wireshark, Autopsy, etc.
        upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        parse_status TEXT DEFAULT 'pending', -- pending | processing | done | error
        artifact_count INTEGER DEFAULT 0,
        file_hash TEXT -- SHA256 hash of the file for integrity verification
    );");

    // Migrate existing evidence tables that predate these columns (safe to run every time)
    try { $db->exec("ALTER TABLE evidence ADD COLUMN parse_status TEXT DEFAULT 'pending';"); } catch (PDOException $e) {}
    try { $db->exec("ALTER TABLE evidence ADD COLUMN artifact_count INTEGER DEFAULT 0;"); } catch (PDOException $e) {}
    try { $db->exec("ALTER TABLE evidence ADD COLUMN file_hash TEXT;"); } catch (PDOException $e) {}

} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}
?>