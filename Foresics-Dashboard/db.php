<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

try {
    $db_path = __DIR__ . '/../database.db';
    $db = new PDO("sqlite:" . $db_path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

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
        upload_date DATETIME DEFAULT CURRENT_TIMESTAMP
    );");

} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}
?>