<?php
// Database Connection to SQL Lite and table creation if the tables do not exist
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

try {
    $db_path = __DIR__ . '/../database.db';
    $db = new PDO("sqlite:" . $db_path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Tables Creation
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
        status TEXT DEFAULT 'Open', 
        date_created DATETIME DEFAULT CURRENT_TIMESTAMP
    );");

    $db->exec("CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool TEXT,        
        artifact_type TEXT, 
        value TEXT,          
        severity TEXT,       
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        evidence_id INTEGER, 
        case_id TEXT         
    );");

    $db->exec("CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        source_program TEXT NOT NULL, 
        upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        parse_status TEXT DEFAULT 'pending', 
        artifact_count INTEGER DEFAULT 0,
        file_hash TEXT 
    );");

    // Adding addtional columns to existing tables
    try { $db->exec("ALTER TABLE evidence ADD COLUMN parse_status TEXT DEFAULT 'pending';"); } catch (PDOException $e) {}
    try { $db->exec("ALTER TABLE evidence ADD COLUMN artifact_count INTEGER DEFAULT 0;"); } catch (PDOException $e) {}
    try { $db->exec("ALTER TABLE evidence ADD COLUMN file_hash TEXT;"); } catch (PDOException $e) {}

} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}
?>