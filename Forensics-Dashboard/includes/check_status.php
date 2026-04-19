<?php
/**
 * check_status.php
 * This file is responsible for checking the parsing status of a given evidence item. 
 * It retrieves the parse status and artifact count from the database and returns it as a JSON response. 
 * This is used by the frontend to display the current status of evidence parsing.
 */
require '../db.php';

header('Content-Type: application/json');

// Check if case_id and evidence_id are set in the session and GET parameters
if (!isset($_SESSION['case_id']) || !isset($_GET['evidence_id'])) {
    echo json_encode(['status' => 'none', 'artifact_count' => 0]);
    exit;
}

// Sanitize and validate evidence_id
$case_id = $_SESSION['case_id'];
$evidence_id = intval($_GET['evidence_id']);

// SQL Statement to retrieve parse_status and artifact_count for the given evidence_id and case_id
$stmt = $db->prepare(
    "SELECT parse_status, artifact_count
     FROM evidence
     WHERE id = ? AND case_id = ?"
);
$stmt->execute([$evidence_id, $case_id]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

//Displays the parse status and artifact count 
if (!$row) {
    echo json_encode(['status' => 'none', 'artifact_count' => 0]);
} else {
    echo json_encode([
        'status'         => $row['parse_status']   ?? 'pending',
        'artifact_count' => (int)($row['artifact_count'] ?? 0),
    ]);
}