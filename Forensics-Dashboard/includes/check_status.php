<?php
/**
 * check_status.php
 * Polling endpoint — returns JSON parse status for a specific evidence file.
 *
 * Response: { "status": "pending|processing|done|error|none", "artifact_count": N }
 */
require '../db.php';

header('Content-Type: application/json');

if (!isset($_SESSION['case_id']) || !isset($_GET['evidence_id'])) {
    echo json_encode(['status' => 'none', 'artifact_count' => 0]);
    exit;
}

$case_id = $_SESSION['case_id'];
$evidence_id = intval($_GET['evidence_id']);

$stmt = $db->prepare(
    "SELECT parse_status, artifact_count
     FROM evidence
     WHERE id = ? AND case_id = ?"
);
$stmt->execute([$evidence_id, $case_id]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$row) {
    echo json_encode(['status' => 'none', 'artifact_count' => 0]);
} else {
    echo json_encode([
        'status'         => $row['parse_status']   ?? 'pending',
        'artifact_count' => (int)($row['artifact_count'] ?? 0),
    ]);
}