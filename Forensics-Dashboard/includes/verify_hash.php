<?php
/**
 * verify_hash.php
 * Verify file integrity by comparing stored hash with current file hash
 */
require '../db.php';

header('Content-Type: application/json');

if (!isset($_SESSION['case_id']) || !isset($_POST['evidence_id'])) {
    echo json_encode(['success' => false, 'error' => 'Missing parameters']);
    exit;
}

$evidence_id = intval($_POST['evidence_id']);
$case_id = $_SESSION['case_id'];

// Get evidence record
$stmt = $db->prepare("SELECT id, file_path, file_hash, file_name FROM evidence WHERE id = ? AND case_id = ?");
$stmt->execute([$evidence_id, $case_id]);
$evidence = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$evidence) {
    echo json_encode(['success' => false, 'error' => 'Evidence file not found']);
    exit;
}

$file_path = $evidence['file_path'];
$stored_hash = $evidence['file_hash'];
$file_name = $evidence['file_name'];

// Check if file exists
if (!file_exists($file_path)) {
    echo json_encode([
        'success' => false,
        'error' => 'File not found on disk',
        'file_name' => $file_name,
        'stored_hash' => $stored_hash
    ]);
    exit;
}

// Compute current hash
$current_hash = hash_file('sha256', $file_path);

// Compare hashes
$is_valid = ($current_hash === $stored_hash);

echo json_encode([
    'success' => true,
    'file_name' => $file_name,
    'is_valid' => $is_valid,
    'stored_hash' => $stored_hash,
    'current_hash' => $current_hash,
    'file_size' => filesize($file_path),
    'last_modified' => date('Y-m-d H:i:s', filemtime($file_path))
]);
?>
