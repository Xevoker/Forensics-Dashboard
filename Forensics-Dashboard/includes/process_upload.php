<?php
    require '../db.php';

    if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['evidence_file'])) {
    $case_id = $_SESSION['case_id'];
    $source = $_POST['source_program'];
    
    // Create case-specific upload directory: uploads/case_ID/
    $uploadsDir = realpath(__DIR__ . '/../uploads') . DIRECTORY_SEPARATOR;
    $caseDir = $uploadsDir . 'case_' . $case_id . DIRECTORY_SEPARATOR;
    
    if (!file_exists($uploadsDir)) {
        mkdir($uploadsDir, 0777, true);
    }
    if (!file_exists($caseDir)) {
        mkdir($caseDir, 0777, true);
    }

    $fileName = basename($_FILES["evidence_file"]["name"]);
    $targetFilePath = $caseDir . time() . "_" . $fileName; // Add timestamp to prevent overwriting

    if (move_uploaded_file($_FILES["evidence_file"]["tmp_name"], $targetFilePath)) {
        // Compute SHA256 hash of the uploaded file
        $file_hash = hash_file('sha256', $targetFilePath);
        
        // Insert record into the 'evidence' table
        $stmt = $db->prepare("INSERT INTO evidence (case_id, file_name, file_path, source_program, file_hash) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$case_id, $fileName, $targetFilePath, $source, $file_hash]);
        
        echo "Success";
    } else {
        http_response_code(500);
        echo "Move failed. Check folder permissions.";
    }
    }
?>