<?php
    require '../db.php';

    if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['evidence_file'])) {
    $case_id = $_SESSION['case_id'];
    $source = $_POST['source_program'];
    
    // Create an 'uploads' directory if it doesn't exist
    $targetDir = "../uploads/";
    if (!file_exists($targetDir)) {
        mkdir($targetDir, 0777, true);
    }

    $fileName = basename($_FILES["evidence_file"]["name"]);
    $targetFilePath = $targetDir . time() . "_" . $fileName; // Add timestamp to prevent overwriting

    if (move_uploaded_file($_FILES["evidence_file"]["tmp_name"], $targetFilePath)) {
        // Insert record into the 'evidence' table
        $stmt = $db->prepare("INSERT INTO evidence (case_id, file_name, file_path, source_program) VALUES (?, ?, ?, ?)");
        $stmt->execute([$case_id, $fileName, $targetFilePath, $source]);
        
        echo "Success";
    } else {
        http_response_code(500);
        echo "Move failed. Check folder permissions.";
    }
    }
?>