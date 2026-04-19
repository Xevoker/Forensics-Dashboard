<?php
    require '../db.php';
    require_once '../logs/logger.php';

    if (!isset($_SESSION['user_id'])) {
        header("Location: ../Login/login.php");
        exit();
    }
    logAction($_SESSION['user_id'], "User Accessed Evidence Page", "evidence.php");

    $current_case = $_SESSION['case_id'] ?? null;
    $artifacts = [];
    $evidence_files = [];
    // Get evidence and artifacts for the current case
    if ($current_case) {
        $query = "SELECT a.*, e.file_name, e.source_program 
                  FROM artifacts a 
                  JOIN evidence e ON a.evidence_id = e.id 
                  WHERE a.case_id = ? 
                  ORDER BY a.timestamp DESC";
        $stmt = $db->prepare($query);
        $stmt->execute([$current_case]);
        $artifacts = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Get evidence files
        $query = "SELECT id, file_name, source_program, upload_date, file_hash FROM evidence WHERE case_id = ? ORDER BY upload_date DESC";
        $stmt = $db->prepare($query);
        $stmt->execute([$current_case]);
        $evidence_files = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Evidence</title>
    <link href="../css/styles.css" rel="stylesheet" />
</head>
<body class="sb-nav-fixed">
    <?php include '../includes/navbar.php'; ?>
    <div id="layoutSidenav">
        <?php include '../includes/sidebar.php'; ?>
        <div id="layoutSidenav_content">
            <main>
                <div class="container-fluid px-4">
                    <h1 class="mt-4">Evidence</h1>

                    <?php if (!$current_case): ?>
                        <div class="alert alert-warning">No active case selected. Please <a href="../Login/case-login.php">select a case</a> before uploading evidence.</div>
                    <?php else: ?>
                        <?php include '../includes/upload_form.php'; ?>

                        <div class="card mb-4">
                            <div class="card-header"><i class="fas fa-file me-1"></i> Uploaded Evidence Files</div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped table-bordered">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>File Name</th>
                                                <th>Source Program</th>
                                                <th>Upload Date</th>
                                                <th>File Hash (SHA256)</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (!empty($evidence_files)): ?>
                                                <?php foreach ($evidence_files as $file): ?>
                                                <tr>
                                                    <td><code><?php echo htmlspecialchars($file['file_name']); ?></code></td>
                                                    <td><span class="badge bg-info text-dark"><?php echo htmlspecialchars($file['source_program']); ?></span></td>
                                                    <td><?php echo htmlspecialchars($file['upload_date']); ?></td>
                                                    <td><code style="font-size: 0.85em;"><?php echo htmlspecialchars($file['file_hash'] ?? 'N/A'); ?></code></td>
                                                </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="4" class="text-center">
                                                        <?php if ($current_case): ?>
                                                            No evidence files have been uploaded for this case yet.
                                                        <?php else: ?>
                                                            Please select a case to view evidence.
                                                        <?php endif; ?>
                                                    </td>
                                                </tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="card mb-4">
                            <div class="card-header"><i class="fas fa-table me-1"></i> Evidence Analysis Dump</div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-bordered">
                                        <thead>
                                            <tr>
                                                <th>Source Program</th>
                                                <th>Original File</th>
                                                <th>Extracted Data</th>
                                                <th>Timestamp</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (!empty($artifacts)): ?>
                                                <?php foreach ($artifacts as $row): ?>
                                                <tr>
                                                    <td><span class="badge bg-info text-dark"><?php echo htmlspecialchars($row['source_program']); ?></span></td>
                                                    <td><code><?php echo htmlspecialchars($row['file_name']); ?></code></td>
                                                    <td><?php echo htmlspecialchars($row['value']); ?></td>
                                                    <td><?php echo htmlspecialchars($row['timestamp']); ?></td>
                                                </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="4" class="text-center">
                                                        <?php if ($current_case): ?>
                                                            No evidence has been processed for this case yet.
                                                        <?php else: ?>
                                                            Please select a case to view evidence.
                                                        <?php endif; ?>
                                                    </td>
                                                </tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
            </main>
            <?php include '../includes/footer.php'; ?>
        </div>
    </div>
</body>
</html>