<?php
    require '../db.php';
    require_once '../logs/logger.php';

    // Checks if user_id is missing from session and redirects to login.php
    if (!isset($_SESSION['user_id'])) {
        header("Location: ../Login/login.php"); // Kick out people who aren't logged in
        exit();
    }
    logAction($_SESSION["user_id"], "User Accessed Dashboard", "dashboard.php");

    // Get the active case ID from session
    $current_case = $_SESSION['case_id'] ?? 'None';
    $artifacts = [];
    $evidence_files = [];

    if ($current_case) {
        // Get artifacts (extracted data)
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
    $stmt_uploads = $db->prepare("
    SELECT file_name, source_program, upload_date, file_hash 
    FROM evidence 
    WHERE case_id = ? 
    ORDER BY upload_date DESC
");
$stmt_uploads->execute([$current_case]);
$upload_rows = $stmt_uploads->fetchAll(PDO::FETCH_ASSOC);

    // Count Evidence Items for THIS case
    $stmt_evidence = $db->prepare("SELECT COUNT(*) FROM evidence WHERE case_id = ?");
    $stmt_evidence->execute([$current_case]);
    $evidence_count = $stmt_evidence->fetchColumn();

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Digital - Forensics Dashboard</title>
    <link href="../css/styles.css" rel="stylesheet" />
</head>

<body class="sb-nav-fixed">
    <?php include '../includes/navbar.php'; ?>

    <div id="layoutSidenav">
        <?php include '../includes/sidebar.php'; ?>

    <div id="layoutSidenav_content">
        <main>
            <div class="container-fluid px-4">
                <h1 class="mt-4">Digital Forensics Dashboard</h1>
                <div class="row">
                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-primary text-white mb-4">
                            <div class="card-body">Active Case: <?php echo htmlspecialchars($current_case); ?></div>
                        </div>
                    </div>
                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-warning text-white mb-4">
                            <div class="card-body">Evidence Items: <?php echo $evidence_count; ?></div>
                        </div>
                    </div>
                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-success text-white mb-4">
                            <div class="card-body">Pending Reports</div>
                        </div>
                    </div>
                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-danger text-white mb-4">
                            <div class="card-body">Flagged Alerts</div>
                        </div>
                    </div>
                </div>
                <div class="card mb-4 border-left-primary shadow h-100 py-2">
                    <div class="card-body">
                        <div class="row no-gutters align-items-center">
                            <div class="col mr-2">
                                <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                    Forensic Processing Engine
                                </div>
                                <div class="h5 mb-0 font-weight-bold text-gray-800">
                                    Run Automated Analysis
                                </div>
                                <p class="text-muted small">Run Wireshark scraping from the dedicated analysis page and keep the dashboard focused on evidence.</p>
                            </div>
                            <div class="col-auto">
                                <a href="wireshark_analysis.php" class="btn btn-primary btn-lg">
                                    <i class="fas fa-arrow-right fa-sm text-white-50 me-2"></i> Go to Wireshark Analysis
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card mb-4">
    <div class="card-header"><i class="fas fa-clock me-1"></i> Evidence Upload Log</div>
    <div class="card-body">
        <table class="table table-striped table-bordered">
            <thead class="table-dark">
                <tr>
                    <th>File Name</th>
                    <th>Source Program</th>
                    <th>Upload Date</th>
                    <th>Integrity</th>
                </tr>
            </thead>
            <tbody>
                <?php if (!empty($upload_rows)): ?>
                    <?php foreach ($upload_rows as $row): ?>
                    <tr>
                        <td><code><?php echo htmlspecialchars($row['file_name']); ?></code></td>
                        <td><span class="badge bg-info text-dark"><?php echo htmlspecialchars($row['source_program']); ?></span></td>
                        <td><?php echo htmlspecialchars($row['upload_date']); ?></td>
                        <td>
                            <?php if (!empty($row['file_hash'])): ?>
                                <span class="badge bg-success"><i class="fas fa-check me-1"></i>Hash Stored</span>
                            <?php else: ?>
                                <span class="badge bg-warning text-dark"><i class="fas fa-exclamation me-1"></i>No Hash</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="4" class="text-center text-muted">No evidence uploaded for this case yet.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
            </div>
        </main>
        <?php include '../includes/footer.php'; ?>
    </div>
</div>
</body>
</html>