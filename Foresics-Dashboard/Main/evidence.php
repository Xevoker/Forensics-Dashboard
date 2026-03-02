<?php
    require '../db.php';
    $case_id = $_SESSION['case_id'];

    // Query to get artifacts JOINED with their original evidence file info
    $query = "SELECT a.*, e.file_name, e.source_program 
          FROM artifacts a 
          JOIN evidence e ON a.evidence_id = e.id 
          WHERE a.case_id = ? 
          ORDER BY a.timestamp DESC";
    $stmt = $db->prepare($query);
    $stmt->execute([$case_id]);
    $artifacts = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="card shadow mb-4">
    <div class="card-header">
        <i class="fas fa-file-alt me-1"></i> Evidence Analysis Dump (Sudo Report)
    </div>
    <div class="card-body">
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
                <?php foreach ($artifacts as $row): ?>
                <tr>
                    <td><span class="badge bg-info text-dark"><?php echo htmlspecialchars($row['source_program']); ?></span></td>
                    <td><code><?php echo htmlspecialchars($row['file_name']); ?></code></td>
                    <td><?php echo htmlspecialchars($row['value']); ?></td>
                    <td><?php echo $row['timestamp']; ?></td>
                </tr>
                <?php endforeach; ?>
                <?php if(empty($artifacts)) echo "<tr><td colspan='4' class='text-center'>No data scraped yet. Click 'Run Analysis' on Dashboard.</td></tr>"; ?>
            </tbody>
        </table>
    </div>
</div>