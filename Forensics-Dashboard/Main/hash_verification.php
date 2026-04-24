<?php
session_start();
if (!isset($_SESSION['user_id']) || !isset($_SESSION['case_id'])) {
    header('Location: ../Login/login.php');
    exit;
}

require '../db.php';

// Get all evidence files for the current case
$case_id = $_SESSION['case_id'];
$stmt = $db->prepare('SELECT id, file_name, file_hash, upload_date FROM evidence WHERE case_id = ? ORDER BY upload_date DESC');
$stmt->execute([$case_id]);
$evidence_files = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <title>Hash Verification - Forensics Dashboard</title>
        <link href="../css/styles.css" rel="stylesheet" />
		<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</head>
    <body class="sb-nav-fixed">
        <?php include '../includes/navbar.php'; ?>
        <div id="layoutSidenav">
            <?php include '../includes/sidebar.php'; ?>
            <div id="layoutSidenav_content">
                <main>
                    <div class="container-fluid px-4">
                        <h1 class="mt-4">Hash Verification</h1>
                        <ol class="breadcrumb mb-4">
                            <li class="breadcrumb-item active">Verify evidence file integrity</li>
                        </ol>

                        <div class="card mb-4">
                            <div class="card-header">
                                <i class="fas fa-fingerprint me-2"></i>Evidence Files - SHA256 Hash Verification
                            </div>
                            <div class="card-body">
                                <?php if (empty($evidence_files)): ?>
                                    <div class="alert alert-info">
                                        <i class="fas fa-info-circle me-2"></i>No evidence files found for this case. Upload files on the Evidence page first.
                                    </div>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-hover">
                                            <thead class="table-dark">
                                                <tr>
                                                    <th>File Name</th>
                                                    <th>Upload Date</th>
                                                    <th>Stored Hash (SHA256)</th>
                                                    <th>Action</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($evidence_files as $file): ?>
                                                    <tr>
                                                        <td>
                                                            <code><?php echo htmlspecialchars($file['file_name']); ?></code>
                                                        </td>
                                                        <td>
                                                            <small class="text-muted"><?php echo htmlspecialchars($file['upload_date']); ?></small>
                                                        </td>
                                                        <td>
                                                            <code class="text-break small"><?php echo htmlspecialchars(substr($file['file_hash'], 0, 32)); ?>...</code>
                                                        </td>
                                                        <td>
                                                            <button class="btn btn-sm btn-outline-primary" onclick="verifyHash(<?php echo htmlspecialchars($file['id']); ?>, '<?php echo htmlspecialchars(addslashes($file['file_name'])); ?>')">
                                                                <i class="fas fa-check-circle me-1"></i> Verify
                                                            </button>
                                                            <button class="btn btn-sm btn-outline-secondary" onclick="viewHash(<?php echo htmlspecialchars($file['id']); ?>, '<?php echo htmlspecialchars(addslashes($file['file_name'])); ?>', '<?php echo htmlspecialchars($file['file_hash']); ?>')">
                                                                <i class="fas fa-eye me-1"></i> View Hash
                                                            </button>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header bg-light">
                                <i class="fas fa-shield-alt me-2"></i>How Hash Verification Works
                            </div>
                            <div class="card-body">
                                <p>Hash verification ensures the integrity of evidence files and detects any unauthorized modifications or corruption:</p>
                                <ul class="mb-0">
                                    <li><strong>Stored Hash:</strong> Computed and saved when the file was first uploaded</li>
                                    <li><strong>Current Hash:</strong> Computed from the file on disk right now</li>
                                    <li><strong>Comparison:</strong> If hashes match, the file has not been modified</li>
                                    <li><strong>Tampering Detection:</strong> If hashes don't match, the file may have been altered, corrupted, or deleted</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </main>
                <?php include '../includes/footer.php'; ?>
            </div>
        </div>

        <div class="modal fade" id="hashVerificationModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">File Integrity Verification</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="hashVerificationContent">
                        <div class="text-center">
                            <div class="spinner-border" role="status">
                                <span class="visually-hidden">Verifying...</span>
                            </div>
                            <p class="mt-2">Verifying file integrity...</p>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade" id="viewHashModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">View File Hash</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="viewHashContent">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>

        <script>
        // JavaScript functions to handle hash verification and viewing stored hash
        function verifyHash(evidenceId, fileName) {
            const modal = new bootstrap.Modal(document.getElementById('hashVerificationModal'));
            const content = document.getElementById('hashVerificationContent');
            
            // Show loading state in modal
            modal.show();
            
            // Send verification request throough verify_hash.php 
            fetch('../includes/verify_hash.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: 'evidence_id=' + evidenceId
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    const isValid = data.is_valid;
                    const statusClass = isValid ? 'alert-success' : 'alert-danger';
                    const statusIcon = isValid ? 'fa-check-circle text-success' : 'fa-exclamation-triangle text-danger';
                    const statusText = isValid ? 'File Integrity Verified' : 'File Integrity Compromised';
                    
                    // Display verification results in the modal
                    content.innerHTML = `
                        <div class="alert ${statusClass}">
                            <h6><i class="fas ${statusIcon} me-2"></i>${statusText}</h6>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <strong>File Name:</strong><br>
                                <code>${escapeHtml(data.file_name)}</code>
                            </div>
                            <div class="col-md-6">
                                <strong>File Size:</strong><br>
                                ${formatBytes(data.file_size)}
                            </div>
                        </div>
                        <hr>
                        <div>
                            <strong>Stored Hash (SHA256):</strong>
                            <code class="d-block text-break" style="font-size: 0.85em; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                                ${escapeHtml(data.stored_hash)}
                            </code>
                        </div>
                        <hr>
                        <div>
                            <strong>Current Hash (SHA256):</strong>
                            <code class="d-block text-break" style="font-size: 0.85em; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                                ${escapeHtml(data.current_hash)}
                            </code>
                        </div>
                        <hr>
                        <div class="small text-muted">
                            <strong>Last Modified:</strong> ${data.last_modified}
                        </div>
                        ${!isValid ? '<div class="alert alert-warning mt-3"><i class="fas fa-warning me-2"></i><strong>Warning:</strong> The file hash does not match the stored hash. This may indicate the file has been modified or corrupted.</div>' : '<div class="alert alert-info mt-3"><i class="fas fa-info-circle me-2"></i>File integrity verified successfully. The file has not been modified since upload.</div>'}
                    `;
                } else {
                    content.innerHTML = `
                        <div class="alert alert-danger">
                            <h6><i class="fas fa-exclamation-circle me-2"></i>Verification Error</h6>
                            <p class="mb-0">${escapeHtml(data.error)}</p>
                        </div>
                    `;
                }
            })
            .catch(err => {
                content.innerHTML = `
                    <div class="alert alert-danger">
                        <h6><i class="fas fa-exclamation-circle me-2"></i>Error</h6>
                        <p class="mb-0">An error occurred during verification. Please try again.</p>
                    </div>
                `;
            });
        }
        // Function to display the stored hash in a modal
        function viewHash(evidenceId, fileName, storedHash) {
            const modal = new bootstrap.Modal(document.getElementById('viewHashModal'));
            const content = document.getElementById('viewHashContent');
            
            content.innerHTML = `
                <div>
                    <strong>File Name:</strong><br>
                    <code>${escapeHtml(fileName)}</code>
                    <hr>
                    <strong>Stored Hash (SHA256):</strong>
                    <code class="d-block text-break" style="font-size: 0.85em; background: #f8f9fa; padding: 8px; border-radius: 4px; min-height: 50px;">
                        ${escapeHtml(storedHash)}
                    </code>
                </div>
            `;
            
            modal.show();
        }
        // Utility function to escape HTML special characters to prevent XSS
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, m => map[m]);
        }
        
        // Utility function to format bytes
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
        }
        </script>
    </body>
</html>
