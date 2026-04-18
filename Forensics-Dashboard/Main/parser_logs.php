<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: ../Login/login.php');
    exit;
}

require '../db.php';
require_once '../logs/logger.php';

logAction($_SESSION['user_id'], "Accessed Parser Logs", "parser_logs.php");

$log_file = __DIR__ . '/../logs/parser.log';
$log_contents = '';
$file_exists = file_exists($log_file);

if ($file_exists) {
    $log_contents = file_get_contents($log_file);
    // Get last 100 lines for display
    $lines = explode("\n", $log_contents);
    $log_contents = implode("\n", array_slice($lines, max(0, count($lines) - 100)));
}

// Handle log clearing
if (isset($_POST['clear_logs']) && $file_exists) {
    file_put_contents($log_file, '');
    header('Location: parser_logs.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="Parser Logs - Forensics Dashboard" />
    <title>Parser Logs - Forensics Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" />
    <script src="https://use.fontawesome.com/releases/v6.3.0/js/all.js" crossorigin="anonymous"></script>
    <link href="../css/styles.css" rel="stylesheet" />
    <style>
        .log-viewer {
            background-color: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Courier New', monospace;
            padding: 15px;
            border-radius: 4px;
            max-height: 600px;
            overflow-y: auto;
            line-height: 1.5;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .log-viewer .info {
            color: #569cd6;
        }
        .log-viewer .error {
            color: #f48771;
        }
        .log-viewer .success {
            color: #6a9955;
        }
        .log-viewer .warning {
            color: #dcdcaa;
        }
    </style>
</head>
<body class="sb-nav-fixed">
    <?php include '../includes/navbar.php'; ?>
    <div id="layoutSidenav">
        <?php include '../includes/sidebar.php'; ?>
        <div id="layoutSidenav_content">
            <main>
                <div class="container-fluid px-4">
                    <h1 class="mt-4">Parser Logs</h1>
                    <ol class="breadcrumb mb-4">
                        <li class="breadcrumb-item active">View forensic tool parser activity and debugging information</li>
                    </ol>

                    <div class="card mb-4">
                        <div class="card-header">
                            <i class="fas fa-file-lines me-2"></i>Parser Activity Log
                            <div class="float-end">
                                <small class="text-muted">
                                    <?php if ($file_exists): ?>
                                        Last updated: <?php echo date('Y-m-d H:i:s', filemtime($log_file)); ?>
                                    <?php endif; ?>
                                </small>
                            </div>
                        </div>
                        <div class="card-body">
                            <?php if (!$file_exists): ?>
                                <div class="alert alert-info">
                                    <i class="fas fa-info-circle me-2"></i>No parser logs yet. Run an analysis on any forensic tool to generate logs.
                                </div>
                            <?php else: ?>
                                <div class="log-viewer" id="logViewer">
                                    <?php
                                    // Color-code log entries
                                    $lines = explode("\n", $log_contents);
                                    foreach ($lines as $line) {
                                        if (empty(trim($line))) continue;
                                        
                                        if (strpos($line, '[ERROR]') !== false) {
                                            echo '<div class="error">' . htmlspecialchars($line) . '</div>';
                                        } elseif (strpos($line, '[WARNING]') !== false) {
                                            echo '<div class="warning">' . htmlspecialchars($line) . '</div>';
                                        } elseif (strpos($line, 'Successfully') !== false || strpos($line, 'done') !== false) {
                                            echo '<div class="success">' . htmlspecialchars($line) . '</div>';
                                        } elseif (strpos($line, '[INFO]') !== false) {
                                            echo '<div class="info">' . htmlspecialchars($line) . '</div>';
                                        } else {
                                            echo '<div>' . htmlspecialchars($line) . '</div>';
                                        }
                                    }
                                    ?>
                                </div>
                                
                                <div class="mt-3">
                                    <button class="btn btn-sm btn-secondary" onclick="location.reload()">
                                        <i class="fas fa-sync me-1"></i> Refresh
                                    </button>
                                    <button class="btn btn-sm btn-outline-primary" onclick="scrollToBottom()">
                                        <i class="fas fa-arrow-down me-1"></i> Scroll to Bottom
                                    </button>
                                    <button class="btn btn-sm btn-outline-danger" onclick="document.getElementById('clearForm').submit()">
                                        <i class="fas fa-trash me-1"></i> Clear Logs
                                    </button>
                                </div>
                                
                                <form id="clearForm" method="POST" style="display:none;">
                                    <input type="hidden" name="clear_logs" value="1">
                                </form>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header bg-light">
                            <i class="fas fa-info-circle me-2"></i>Log Format
                        </div>
                        <div class="card-body">
                            <p class="mb-2"><strong>Each log entry contains:</strong></p>
                            <ul class="mb-0">
                                <li><code>[Timestamp]</code> - When the event occurred</li>
                                <li><code>[Level]</code> - INFO, ERROR, or WARNING</li>
                                <li><code>[Tool]</code> - Which parser ran (Wireshark, Autopsy, Volatility, Guymager)</li>
                                <li><code>Message</code> - Details about the event</li>
                            </ul>
                            <hr class="my-3">
                            <p class="mb-0"><strong>Example:</strong></p>
                            <code style="color: #569cd6;">[2026-04-18 14:30:45,123] [INFO] [Autopsy] Starting Autopsy parser for evidence_id: 5</code>
                        </div>
                    </div>
                </div>
            </main>
            <?php include '../includes/footer.php'; ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    function scrollToBottom() {
        const viewer = document.getElementById('logViewer');
        viewer.scrollTop = viewer.scrollHeight;
    }
    
    // Auto-scroll to bottom on load
    window.addEventListener('load', scrollToBottom);
    
    // Auto-refresh every 5 seconds
    setInterval(function() {
        fetch(window.location.href)
            .then(r => r.text())
            .then(html => {
                const parser = new DOMParser();
                const newDoc = parser.parseFromString(html, 'text/html');
                const newViewer = newDoc.getElementById('logViewer');
                const oldViewer = document.getElementById('logViewer');
                if (newViewer && oldViewer) {
                    oldViewer.innerHTML = newViewer.innerHTML;
                    scrollToBottom();
                }
            })
            .catch(e => console.log('Auto-refresh failed'));
    }, 5000);
    </script>
</body>
</html>
