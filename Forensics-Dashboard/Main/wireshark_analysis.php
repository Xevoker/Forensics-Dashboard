<?php
    require '../db.php';
    require_once '../logs/logger.php';

    // Redirect to login if not authenticated
    if (!isset($_SESSION['user_id'])) {
        header("Location: ../Login/login.php");
        exit();
    }

    logAction($_SESSION["user_id"], "User Accessed Analysis", "wireshark_analysis.php");

    $current_case = $_SESSION['case_id'] ?? 'None';
    $analysis_message = "";
    $analysis_status = "";
    
    // Handle status messages based on query parameters
    if (isset($_GET['analysis'])) {
        switch ($_GET['analysis']) {
            case 'started':
                $analysis_status  = "info";
                $analysis_message = "Analysis started for case <strong>" . htmlspecialchars($current_case) . "</strong>. Results will appear below as they are processed.";
                break;
            case 'config_error':
                $analysis_status  = "danger";
                $analysis_message = "Python path not configured. Create <code>config.ini</code> next to <code>database.db</code> with:<br><code>[python]<br>path = C:\\...\\python.exe</code>";
                break;
        }
    }
    // Handle form submission to run Wireshark analysis
    if (isset($_POST['run_analysis'])) {
        $evidence_id = $_POST['evidence_id'] ?? null;
        $scriptPath = realpath(__DIR__ . '/../scripts/wireshark_parser.py');

        if (!$evidence_id) {
            $analysis_status = "danger";
            $analysis_message = "Error: Please select an evidence file to analyze.";
        } elseif ($scriptPath && file_exists($scriptPath)) {
            $db = null;

            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                $configPath = __DIR__ . '\\..\\..\\config.ini';
                $config = file_exists($configPath) ? parse_ini_file($configPath, true) : [];
                $pythonPath = $config['python']['path'] ?? null;

                $logDir  = __DIR__ . '\\..\\logs';
                $logPath = $logDir . '\\parser.log';
                if (!file_exists($logDir)) { mkdir($logDir, 0777, true); }

                if (empty($pythonPath) || !file_exists($pythonPath)) {
                    header("Location: wireshark_analysis.php?analysis=config_error");
                    exit();
                } else {
                    $cmd = "cmd /c start /B \"\" \"$pythonPath\" \"$scriptPath\" \"$evidence_id\" >> \"$logPath\" 2>&1";
                    pclose(popen($cmd, "r"));
                    header("Location: wireshark_analysis.php?analysis=started");
                    exit();
                }
            } else {
                exec("python3 \"$scriptPath\" \"$evidence_id\" > /dev/null 2>&1 &");
                $analysis_message = "Analysis started. Refresh in a few seconds to see results.";
            }

            require '../db.php';
        } else {
            $analysis_message = "Error: Python script not found at " . htmlspecialchars($scriptPath);
        }
    }

    // Fetch all evidence files for the current case
    $stmt = $db->prepare("SELECT id, file_name, source_program, upload_date, parse_status, artifact_count FROM evidence WHERE case_id = ? ORDER BY upload_date DESC");
    $stmt->execute([$current_case]);
    $allEvidence = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get the latest evidence for display
    $latestEvidence = !empty($allEvidence) ? $allEvidence[0] : null;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Wireshark Analysis</title>
    <link href="../css/styles.css" rel="stylesheet" />
</head>

<body class="sb-nav-fixed">
    <?php include '../includes/navbar.php'; ?>

    <div id="layoutSidenav">
        <?php include '../includes/sidebar.php'; ?>

        <div id="layoutSidenav_content">
            <main>
                <div class="container-fluid px-4">
                    <h1 class="mt-4">Evidence Analysis</h1>

                    <?php if ($analysis_message): ?>
                        <div class="alert alert-<?php echo htmlspecialchars($analysis_status ?: 'info'); ?>">
                            <?php echo $analysis_message; ?>
                        </div>
                    <?php endif; ?>

                    <div class="alert alert-info" role="alert">
                        <h6 class="alert-heading"><i class="fas fa-lightbulb me-2"></i>Wireshark Export Instructions</h6>
                        <p class="mb-2"><strong>To analyze Wireshark packet captures:</strong></p>
                        <ol class="mb-0">
                            <li>In Wireshark, go to <code>File &gt; Export Packet List</code></li>
                            <li>Select <strong>CSV</strong> as the file format</li>
                            <li>Upload the <code>.csv</code> file (not the binary <code>.pcap</code> file)</li>
                            <li>Click "Start Evidence Scrape" to analyze</li>
                        </ol>
                        <hr class="my-2">
                        <small><strong>Note:</strong> Binary PCAP files must be exported to CSV format first. The parser cannot directly analyze binary PCAP files.</small>
                    </div>

                    <div class="row">
                        <div class="col-md-12">
                            <div class="card mb-4">
                                <div class="card-header">Forensic Processing Engine</div>
                                <div class="card-body">
                                    <p class="text-muted">This page runs the evidence scraper for the currently selected case: <strong><?php echo htmlspecialchars($current_case); ?></strong></p>
                                    
                                    <?php if (!empty($allEvidence)): ?>
                                        <form method="POST">
                                            <div class="mb-3">
                                                <label for="evidenceSelect" class="form-label">Select Evidence File to Analyze</label>
                                                <select id="evidenceSelect" name="evidence_id" class="form-select" required>
                                                    <option value="">-- Choose a file --</option>
                                                    <?php foreach ($allEvidence as $evidence): ?>
                                                        <option value="<?php echo htmlspecialchars($evidence['id']); ?>">
                                                            <?php echo htmlspecialchars($evidence['file_name']); ?> 
                                                            (<?php echo htmlspecialchars($evidence['source_program']); ?>) 
                                                            - <?php echo htmlspecialchars($evidence['upload_date']); ?>
                                                            <?php if ($evidence['parse_status'] && $evidence['parse_status'] !== 'pending'): ?>
                                                                <span class="badge bg-<?php echo $evidence['parse_status'] === 'done' ? 'success' : ($evidence['parse_status'] === 'processing' ? 'warning' : 'danger'); ?>"><?php echo htmlspecialchars($evidence['parse_status']); ?></span>
                                                            <?php endif; ?>
                                                        </option>
                                                    <?php endforeach; ?>
                                                </select>
                                            </div>
                                            <button type="submit" name="run_analysis" class="btn btn-primary btn-lg">
                                                <i class="fas fa-play fa-sm text-white-50 me-2"></i> Start Evidence Scrape
                                            </button>
                                        </form>
                                        <div id="parseStatusBanner" class="mt-3" style="display:none;">
                                            <div id="parseStatusInner" class="alert mb-0"></div>
                                        </div>
                                    <?php else: ?>
                                        <p class="text-warning"><i class="fas fa-exclamation-triangle me-2"></i>No evidence files have been uploaded for this case yet.</p>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-table me-1"></i> Extracted Artifacts</div>
                        <div class="card-body" style="max-height: 700px; overflow-y: auto;">
                            <?php
                            // Get artifacts for the case
                            $stmt = $db->prepare("SELECT a.id, a.tool, a.artifact_type, a.value, a.severity, a.timestamp, a.evidence_id, e.file_name FROM artifacts a JOIN evidence e ON a.evidence_id = e.id WHERE a.case_id = ? ORDER BY a.timestamp DESC");
                            $stmt->execute([$current_case]);
                            $artifacts = $stmt->fetchAll(PDO::FETCH_ASSOC);
                            
                            // Get unique evidence files
                            $uniqueFiles = [];
                            foreach ($artifacts as $artifact) {
                                if (!in_array($artifact['file_name'], $uniqueFiles)) {
                                    $uniqueFiles[] = $artifact['file_name'];
                                }
                            }
                            ?>
                            <?php if (!empty($artifacts)): ?>
                                <div class="mb-3">
                                    <label for="artifactFileFilter" class="form-label">Filter by Evidence File</label>
                                    <select id="artifactFileFilter" class="form-select form-select-sm" onchange="filterArtifactsByFile(this.value)">
                                        <option value="">-- All Files --</option>
                                        <?php foreach ($uniqueFiles as $fileName): ?>
                                            <option value="<?php echo htmlspecialchars($fileName); ?>"><?php echo htmlspecialchars($fileName); ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="table-responsive">
                                    <table class="table table-striped table-bordered" id="artifactsTable">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>Tool</th>
                                                <th>Type</th>
                                                <th>Value</th>
                                                <th>Severity</th>
                                                <th>Time</th>
                                                <th>Source File</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($artifacts as $artifact): ?>
                                            <tr data-file="<?php echo htmlspecialchars($artifact['file_name']); ?>">
                                                <td><span class="badge bg-info"><?php echo htmlspecialchars($artifact['tool']); ?></span></td>
                                                <td><?php echo htmlspecialchars($artifact['artifact_type']); ?></td>
                                                <td><code><?php echo htmlspecialchars(substr($artifact['value'], 0, 100)); ?><?php echo strlen($artifact['value']) > 100 ? '...' : ''; ?></code></td>
                                                <td>
                                                    <span class="badge bg-<?php 
                                                        echo $artifact['severity'] === 'High' ? 'danger' : 
                                                                 ($artifact['severity'] === 'Medium' ? 'warning' : 'success'); 
                                                    ?>">
                                                        <?php echo htmlspecialchars($artifact['severity']); ?>
                                                    </span>
                                                </td>
                                                <td><?php echo htmlspecialchars($artifact['timestamp'] ?? 'N/A'); ?></td>
                                                <td><small><?php echo htmlspecialchars($artifact['file_name']); ?></small></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php else: ?>
                                <p class="text-muted mb-0"><i class="fas fa-info-circle me-2"></i>No artifacts extracted yet. Upload and analyze an evidence file to see results here.</p>
                            <?php endif; ?>
                        </div>
                    </div>
            <?php include '../includes/footer.php'; ?>
        </div>
    </div>

    <script>
    (function () {
        const banner     = document.getElementById('parseStatusBanner');
        const inner      = document.getElementById('parseStatusInner');
        const POLL_MS    = 3000;
        let pollTimer    = null;
        let currentEvidenceId = null;
        // Function to determine the status label based on the response from the server
        function statusLabel(data) {
            switch (data.status) {
                case 'processing':
                    return { cls: 'alert-info', icon: 'fas fa-spinner fa-spin', msg: `Analysing… <strong>${data.artifact_count.toLocaleString()}</strong> artifacts found so far.` };
                case 'done':
                    if (data.artifact_count === 0) {
                        return { cls: 'alert-warning', icon: 'fas fa-exclamation-circle', msg: '<strong>No artifacts extracted.</strong> If you uploaded a <code>.PCAP</code> file, please export it to CSV first from Wireshark (File &gt; Export Packet List &gt; CSV), then re-upload.' };
                    }
                    return { cls: 'alert-success', icon: 'fas fa-check-circle', msg: `Analysis complete — <strong>${data.artifact_count.toLocaleString()}</strong> artifacts extracted.` };
                case 'error':
                    return { cls: 'alert-danger', icon: 'fas fa-exclamation-triangle', msg: 'Analysis failed. Check if the file is a valid CSV export from Wireshark. Binary PCAP files must be converted to CSV first. See <code>logs/parser.log</code> for details.' };
                default:
                    return null;
            }
        }
        // Checks status and refreshs to update listing when done
        function poll() {
            fetch('../includes/check_status.php?evidence_id=' + currentEvidenceId)
                .then(r => r.json())
                .then(data => {
                    const info = statusLabel(data);
                    if (!info) {
                        banner.style.display = 'none';
                        return;
                    }

                    banner.style.display = 'block';
                    inner.className = 'alert mb-0 ' + info.cls;
                    inner.innerHTML = `<i class="${info.icon} me-2"></i>${info.msg}`;

                    if (data.status === 'done' || data.status === 'error') {
                        clearInterval(pollTimer);
                        // Reload the page after 2 seconds to show newly extracted artifacts
                        if (data.status === 'done') {
                            setTimeout(() => {
                                location.reload();
                            }, 2000);
                        }
                    }
                })
                .catch(() => { });
        }

        // Capture the selected evidence_id when form is about to submit
        document.addEventListener('submit', function(e) {
            if (e.target.querySelector('button[name="run_analysis"]')) {
                const evidenceSelect = document.getElementById('evidenceSelect');
                if (evidenceSelect) {
                    currentEvidenceId = evidenceSelect.value;
                    if (currentEvidenceId) {
                        banner.style.display = 'block';
                        inner.className = 'alert mb-0 alert-info';
                        inner.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Starting analysis…';
                        pollTimer = setInterval(poll, POLL_MS);
                        poll();
                    }
                }
            }
        }, true);

        <?php if (!empty($analysis_message)): ?>
            banner.style.display = 'block';
            inner.className = 'alert mb-0 alert-info';
            inner.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Starting analysis…';
            pollTimer = setInterval(poll, POLL_MS);
            poll();
        <?php endif; ?>
    })();

    // Filter artifacts table by evidence file
    function filterArtifactsByFile(fileName) {
        const rows = document.querySelectorAll('#artifactsTable tbody tr');
        rows.forEach(row => {
            if (!fileName) {
                // Show all rows
                row.style.display = '';
            } else {
                // Show only rows matching the selected file
                const rowFile = row.getAttribute('data-file');
                row.style.display = rowFile === fileName ? '' : 'none';
            }
        });
    }
    </script>
</body>
</html>
