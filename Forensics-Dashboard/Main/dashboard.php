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

    // 1. Count Evidence Items for THIS case
    $stmt_evidence = $db->prepare("SELECT COUNT(*) FROM evidence WHERE case_id = ?");
    $stmt_evidence->execute([$current_case]);
    $evidence_count = $stmt_evidence->fetchColumn();



    $analysis_message = "";
    $analysis_status = "";
    if (isset($_GET['analysis'])) {
        switch ($_GET['analysis']) {
            case 'started':
                $analysis_status  = "info";
                $analysis_message = "Analysis started for case <strong>" . htmlspecialchars($current_case) . "</strong>. Results will appear below as they are processed.";
                break;
            case 'config_error':
                $analysis_status  = "danger";
                $analysis_message = "Python path not configured. Create <code>config.ini</code> next to <code>database.db</code> with:<br><code>[python]<br>path = C:\...\python.exe</code>";
                break;
        }
    }

    if (isset($_POST['run_analysis'])) {
        $case_id = $_SESSION['case_id'];
        $scriptPath = realpath(__DIR__ . '/../scripts/wireshark_parser.py');

        if ($scriptPath && file_exists($scriptPath)) {
            // IMPORTANT: Releases the PHP DB connection before Python starts writing.
            // Keeping it open while Python runs has caused SQLite lock.
            $db = null;

            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                // XAMPP's Apache module doesn't contain the users python installation
                // so the path is read through the config.ini file.
                // All hardcoded locations should be in path for debugging purposes in the future.
                $configPath = __DIR__ . '\\..\\..\\config.ini';
                $config     = file_exists($configPath) ? parse_ini_file($configPath, true) : [];
                $pythonPath = $config['python']['path'] ?? null;

                $logDir  = __DIR__ . '\\..\\logs';
                $logPath = $logDir . '\\parser.log';
                if (!file_exists($logDir)) { mkdir($logDir, 0777, true); }

                if (empty($pythonPath) || !file_exists($pythonPath)) {
                    // Redirect with error flag so page loads as GET, not POST -> prevent loop
                    header("Location: dashboard.php?analysis=config_error");
                    exit();
                } else {
                    $cmd = "cmd /c start /B \"\" \"$pythonPath\" \"$scriptPath\" \"$case_id\" >> \"$logPath\" 2>&1";
                    pclose(popen($cmd, "r"));
                    // PRG pattern: redirect to GET so F5/reload never re-fires the POST
                    header("Location: dashboard.php?analysis=started");
                    exit();
                }
            } else {
                exec("python3 \"$scriptPath\" \"$case_id\" > /dev/null 2>&1 &");
                $analysis_message = "Analysis started. Refresh in a few seconds to see results.";
            }

            // Reconnect for the rest of the page render
            require '../db.php';
        } else {
            $analysis_message = "Error: Python script not found at " . htmlspecialchars($scriptPath);
        }
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <!--
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    -->
    <title>Digital - Forensics Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/style.min.css" rel="stylesheet" />
    <link href="../css/styles.css" rel="stylesheet" />
    <script src="https://use.fontawesome.com/releases/v6.3.0/js/all.js" crossorigin="anonymous"></script>
</head>


<body class="sb-nav-fixed">
    <!-- Copies navbar onto all pages -->
    <?php include '../includes/navbar.php'; ?>

    <div id="layoutSidenav">
        <!-- Copies side navbar onto all pages -->
        <?php include '../includes/sidebar.php'; ?>

    <!-- MAIN CONTENT -->
    <div id="layoutSidenav_content">
        <main>
            <div class="container-fluid px-4">
                <h1 class="mt-4">Digital Forensics Dashboard</h1>
                <?php if($analysis_message): ?>
                    <div class="alert alert-success"><?php echo $analysis_message; ?></div>
                <?php endif; ?>

                <!-- CARDS -->
                <div class="row">
                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-primary text-white mb-4">
                            <!-- Currently displays the active case id's but maybe we'll add a count -->
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
                <!-- Parser Button -->
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
                                <p class="text-muted small">This will trigger the Python scraper for your most recently uploaded Wireshark file for Case: <strong><?php echo htmlspecialchars($_SESSION['case_id']); ?></strong></p>
                            </div>
                            <div class="col-auto">
                                <form method="POST">
                                    <button type="submit" name="run_analysis" class="btn btn-primary btn-lg">
                                        <i class="fas fa-play fa-sm text-white-50 me-2"></i> Start Wireshark Scrape
                                    </button>
                                </form>
                            </div>
                        </div>
                        
                        <?php if (isset($analysis_message) && $analysis_message): ?>
                            <div class="alert alert-info mt-3 alert-dismissible fade show" role="alert">
                                <i class="fas fa-info-circle me-1"></i> <?php echo $analysis_message; ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        <?php endif; ?>

                        <!-- Live parse status banner — shown/updated by JS polling -->
                        <div id="parseStatusBanner" class="mt-3" style="display:none;">
                            <div id="parseStatusInner" class="alert mb-0"></div>
                        </div>
                    </div>
                </div>
            
                <!-- EVIDENCE TABLE -->
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

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.8.0/Chart.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/umd/simple-datatables.min.js"></script>
<script src="js/scripts.js"></script>
<script src="js/datatables-simple-demo.js"></script>

<script>
(function () {
    const banner     = document.getElementById('parseStatusBanner');
    const inner      = document.getElementById('parseStatusInner');
    const POLL_MS    = 3000;   // check every 3 seconds
    let   pollTimer  = null;
    let   wasRunning = false;

    function statusLabel(data) {
        switch (data.status) {
            case 'processing':
                return {
                    cls: 'alert-info',
                    icon: 'fas fa-spinner fa-spin',
                    msg: `Analysing&hellip; <strong>${data.artifact_count.toLocaleString()}</strong> artifacts found so far.`
                };
            case 'done':
                return {
                    cls: 'alert-success',
                    icon: 'fas fa-check-circle',
                    msg: `Analysis complete &mdash; <strong>${data.artifact_count.toLocaleString()}</strong> artifacts extracted. Refreshing&hellip;`
                };
            case 'error':
                return {
                    cls: 'alert-danger',
                    icon: 'fas fa-exclamation-triangle',
                    msg: 'Analysis encountered an error. Check server logs.'
                };
            default:
                return null;
        }
    }

    function poll() {
        fetch('../includes/check_status.php')
            .then(r => r.json())
            .then(data => {
                const info = statusLabel(data);

                if (!info) {
                    // pending / none — nothing to show yet
                    banner.style.display = 'none';
                    return;
                }

                banner.style.display = 'block';
                inner.className = 'alert mb-0 ' + info.cls;
                inner.innerHTML = `<i class="${info.icon} me-2"></i>${info.msg}`;

                if (data.status === 'processing') {
                    wasRunning = true;
                }

                if (data.status === 'done' || data.status === 'error') {
                    clearInterval(pollTimer);
                    if (data.status === 'done') {
                        // Give the user 2 seconds to read the message then reload
                        setTimeout(() => location.reload(), 2000);
                    }
                }
            })
            .catch(() => { /* network blip — keep polling */ });
    }

    // Auto-start polling if the page loaded right after hitting Run Analysis
    <?php if (!empty($analysis_message)): ?>
    banner.style.display = 'block';
    inner.className = 'alert mb-0 alert-info';
    inner.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Starting analysis&hellip;';
    pollTimer = setInterval(poll, POLL_MS);
    poll(); // immediate first check
    <?php endif; ?>
})();
</script>

</body>
</html>