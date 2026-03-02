<?php
    require '../db.php';

    // Checks if user_id is missing from session and redirects to login.php
    if (!isset($_SESSION['user_id'])) {
        header("Location: ../Login/login.php"); // Kick out people who aren't logged in
        exit();
    }

    // Get the active case ID from session
    $current_case = $_SESSION['case_id'] ?? 'None';

    // 1. Count Evidence Items for THIS case
    $stmt_evidence = $db->prepare("SELECT COUNT(*) FROM evidence WHERE case_id = ?");
    $stmt_evidence->execute([$current_case]);
    $evidence_count = $stmt_evidence->fetchColumn();

    $analysis_message = "";

    if (isset($_POST['run_analysis'])) {
        $case_id = $_SESSION['case_id'];
        $scriptPath = realpath(__DIR__ . '/../scripts/wireshark_parser.py');

        if ($scriptPath && file_exists($scriptPath)) {
            // Run in background using the 'start /B' method to prevent DB locking
            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                // Passing case_id as an argument to the python script
                pclose(popen("start /B python \"$scriptPath\" \"$case_id\"", "r"));
                $analysis_message = "Background analysis started for " . htmlspecialchars($case_id) . ". Refresh in a few seconds to see results.";
            } else {
                exec("python3 \"$scriptPath\" \"$case_id\" > /dev/null 2>&1 &");
                $analysis_message = "Analysis started.";
            }
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
                    </div>
                </div>
                <!-- CHARTS -->
                <div class="row">
                    <div class="col-xl-6">
                        <div class="card mb-4">
                            <div class="card-header">
                                Case Activity Timeline
                            </div>
                            <div class="card-body">
                                <canvas id="myAreaChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <div class="col-xl-6">
                        <div class="card mb-4">
                            <div class="card-header">
                                Evidence Type Distribution
                            </div>
                            <div class="card-body">
                                <canvas id="myBarChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- EVIDENCE TABLE -->
                <div class="card mb-4">
                    <div class="card-header"><i class="fas fa-table me-1"></i>Evidence Log</div>
                    <div class="card-body">
                        <table id="datatablesSimple">
                            <thead>
                                <tr>
                                    <th>Evidence ID</th>
                                    <th>Type</th>
                                    <th>Source Device</th>
                                    <th>Date Collected</th>
                                    <th>SHA-256 Hash</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                    $results = $db->query("SELECT * FROM artifacts ORDER BY timestamp DESC");
                                    while ($row = $results->fetch(PDO::FETCH_ASSOC)) {
                                        echo "<tr>";
                                        echo "<td>" . htmlspecialchars($row['id']) . "</td>";
                                        echo "<td>" . htmlspecialchars($row['tool']) . "</td>";
                                        echo "<td>" . htmlspecialchars($row['artifact_type']) . "</td>";
                                        echo "<td>" . htmlspecialchars($row['timestamp']). "</td>";
                                        echo "<td>" . htmlspecialchars($row['value']) . "</td>";
                                        echo "<td><span class='badge bg-warning'>" . htmlspecialchars($row['severity']) . "</span></td>";
                                        echo "<td>" . htmlspecialchars($row['timestamp']) . "</td>";
                                        echo "</tr>";
                                    }
                                ?>
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

</body>
</html>