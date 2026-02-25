<?php
require '../db.php';

// Checks if user_id is missing from session and redirects to login.php
if (!isset($_SESSION['user_id'])) {
    header("Location: ../Login/login.php"); // Kick out people who aren't logged in
    exit();
}

// Trigger Python Script via Button
$analysis_message = "";
// Run it asynchronously to prevent system hangs
if (isset($_POST['run_analysis'])) {
    $scriptPath = realpath(__DIR__ . '/../scripts/ingest_tools.py');

    // If Windows: Uses command 'start /B' to run in python script in the background.
    // Else Linux/Mac: Use '> /dev/null 2>&1 &' to run in background
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        pclose(popen("start /B python \"$scriptPath\"", "r"));
    } else {
        exec("python \"$scriptPath\" /dev/null 2>&1 &");
    }
    $analysis_message = "Analysis started in the background!";
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
                            <div class="card-body">Case: <?php echo htmlspecialchars($_SESSION['case_id']); ?></div>
                            <!-- <div class="card-body">Active Cases</div> -->
                        </div>
                    </div>
                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-warning text-white mb-4">
                            <div class="card-body">Evidence Items</div>
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