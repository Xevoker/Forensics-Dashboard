<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: auth/login.php"); // Kick out people who aren't logged in
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <title>Digital Forensics Dashboard</title>

    <link href="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/style.min.css" rel="stylesheet" />
    <link href="css/styles.css" rel="stylesheet" />
    <script src="https://use.fontawesome.com/releases/v6.3.0/js/all.js" crossorigin="anonymous"></script>
</head>

<body class="sb-nav-fixed">

<nav class="sb-topnav navbar navbar-expand navbar-dark bg-dark">
    <a class="navbar-brand ps-3" href="index.html">Forensics System</a>
    <button class="btn btn-link btn-sm order-1 order-lg-0 me-4 me-lg-0" id="sidebarToggle">
        <i class="fas fa-bars"></i>
    </button>
</nav>

<div id="layoutSidenav">

    <!-- SIDEBAR -->
    <div id="layoutSidenav_nav">
        <nav class="sb-sidenav accordion sb-sidenav-dark">
            <div class="sb-sidenav-menu">
                <div class="nav">

                    <div class="sb-sidenav-menu-heading">Investigation</div>

                    <a class="nav-link" href="cases.html">
                        <div class="sb-nav-link-icon"><i class="fas fa-folder-open"></i></div>
                        Cases
                    </a>

                    <a class="nav-link" href="evidence.html">
                        <div class="sb-nav-link-icon"><i class="fas fa-database"></i></div>
                        Evidence
                    </a>

                    <a class="nav-link" href="timeline.html">
                        <div class="sb-nav-link-icon"><i class="fas fa-clock"></i></div>
                        Timeline
                    </a>

                    <a class="nav-link" href="reports.html">
                        <div class="sb-nav-link-icon"><i class="fas fa-file-alt"></i></div>
                        Reports
                    </a>

                    <div class="sb-sidenav-menu-heading">Analysis</div>

                    <a class="nav-link" href="hashing.html">
                        <div class="sb-nav-link-icon"><i class="fas fa-fingerprint"></i></div>
                        Hash Verification
                    </a>

                    <a class="nav-link" href="logs.html">
                        <div class="sb-nav-link-icon"><i class="fas fa-list"></i></div>
                        Log Analysis
                    </a>

                    <a class="nav-link" href="users.html">
                        <div class="sb-nav-link-icon"><i class="fas fa-users"></i></div>
                        Users
                    </a>
                </div>
            </div>

            <div class="sb-sidenav-footer">
                <div class="small">Logged in as:</div>
                Investigator
            </div>
        </nav>
    </div>

    <!-- MAIN CONTENT -->
    <div id="layoutSidenav_content">
        <main>
            <div class="container-fluid px-4">

                <h1 class="mt-4">Digital Forensics Dashboard</h1>

                <!-- CARDS -->
                <div class="row">
                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-primary text-white mb-4">
                            <div class="card-body">Active Cases</div>
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
                    <div class="card-header">
                        Evidence Log
                    </div>
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
                                require 'db.php';
                                $results = $db->query("SELECT * FROM artifacts ORDER BY timestamp DESC");
                                while ($row = $results->fetch(PDO::FETCH_ASSOC)) {
                                    echo "<tr>";
                                    echo "<td>" . htmlspecialchars($row['tool']) . "</td>";
                                    echo "<td>" . htmlspecialchars($row['artifact_type']) . "</td>";
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

        <footer class="py-4 bg-light mt-auto">
            <div class="container-fluid px-4">
                <div class="small text-muted">
                    Copyright © Digital Forensics System 2026
                </div>
            </div>
        </footer>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.8.0/Chart.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/umd/simple-datatables.min.js"></script>
<script src="js/scripts.js"></script>
<script src="js/datatables-simple-demo.js"></script>

</body>
</html>