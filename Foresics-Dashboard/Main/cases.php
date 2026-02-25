<?php
session_start();
// Checks if user_id is missing from session and redirects to login.php
if (!isset($_SESSION['user_id'])) {
    header("Location: ../Login/login.php"); // Kick out people who aren't logged in
    exit();
}

// Trigger Python Script via Button
$analysis_message = "";
if (isset($_POST['run_analysis'])) {
    $scriptPath = realpath(__DIR__ . '/../scripts/ingest_tools.py');
    // Run python and capture errors
    $output = shell_exec("python \"$scriptPath\" 2>&1");
    $analysis_message = "Analysis Complete!";
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
    <title>Case Management</title>

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

                <h1 class="mt-4">Case Management</h1>

                <!-- ADD CASE BUTTON -->
                <div class="mb-3">
                    <button class="btn btn-primary">
                        <i class="fas fa-plus"></i> Add New Case
                    </button>
                </div>

                <!-- CASE TABLE -->
                <div class="card mb-4">
                    <div class="card-header">
                        Active Cases
                    </div>
                    <div class="card-body">
                        <table id="datatablesSimple">
                            <thead>
                                <tr>
                                    <th>Case ID</th>
                                    <th>Case Name</th>
                                    <th>Lead Investigator</th>
                                    <th>Date Opened</th>
                                    <th>Status</th>
                                    <th>Priority</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>CASE-001</td>
                                    <td>Corporate Data Breach</td>
                                    <td>J. Smith</td>
                                    <td>2026-01-28</td>
                                    <td>Open</td>
                                    <td>High</td>
                                </tr>
                                <tr>
                                    <td>CASE-002</td>
                                    <td>Unauthorized Server Access</td>
                                    <td>A. Patel</td>
                                    <td>2026-02-02</td>
                                    <td>Investigating</td>
                                    <td>Medium</td>
                                </tr>
                                <tr>
                                    <td>CASE-003</td>
                                    <td>Email Phishing Incident</td>
                                    <td>L. Johnson</td>
                                    <td>2026-02-05</td>
                                    <td>Pending Evidence</td>
                                    <td>Low</td>
                                </tr>
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
<script src="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/umd/simple-datatables.min.js"></script>
<script src="js/scripts.js"></script>
<script src="js/datatables-simple-demo.js"></script>

</body>
</html>