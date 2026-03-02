<?php
    session_start();
    require '../db.php';

    // Checks if user_id is missing from session and redirects to login.php
    if (!isset($_SESSION['user_id'])) {
        header("Location: ../Login/login.php");
        exit();
    }

    // Update Status and delete case
    if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_SESSION['case_id'])) {
        $active_case_id = $_SESSION['case_id'];

        if (isset($_POST['update_status'])) {
            $new_status = ($_POST['current_status'] == 'Open') ? 'Closed' : 'Open';
            $stmt = $db->prepare("UPDATE cases SET status = ? WHERE case_id = ?");
            $stmt->execute([$new_status, $active_case_id]);
        }

        if (isset($_POST['delete_case'])) {
            $stmt = $db->prepare("DELETE FROM cases WHERE case_id = ?");
            $stmt->execute([$active_case_id]);
            unset($_SESSION['case_id']); 
            header("Location: ../Login/case-login.php");
            exit();
        }
    }

    // Count Statistics
    $total_cases = $db->query("SELECT COUNT(*) FROM cases")->fetchColumn();
    $open_cases = $db->query("SELECT COUNT(*) FROM cases WHERE status = 'Open'")->fetchColumn();
    $closed_cases = $db->query("SELECT COUNT(*) FROM cases WHERE status = 'Closed'")->fetchColumn();

    // Fetch details of the logged-in case
    $session_case_id = $_SESSION['case_id'] ?? null;
    $stmt = $db->prepare("SELECT * FROM cases WHERE case_id = ?");
    $stmt->execute([$session_case_id]);
    $current_case = $stmt->fetch(PDO::FETCH_ASSOC); // This is now an Array
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

                 <!-- Upload Form -->
                <?php include '../includes/upload_form.php'; ?>

                <!-- ADD CASE BUTTON -->
                <div class="mb-3">
                    <button class="btn btn-primary">
                        <i class="fas fa-plus"></i> Add New Case
                    </button>
                </div>

                <!-- Total, Open, and Completed Case Banner -->
                <div class="row">
                    <div class="col-md-4">
                        <div class="card bg-primary text-white mb-4">
                            <div class="card-body">Total Cases: <?php echo $total_cases; ?></div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card bg-success text-white mb-4">
                            <div class="card-body">Open Cases: <?php echo $open_cases; ?></div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card bg-secondary text-white mb-4">
                            <div class="card-body">Completed: <?php echo $closed_cases; ?></div>
                        </div>
                    </div>
                </div>
                
                <!-- Toggle Case Status and Delete Case Buttons -->
                <div class="row">
                    <form method="POST" onsubmit="return confirm('Are you sure?');" style="display:inline;">
                        <input type="hidden" name="current_status" value="<?php echo $current_case['status']; ?>">
                        <button type="submit" name="update_status" class="btn btn-sm btn-info">Toggle Status</button>
                        <button type="submit" name="delete_case" class="btn btn-sm btn-danger">Delete Case</button>
                    </form>
                </div>

                <!-- CASE TABLE -->
                <div class="card mb-4">
                    <div class="card-header">Current Case</div>
                    <div class="card-body">
                        <table id="datatablesSimple">
                            <thead>
                                <tr>
                                    <th class="pe-4">Case ID</th>
                                    <th class="pe-4">Case Name</th>
                                    <th class="pe-4">Lead Investigator</th>
                                    <th class="pe-4">Date Opened</th>
                                    <th class="pe-4">Status</th>
                                    <th class="pe-4">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if ($current_case): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($current_case['case_id']); ?></td>
                                    <td><?php echo htmlspecialchars($current_case['case_name']); ?></td>
                                    <td><?php echo htmlspecialchars($current_case['investigator']); ?></td>
                                    <td><?php echo $current_case['date_created']; ?></td>
                                    <td><span class="badge bg-primary"><?php echo $current_case['status']; ?></span></td>
                                    <td><a href="../Login/case-login.php" class="btn btn-sm btn-warning">Switch Case</a></td>
                                </tr>
                                <?php else: ?>
                                <tr><td colspan="5" class="text-center">No active case selected. <a href="../Login/case-login.php">Login here</a></td></tr>
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
<script src="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/umd/simple-datatables.min.js"></script>
<script src="js/scripts.js"></script>
<script src="js/datatables-simple-demo.js"></script>

</body>
</html>