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

    // Load all cases
    $all_cases = $db->query("SELECT * FROM cases ORDER BY date_created DESC")->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Case Management</title>
    <link href="../css/styles.css" rel="stylesheet" />
</head>

<body class="sb-nav-fixed">
    <?php include '../includes/navbar.php'; ?>

    <div id="layoutSidenav">
        <?php include '../includes/sidebar.php'; ?>

    <div id="layoutSidenav_content">
        <main>
            <div class="container-fluid px-4">

                <h1 class="mt-4">Case Management</h1>
                <div class="mb-3">
                    <a href="../Login/create-case.php" class="btn btn-primary">
                        <i class="fas fa-plus"></i> Add New Case
                    </a>
                </div>

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
                
                <div class="row">
                    <form method="POST" onsubmit="return confirm('Are you sure?');" style="display:inline;">
                        <input type="hidden" name="current_status" value="<?php echo $current_case['status']; ?>">
                        <button type="submit" name="update_status" class="btn btn-sm btn-info">Toggle Status</button>
                        <button type="submit" name="delete_case" class="btn btn-sm btn-danger">Delete Case</button>
                    </form>
                </div>

                <div class="card mb-4">
                    <div class="card-header">All Cases</div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table id="datatablesSimple" class="table table-striped table-bordered table-hover align-middle mb-0">
                                <thead class="table-light border-bottom">
                                    <tr>
                                        <th class="pe-4">Case ID</th>
                                        <th class="pe-4">Case Name</th>
                                        <th class="pe-4">Lead Investigator</th>
                                        <th class="pe-4">Date Opened</th>
                                        <th class="pe-4">Status</th>
                                        <th class="pe-4">Active</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (!empty($all_cases)): ?>
                                        <?php foreach ($all_cases as $case): ?>
                                        <tr>
                                            <td class="fw-bold text-dark"><?php echo htmlspecialchars($case['case_id']); ?></td>
                                            <td><?php echo htmlspecialchars($case['case_name']); ?></td>
                                            <td><?php echo htmlspecialchars($case['investigator']); ?></td>
                                            <td><?php echo htmlspecialchars($case['date_created']); ?></td>
                                            <td><span class="badge <?php echo $case['status'] === 'Open' ? 'bg-success' : 'bg-secondary'; ?>"><?php echo htmlspecialchars($case['status']); ?></span></td>
                                            <td>
                                                <?php if ($case['case_id'] === $session_case_id): ?>
                                                    <span class="badge bg-primary">Current</span>
                                                <?php else: ?>
                                                    <a href="../Login/case-login.php" class="btn btn-sm btn-warning">Switch</a>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <tr><td colspan="6" class="text-center py-4">No cases found.</td></tr>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </main>
        <?php include '../includes/footer.php'; ?>
    </div>
</div>
</body>
</html>