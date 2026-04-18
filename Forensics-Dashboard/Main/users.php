<?php
    require '../db.php';
    require_once '../logs/logger.php';

    if (!isset($_SESSION['user_id'])) {
        header("Location: ../Login/login.php");
        exit();
    }
    logAction($_SESSION['user_id'], "User Accessed Users Page", "users.php");

    $current_case = $_SESSION['case_id'] ?? null;
    $case_investigator = null;
    $all_users = [];

    // Get the investigator for the current case
    if ($current_case) {
        $query = "SELECT investigator FROM cases WHERE case_id = ?";
        $stmt = $db->prepare($query);
        $stmt->execute([$current_case]);
        $case = $stmt->fetch(PDO::FETCH_ASSOC);
        $case_investigator = $case['investigator'] ?? null;
    }

    // Get all users
    $query = "SELECT id, user_id FROM users ORDER BY user_id ASC";
    $stmt = $db->prepare($query);
    $stmt->execute();
    $all_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Users</title>
    <link href="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/style.min.css" rel="stylesheet" />
    <link href="../css/styles.css" rel="stylesheet" />
    <script src="https://use.fontawesome.com/releases/v6.3.0/js/all.js" crossorigin="anonymous"></script>
</head>
<body class="sb-nav-fixed">
    <?php include '../includes/navbar.php'; ?>
    <div id="layoutSidenav">
        <?php include '../includes/sidebar.php'; ?>
        <div id="layoutSidenav_content">
            <main>
                <div class="container-fluid px-4">
                    <h1 class="mt-4">Users</h1>

                    <?php if (!$current_case): ?>
                        <div class="alert alert-warning">No active case selected. Please <a href="../Login/case-login.php">select a case</a> to view users with case access.</div>
                    <?php else: ?>
                        <div class="card mb-4">
                            <div class="card-header"><i class="fas fa-users me-1"></i> Users with Access to Case <?php echo htmlspecialchars($current_case); ?></div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped table-bordered">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>Username</th>
                                                <th>Role</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (!empty($all_users)): ?>
                                                <?php foreach ($all_users as $user): ?>
                                                <tr>
                                                    <td>
                                                        <span class="badge bg-primary"><?php echo htmlspecialchars($user['user_id']); ?></span>
                                                    </td>
                                                    <td>
                                                        <?php if ($user['user_id'] === $case_investigator): ?>
                                                            <span class="badge bg-warning text-dark">Instigator</span>
                                                        <?php else: ?>
                                                            <span class="badge bg-secondary">Team Member</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <?php if ($user['user_id'] === $_SESSION['user_id']): ?>
                                                            <span class="badge bg-success">Currently Logged In</span>
                                                        <?php else: ?>
                                                            <span class="badge bg-info">Available</span>
                                                        <?php endif; ?>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="3" class="text-center">
                                                        No users found in the system.
                                                    </td>
                                                </tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header"><i class="fas fa-info-circle me-1"></i> Information</div>
                            <div class="card-body">
                                <p><strong>Total Users:</strong> <?php echo count($all_users); ?></p>
                                <p><strong>Case Instigator:</strong> <?php echo htmlspecialchars($case_investigator ?? 'Unknown'); ?></p>
                                <p class="text-muted"><small>All users in the system have potential access to this case with the correct case password. The instigator is the user who created the case. Team members are other users who may assist in the investigation.</small></p>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </main>
            <?php include '../includes/footer.php'; ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/umd/simple-datatables.min.js"></script>
    <script src="../js/scripts.js"></script>
    <script src="../js/datatables-simple-demo.js"></script>
</body>
</html>
