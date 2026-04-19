<?php
    require '../db.php';
    require_once '../logs/logger.php';

    if (!isset($_SESSION['user_id'])) {
        header("Location: ../Login/login.php");
        exit();
    }
    logAction($_SESSION['user_id'], "User Accessed Chain of Custody", "COC.php");

    // Initialize variables for logs and users
    $current_case = $_SESSION['case_id'] ?? null;
    $activity_logs = [];
    $all_logs = [];
    $unique_users = [];
    $selected_user = isset($_GET['user']) ? trim($_GET['user']) : 'all';

    if ($current_case) {
        // Read and parse the user_activity.log file
        $log_file = '../logs/user_activity.log';
        
        // Check if log file exists before attempting to read
        if (file_exists($log_file)) {
            $lines = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            if ($lines !== false) {
                foreach ($lines as $line) {
                    // Check if the line contains the current case ID
                    if (strpos($line, 'case_id=' . $current_case) !== false) {
                        
                        // Parse the log line
                        $entry = parseLogLine($line);
                        if ($entry) {
                            $all_logs[] = $entry;
                            // Collect unique users
                            if (!empty($entry['user']) && !in_array($entry['user'], $unique_users)) {
                                $unique_users[] = $entry['user'];
                            }
                        }
                    }
                }
            }
        }
        // Filter logs based on selected user
        if ($selected_user === 'all') {
            $activity_logs = $all_logs;
        } else {
            $activity_logs = array_filter($all_logs, function($log) use ($selected_user) {
                return ($log['user'] ?? '') === $selected_user;
            });
        }
    }

    // Function to parse a log line
    function parseLogLine($line) {
        // Match pattern
        if (!preg_match('/\[([^\]]+)\]\s(.*)/', $line, $matches)) {
            return null;
        }
        
        $timestamp = $matches[1];
        $rest = $matches[2];
        
        $entry = ['timestamp' => $timestamp];
        
        // Parse key=value pairs, handling both quoted and unquoted values
        preg_match_all('/(\w+)=(?:"([^"]*)"|([^\s]+))/', $rest, $pairs);
        
        if (!empty($pairs[1])) {
            for ($i = 0; $i < count($pairs[1]); $i++) {
                $key = $pairs[1][$i];
                // Use quoted value if present, otherwise use unquoted value
                $value = !empty($pairs[2][$i]) ? $pairs[2][$i] : $pairs[3][$i];
                $entry[$key] = $value;
            }
        }
        
        return $entry;
    }

    // Reverse to show newest first
    $activity_logs = array_reverse($activity_logs);
    sort($unique_users);
?>
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Chain of Custody</title>
    <link href="../css/styles.css" rel="stylesheet" />
</head>
<body class="sb-nav-fixed">
    <?php include '../includes/navbar.php'; ?>
    <div id="layoutSidenav">
        <?php include '../includes/sidebar.php'; ?>
        <div id="layoutSidenav_content">
            <main>
                <div class="container-fluid px-4">
                    <h1 class="mt-4">Chain of Custody</h1>

                    <?php if (!$current_case): ?>
                        <div class="alert alert-warning">No active case selected. Please <a href="../Login/case-login.php">select a case</a> to view chain of custody logs.</div>
                    <?php else: ?>
                        <div class="card mb-4">
                            <div class="card-header"><i class="fas fa-filter me-1"></i> Filter by User</div>
                            <div class="card-body">
                                <form method="GET" class="row g-3">
                                    <div class="col-md-4">
                                        <label for="userFilter" class="form-label">Select User</label>
                                        <select name="user" id="userFilter" class="form-select" onchange="this.form.submit()">
                                            <option value="all" <?php echo $selected_user === 'all' ? 'selected' : ''; ?>>All Users</option>
                                            <?php foreach ($unique_users as $user): ?>
                                                <option value="<?php echo htmlspecialchars($user); ?>" <?php echo $selected_user === $user ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($user); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                </form>
                            </div>
                        </div>

                        <div class="card mb-4">
                            <div class="card-header">
                                <i class="fas fa-list me-1"></i> User Activity Log for Case <?php echo htmlspecialchars($current_case); ?>
                                <?php if ($selected_user !== 'all'): ?>
                                    - User: <strong><?php echo htmlspecialchars($selected_user); ?></strong>
                                <?php endif; ?>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped table-bordered">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>Timestamp</th>
                                                <th>Username</th>
                                                <th>Action</th>
                                                <th>Page</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (!empty($activity_logs)): ?>
                                                <?php foreach ($activity_logs as $log): ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                                    <td><span class="badge bg-primary"><?php echo htmlspecialchars($log['user'] ?? 'N/A'); ?></span></td>
                                                    <td><?php echo htmlspecialchars(preg_replace('/Case(\d+)/', 'Case $1', $log['action'] ?? 'N/A')); ?></td>
                                                    <td><?php echo htmlspecialchars($log['page'] ?? 'N/A'); ?></td>
                                                </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="4" class="text-center">
                                                        No activity log entries found for this case.
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
                                <p><strong>Total Entries:</strong> <?php echo count($activity_logs); ?></p>
                                <?php if ($selected_user !== 'all'): ?>
                                    <p><strong>Filtered User:</strong> <?php echo htmlspecialchars($selected_user); ?></p>
                                <?php else: ?>
                                    <p><strong>Total Unique Users:</strong> <?php echo count($unique_users); ?></p>
                                <?php endif; ?>
                                <p class="text-muted"><small>This Chain of Custody log provides an audit trail of all user activities within the case. You can filter by specific users to see their actions. This is essential for maintaining forensic integrity and demonstrating that the evidence has been properly handled and protected.</small></p>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </main>
            <?php include '../includes/footer.php'; ?>
        </div>
    </div>
</body>
</html>
