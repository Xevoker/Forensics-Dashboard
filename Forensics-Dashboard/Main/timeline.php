<?php
    require '../db.php';
    require_once '../logs/logger.php';

    if (!isset($_SESSION['user_id'])) {
        header("Location: ../Login/login.php");
        exit();
    }

    logAction($_SESSION["user_id"], "User Accessed Timeline", "timeline.php");

    $current_case = $_SESSION['case_id'] ?? 'None';

    // Evidence count
    $stmt_evidence = $db->prepare("SELECT COUNT(*) FROM evidence WHERE case_id = ?");
    $stmt_evidence->execute([$current_case]);
    $evidence_count = $stmt_evidence->fetchColumn();

    // Timeline — one point per uploaded evidence file
    $stmt_timeline = $db->prepare("
        SELECT upload_date, file_name 
        FROM evidence 
        WHERE case_id = ? 
        ORDER BY upload_date ASC
    ");
    $stmt_timeline->execute([$current_case]);
    $timeline_rows  = $stmt_timeline->fetchAll(PDO::FETCH_ASSOC);
    $timeline_labels = array_column($timeline_rows, 'upload_date');
    $timeline_names  = array_column($timeline_rows, 'file_name');
    $timeline_counts = array_fill(0, count($timeline_rows), 1);

    // Evidence type distribution from artifacts
    $stmt_types = $db->prepare("
        SELECT artifact_type, COUNT(*) AS count 
        FROM artifacts 
        WHERE case_id = ? 
        GROUP BY artifact_type 
        ORDER BY count DESC
    ");
    $stmt_types->execute([$current_case]);
    $type_rows   = $stmt_types->fetchAll(PDO::FETCH_ASSOC);
    $type_labels = array_column($type_rows, 'artifact_type');
    $type_counts = array_map('intval', array_column($type_rows, 'count'));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Timeline</title>
    <link href="../css/styles.css" rel="stylesheet" />
	<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="sb-nav-fixed">
    <?php include '../includes/navbar.php'; ?>
    <div id="layoutSidenav">
        <?php include '../includes/sidebar.php'; ?>
        <div id="layoutSidenav_content">
            <main>
                <div class="container-fluid px-4">
                    <h1 class="mt-4">Timeline</h1>
                    <div class="row mb-4">
                        <div class="col-md-4">
                            <div class="card bg-primary text-white mb-4">
                                <div class="card-body">Active Case: <?php echo htmlspecialchars($current_case); ?></div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card bg-warning text-white mb-4">
                                <div class="card-body">Evidence Records: <?php echo $evidence_count; ?></div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card bg-success text-white mb-4">
                                <div class="card-body">Timeline Events: <?php echo count($timeline_rows); ?></div>
                            </div>
                        </div>
                    </div>

                    <div class="row">
                        <div class="col-xl-8">
                            <div class="card mb-4">
                                <div class="card-header">Activity Timeline</div>
                                <div class="card-body">
                                    <canvas id="timelineChart"></canvas>
                                </div>
                            </div>
                        </div>
                        <div class="col-xl-4">
                            <div class="card mb-4">
                                <div class="card-header">Evidence Type Distribution</div>
                                <div class="card-body">
                                    <canvas id="typeChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-table me-1"></i> Recent Evidence Events</div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-bordered table-striped align-middle mb-0">
                                    <thead class="table-light">
                                        <tr>
                                            <th>Date</th>
                                            <th>File Name</th>
                                            <th>Integrity Check</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (!empty($timeline_rows)): ?>
                                            <?php foreach ($timeline_rows as $row): ?>
                                                <tr>
                                                    <tr>
                                                        <td><?php echo htmlspecialchars($row['upload_date']); ?></td>
                                                        <td><?php echo htmlspecialchars($row['file_name']); ?></td>
                                                        <td>—</td>
                                                    </tr>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php else: ?>
                                            <tr>
                                                <td colspan="3" class="text-center text-muted">No timeline data available for this case.</td>
                                            </tr>
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

    <script>
    // Initialize charts with data from PHP
    (function () {
        const timelineLabels = <?php echo json_encode($timeline_labels); ?>;
        const timelineCounts = <?php echo json_encode($timeline_counts); ?>;
        const typeLabels = <?php echo json_encode($type_labels); ?>;
        const typeCounts = <?php echo json_encode($type_counts); ?>;

        const ctxTimeline = document.getElementById('timelineChart');
        // Only render the timeline chart if there are labels to display
    if (ctxTimeline && timelineLabels.length) {
        new Chart(ctxTimeline, {
            type: 'line',
            data: {
                labels: <?php echo json_encode($timeline_labels); ?>,
                datasets: [{
                    label: 'Evidence Uploaded',
                    data: <?php echo json_encode($timeline_counts); ?>,
                    fill: false,
                    borderColor: 'rgba(78,115,223,1)',
                    backgroundColor: 'rgba(78,115,223,1)',
                    pointBackgroundColor: 'rgba(78,115,223,1)',
                    pointRadius: 6,
                    pointHoverRadius: 8,
                    showLine: true,
                    tension: 0
                }]
            },
            options: {
                tooltips: {
                    callbacks: {
                        // Show the filename in the tooltip on hover
                        title: function(tooltipItems) {
                            return <?php echo json_encode($timeline_names); ?>[tooltipItems[0].index];
                        },
                        label: function(tooltipItem) {
                            return 'Uploaded: ' + tooltipItem.xLabel;
                        }
                    }
                },
                scales: {
                    xAxes: [{
                        display: true,
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45,
                            autoSkip: true,
                            maxTicksLimit: 10
                        }
                    }],
                    yAxes: [{
                        display: false  // y axis hidden since all values are 1
                    }]
                }
            }
        });
        // If there are no timeline events, display a message on the canvas
    } else if (ctxTimeline) {
        const ctx = ctxTimeline.getContext('2d');
        ctx.font = '14px sans-serif';
        ctx.fillStyle = '#aaa';
        ctx.textAlign = 'center';
        ctx.fillText('No evidence uploads yet for this case', ctxTimeline.width / 2, ctxTimeline.height / 2);
    }

            const ctxType = document.getElementById('typeChart');
            if (ctxType && typeLabels.length) {
                new Chart(ctxType, {
                    type: 'doughnut',
                    data: {
                        labels: typeLabels,
                        datasets: [{
                            data: typeCounts,
                            backgroundColor: ['#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b', '#4e73df'],
                            borderWidth: 1,
                        }]
                    },
                    options: {
                        legend: { position: 'bottom' }
                    }
                });
            }
        })();
    </script>
</body>
</html>
