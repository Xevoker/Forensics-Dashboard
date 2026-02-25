<!-- SIDEBAR -->
<div id="layoutSidenav_nav">
    <nav class="sb-sidenav accordion sb-sidenav-dark" id="sidenavAccordion">
        <div class="sb-sidenav-menu">
            <div class="nav">
                <div class="sb-sidenav-menu-heading">Investigation</div>
                <a class="nav-link" href="dashboard.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-tachometer-alt"></i></div>
                    Dashboard
                </a>
                <a class="nav-link" href="cases.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-folder-open"></i></div>
                    Cases
                </a>
                <a class="nav-link" href="#"> <!-- evidence.php -->
                    <div class="sb-nav-link-icon"><i class="fas fa-database"></i></div>
                    Evidence
                </a>
                <a class="nav-link" href="#"> <!-- timeline.php -->
                    <div class="sb-nav-link-icon"><i class="fas fa-clock"></i></div>
                    Timeline
                </a>
                <a class="nav-link" href="#"> <!-- reports.php-->
                    <div class="sb-nav-link-icon"><i class="fas fa-file-alt"></i></div>
                    Reports
                </a>

                <div class="sb-sidenav-menu-heading">Analysis Tools</div>
                <form action="dashboard.php" method="POST" style="padding: 0 1rem;">
                    <button type="submit" name="run_analysis" class="btn btn-success btn-sm w-100 mt-2">
                        <i class="fas fa-play me-1"></i> Run Ingestion
                    </button>
                </form>
                <a class="nav-link" href="#"> <!-- hashing.php-->
                    <div class="sb-nav-link-icon"><i class="fas fa-fingerprint"></i></div>
                    Hash Verification
                </a>
                <a class="nav-link" href="#"> <!-- logs.php-->
                    <div class="sb-nav-link-icon"><i class="fas fa-list"></i></div>
                    Log Analysis
                </a>
                <a class="nav-link" href="#"> <!-- users.php-->
                    <div class="sb-nav-link-icon"><i class="fas fa-users"></i></div>
                    Users
                </a>
            </div>
        </div>
        <div class="sb-sidenav-footer">
            <div class="small">Logged in as:</div>
            <?php echo htmlspecialchars($_SESSION['user_id'] ?? 'Guest'); ?>
            <br>
            <small class="text-muted">Case: <?php echo htmlspecialchars($_SESSION['case_id'] ?? 'None'); ?></small>
        </div>
    </nav>
</div>