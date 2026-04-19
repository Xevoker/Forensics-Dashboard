<!-- Handles the sidebar navigation for the dashboard and all other pages -->
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
                <a class="nav-link" href="evidence.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-database"></i></div>
                    Evidence
                </a>
                <a class="nav-link" href="timeline.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-clock"></i></div>
                    Timeline
                </a>
                <div class="sb-sidenav-menu-heading">Analysis Tools</div>
                <a class="nav-link" href="wireshark_analysis.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-network-wired"></i></div>
                    Wireshark Analysis
                </a>
                <a class="nav-link" href="autopsy_analysis.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-magnifying-glass"></i></div>
                    Autopsy Analysis
                </a>
                <a class="nav-link" href="volatility_analysis.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-memory"></i></div>
                    Volatility Analysis
                </a>
                <a class="nav-link" href="guymager_analysis.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-hdd"></i></div>
                    Guymager Analysis
                </a>
                <a class="nav-link" href="hash_verification.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-fingerprint"></i></div>
                    Hash Verification
                </a>
                <a class="nav-link" href="parser_logs.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-file-lines"></i></div>
                    Parser Logs
                </a>
                <a class="nav-link" href="COC.php">
                    <div class="sb-nav-link-icon"><i class="fas fa-list"></i></div>
                    Chain of Custody
                </a>
                <a class="nav-link" href="users.php">
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