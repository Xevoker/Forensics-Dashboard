<?php
// Set Timezone to our location - Problems with incorrect timezone
date_default_timezone_set('America/Los_Angeles');

//define a secret key for HMAC signing of log entries. The logAction function formats and writes user activity logs to a file, including an HMAC for integrity verification.
define('LOG_HMAC_SECRET', 'your-secret-key-here');

// Logs user actions with a timestamp, username, IP address, session ID, action description, and page. Each log entry is signed with an HMAC to prevent tampering.
function logAction($username, $action, $page = null) {
    $time = date("Y-m-d H:i:s");
    $page = $page ?? basename($_SERVER['PHP_SELF']);
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $sid  = session_id() ?: 'none';
    $eid  = bin2hex(random_bytes(8));
    $cid  = $_SESSION['case_id'] ?? null;

    // Sanitize inputs to prevent log injection
    $sanitize = fn($v) => preg_replace('/[\x00-\x1F\x7F]/', '', $v);

    // Format log entry with key=value pairs and JSON-encoded action for better structure
    $entry_parts = [
        "[$time]",
        "eid=$eid",
        "user="   . $sanitize($username),
        "ip=$ip",
        "sid=$sid",
    ];
    
    // Add case_id if available
    if ($cid !== null) {
        $entry_parts[] = "case_id=$cid";
    }
    
    $entry_parts[] = "action=" . json_encode($sanitize($action));
    $entry_parts[] = "page="   . $sanitize($page);
    
    $entry = implode(' ', $entry_parts) . PHP_EOL;

    // Generate HMAC signature for the log entry
    $hmac  = hash_hmac('sha256', $entry, LOG_HMAC_SECRET);
    $entry = rtrim($entry) . " hmac=$hmac" . PHP_EOL;

    // Write the log entry to the user_activity.log file, ensuring the logs directory exists and using file locking to prevent concurrent write issues
    $logPath = __DIR__ . "/../logs/user_activity.log";

    // Ensure the logs directory exists
    if (!is_dir(dirname($logPath))) {
        mkdir(dirname($logPath), 0755, true);
    }

    // Append the log entry to the file with exclusive lock
    $fh = fopen($logPath, 'a');
    if ($fh) {
        flock($fh, LOCK_EX);
        fwrite($fh, $entry);
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}
?>

