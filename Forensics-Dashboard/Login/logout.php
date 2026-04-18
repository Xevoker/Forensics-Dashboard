<?php
    require_once '../logs/logger.php';
    
    session_start();
    session_destroy();
    logAction($_SESSION["user_id"], "User Logged Out");
    header("Location: login.php");
    exit();
?>