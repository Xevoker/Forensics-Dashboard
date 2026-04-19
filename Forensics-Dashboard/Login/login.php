<?php
require '../db.php';
require_once '../logs/logger.php';

// Check if user is logged in, if not redirect to login page
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user_id = trim($_POST["user_id"]);
    $password = $_POST["password"];

    $stmt = $db->prepare("SELECT * FROM users WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Verify user credentials and log in if valid
    if ($user && password_verify($password, $user["password"])) {
        $_SESSION["user_id"] = $user["user_id"];
        logAction($user_id, "User Successfully Logged In", "login.php");
        header("Location: case-login.php");
        exit();
    } else {
        logAction($user_id, "Failed Login Attempt", "login.php");
        $error = "Invalid login credentials.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>User Login</title>
    <link href="../css/styles.css" rel="stylesheet" />
</head>

<body class="bg-dark">
    <div class="container mt-5">
    <div class="row justify-content-center">
    <div class="col-lg-5">
    <div class="card">
    <div class="card-header text-center"><h3>User Login</h3></div>
    <div class="card-body">
    <?php if(isset($error)) echo "<div class='alert alert-danger'>$error</div>"; ?>
    <form method="POST">
    <div class="form-floating mb-3">
    <input class="form-control" name="user_id" type="text" required>
    <label>User ID</label>
    </div>
    <div class="form-floating mb-3">
    <input class="form-control" name="password" type="password" required>
    <label>Password</label>
    </div>
    <button class="btn btn-primary w-100">Login</button>
    </form>
    <div class="text-center mt-1">
        <a href="register.php">Create Account</a>
    </div>
    </div>
    </div>
    </div>
    </div>
    </div>
</body>
</html>