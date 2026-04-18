<?php
require '../db.php';
require_once '../logs/logger.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user_id = trim($_POST["user_id"]);
    $password = password_hash($_POST["password"], PASSWORD_DEFAULT);

    try {
        $stmt = $db->prepare("INSERT INTO users (user_id, password) VALUES (?, ?)");
        $stmt->execute([$user_id, $password]);
        logAction($user_id, "User Registered", "register.php");
        header("Location: login.php");
        exit();
    } catch (PDOException $e) {
        $error = "User already exists.";
        logAction($user_id, "Failed User Registration", "register.php");
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <link href="../css/styles.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark">
<div class="container mt-5">
<div class="row justify-content-center">
<div class="col-lg-5">
<div class="card">
<div class="card-header text-center"><h3>Create Account</h3></div>
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
<button class="btn btn-success w-100">Register</button>
</form>
<div class="text-center mt-1">
    <a href="login.php">Already Have An Account?</a>
</div>
</div>
</div>
</div>
</div>
</div>
</body>
</html>