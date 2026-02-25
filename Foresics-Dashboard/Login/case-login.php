<?php
require '../db.php';

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $case_id = trim($_POST["case_id"]);
    $case_password = $_POST["case_password"];

    $stmt = $db->prepare("SELECT * FROM cases WHERE case_id = ?");
    $stmt->execute([$case_id]);
    $case = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($case && password_verify($case_password, $case["case_password"])) {
        $_SESSION["case_id"] = $case["case_id"];
        header("Location: ../Main/dashboard.php");
        exit();
    } else {
        $error = "Invalid case credentials.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Case Login</title>
    <link href="../css/styles.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-secondary">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-lg-5">
                <div class="card">
                    <div class="card-header text-center"><h3>Case Login</h3></div>
                    <div class="card-body">
                        <?php if(isset($error)) echo "<div class='alert alert-danger'>$error</div>"; ?>
                        <form method="POST">
                            <div class="form-floating mb-3">
                                <input class="form-control" name="case_id" type="text" required>
                                <label>Case ID</label>
                            </div>
                            <div class="form-floating mb-3">
                                <input class="form-control" name="case_password" type="password" required>
                                <label>Case Password</label>
                            </div>
                            <button class="btn btn-danger w-100 mb-3">Enter Case</button>
                        </form>
                        <div class="mt-3 text-center">
                            <p>Starting a new investigation?</p>
                            <a href="create-case.php" class="btn btn-outline-primary">Create New Case</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>