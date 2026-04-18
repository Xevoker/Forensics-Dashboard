<?php
require '../db.php';
require_once '../logs/logger.php';

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit();
}
logAction($_SESSION["user_id"], "Accessed Create Case Page", "create-case.php");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $case_id = trim($_POST["case_id"]);
    $case_password = password_hash($_POST["case_password"], PASSWORD_DEFAULT);
    $case_name = trim($_POST["case_name"]);
    $investigator = $_SESSION["user_id"]; // Autho-assign creator

    if (!empty($case_id) && !empty($_POST["case_password"]) && !empty($case_name)) {
        try {
            $stmt = $db->prepare("INSERT INTO cases (case_id, case_password, case_name, investigator) VALUES (?, ?, ?, ?)");
            $stmt->execute([$case_id, $case_password, $case_name, $investigator]);

            // Redirect to USER case-login page
            logAction($_SESSION["user_id"], "Created New Case", "create-case.php");
            header("Location: case-login.php");
            exit();

        } catch (PDOException $e) {
            $error = "Case ID already exists.";
            logAction($_SESSION["user_id"], "Failed to Create New Case", "create-case.php");
        }
    } else {
        $error = "All fields are required.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Create Case</title>
    <link href="../css/styles.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark">

<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-lg-5">
            <div class="card shadow">
                <div class="card-header text-center">
                    <h3>Create New Case</h3>
                </div>
                <div class="card-body">

                    <?php if(isset($error)) echo "<div class='alert alert-danger'>$error</div>"; ?>

                    <form method="POST">
                        <div class="form-floating mb-3">
                            <input class="form-control" name="case_id" type="text" required>
                            <label>Case ID</label>
                        </div>
                        <div class="form-floating mb-3">
                            <input class="form-control" name="case_name" type="text" required>
                            <label>Case Name</label>
                        </div>
                        <div class="form-floating mb-3">
                            <input class="form-control" name="case_password" type="password" required>
                            <label>Case Password</label>
                        </div>

                        <button class="btn btn-primary w-100">Create Case</button>
                    </form>

                    <div class="mt-3 text-center">
                        <a href="case-login.php">Back to Case Login</a>
                    </div>

                </div>
            </div>
        </div>
    </div>
</div>

</body>
</html>