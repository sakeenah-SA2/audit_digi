<?php
session_start();
require 'db.php';
require 'logger.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        $error = 'Username and password required';
    } else {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);

        if ($stmt->fetch()) {
            $error = 'Username already taken';
        } else {
            $stmt = $pdo->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')");
            $stmt->execute([$username, $password]);
            $newId = $pdo->lastInsertId();

            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            $stmt = $pdo->prepare("
                INSERT INTO audit_logs (user_id, username, action, details, ip_address)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$newId, $username, 'REGISTER', "New account created: $username", $ip]);

            $success = 'Account created! You can now log in.';
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<h3>Register</h3>

<?php if ($error): ?>
    <p><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<?php if ($success): ?>
    <p><?= htmlspecialchars($success) ?> <a href="login.php">Login here</a></p>
<?php endif; ?>

<form method="POST">
    Username: <input type="text" name="username" required><br><br>
    Password: <input type="password" name="password" required><br><br>
    <button type="submit">Register</button>
</form>

<p><a href="login.php">Back to login</a></p>

</body>
</html>
