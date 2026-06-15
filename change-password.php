<?php
session_start();
require 'db.php';
require 'logger.php';
require 'stepup.php';

// 1. Normal authentication: must be logged in.
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// 2. Step-up authentication: must have confirmed password in the last 5 minutes.
//    If not, this call redirects to verify-password.php and never returns here.
requireStepUp(300);

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new = $_POST['new_password'] ?? '';

    if (strlen($new) < 8) {
        $message = 'New password must be at least 8 characters.';
    } else {
        // Plaintext storage by request (demo only — not for production).
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$new, $_SESSION['user_id']]);

        logAction($pdo, 'PASSWORD_CHANGED', 'User changed their password');
        $message = 'Password updated successfully.';
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Change Password</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<p><a href="dashboard.php">&larr; Back to dashboard</a></p>

<h3>Change Password</h3>

<?php if ($message): ?>
    <p><?= htmlspecialchars($message) ?></p>
<?php endif; ?>

<form method="POST">
    New password: <input type="password" name="new_password" required><br><br>
    <button type="submit">Update password</button>
</form>

</body>
</html>
