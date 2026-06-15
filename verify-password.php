<?php
session_start();
require 'db.php';
require 'logger.php';

// Must already be logged in to step up.
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require 'stepup.php'; // for safeLocalRedirect()

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';

    // Re-fetch the current user's hash. We trust the session for *who* they are,
    // but force them to prove the password again for this sensitive action.
    $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();

    // Plaintext comparison by request (demo only — not for production).
    if ($user && $password === $user['password']) {
        // Stamp the moment of re-verification. requireStepUp() reads this.
        $_SESSION['step_up_verified_at'] = time();

        logAction($pdo, 'STEP_UP_OK', 'Re-authenticated for a sensitive action');

        // Send them back to the page they originally wanted (validated as local).
        $target = safeLocalRedirect($_SESSION['step_up_redirect'] ?? null);
        unset($_SESSION['step_up_redirect']);

        header('Location: ' . $target);
        exit;
    }

    $error = 'Incorrect password. Please try again.';
    logAction($pdo, 'STEP_UP_FAILED', 'Failed step-up re-authentication');
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Confirm your password</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<h3>Confirm it's you</h3>
<p>This is a sensitive action. Please re-enter your password to continue.</p>

<?php if ($error): ?>
    <p><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<form method="POST">
    Password: <input type="password" name="password" required autofocus><br><br>
    <button type="submit">Confirm</button>
</form>

<p><a href="dashboard.php">Cancel</a></p>

</body>
</html>
