<?php
session_start();
require 'db.php';
require 'logger.php';

// This page is reached AFTER the session was torn down by the anomaly handler.
// The only thing we carry over is which user is pending OTP verification.
$pendingUserId = $_SESSION['otp_pending_user'] ?? null;

if (!$pendingUserId) {
    // Nothing to verify — go back to the normal login.
    header('Location: login.php');
    exit;
}

// Look up the pending user (prepared statement).
$stmt = $pdo->prepare("SELECT id, username, security_status FROM users WHERE id = ?");
$stmt->execute([$pendingUserId]);
$user = $stmt->fetch();

// If the account was already cleared, don't keep them here.
if (!$user || $user['security_status'] === 'ok') {
    unset($_SESSION['otp_pending_user'], $_SESSION['otp_code']);
    header('Location: login.php');
    exit;
}

$error = '';
$info  = '';

// --- Generate the one-time code on first view ---------------------------------
// REAL SYSTEM: generate this, store it, and EMAIL it to the user's address.
// Here we keep it in the session and print it on screen so the demo is testable
// without a mail server.
if (!isset($_SESSION['otp_code'])) {
    $_SESSION['otp_code'] = (string) random_int(100000, 999999);
    logAction($pdo, 'OTP_SENT', "OTP issued to '{$user['username']}' after impossible-travel alert");
}

// --- Verify the submitted code -----------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $entered = trim($_POST['otp'] ?? '');

    // hash_equals: constant-time compare, avoids timing side-channels.
    if (hash_equals($_SESSION['otp_code'], $entered)) {
        // Clear the flag — the account can log in normally again.
        $clear = $pdo->prepare("UPDATE users SET security_status = 'ok' WHERE id = ?");
        $clear->execute([$user['id']]);

        logAction($pdo, 'OTP_VERIFIED', "User '{$user['username']}' cleared the security alert");

        unset($_SESSION['otp_pending_user'], $_SESSION['otp_code']);
        $info = 'Identity verified. You can now log in again.';
    } else {
        $error = 'Incorrect code. Please try again.';
        logAction($pdo, 'OTP_FAILED', "Bad OTP entered for '{$user['username']}'");
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Security Alert</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<h3>⚠ Security Alert: Unusual Sign-In Location</h3>

<p>
    We detected a sign-in to <strong><?= htmlspecialchars($user['username']) ?></strong>
    from a location that is physically impossible to reach in the time since the
    last sign-in (an "impossible travel" anomaly). For your protection, access has
    been suspended until you verify your identity.
</p>

<?php if ($info): ?>
    <p><?= htmlspecialchars($info) ?> <a href="login.php">Back to login</a></p>
<?php else: ?>

    <!-- DEMO ONLY: a real system emails this code instead of showing it. -->
    <p style="border:1px dashed #999; padding:8px;">
        <em>Demo mode — your verification code is:</em>
        <strong><?= htmlspecialchars($_SESSION['otp_code']) ?></strong>
    </p>

    <?php if ($error): ?>
        <p><?= htmlspecialchars($error) ?></p>
    <?php endif; ?>

    <form method="POST">
        Enter the 6-digit code:
        <input type="text" name="otp" inputmode="numeric" pattern="[0-9]{6}" required autofocus>
        <button type="submit">Verify</button>
    </form>
<?php endif; ?>

</body>
</html>
