<?php
session_start();
require 'db.php';
require 'logger.php';
require 'geo.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // Pull the account (prepared statement = no SQL injection).
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    // Use native DateTime objects throughout so we compare real moments
    // in time, not fragile string comparisons.
    $now = new DateTime();

    if (!$user) {
        // Unknown username. Keep the message generic so we don't tell an
        // attacker which usernames exist.
        $error = 'Invalid username or password';
        logAction($pdo, 'LOGIN_FAILED', "Failed login attempt for '$username'");

    } elseif ($user['locked_until'] !== null && $now < new DateTime($user['locked_until'])) {
        // ---- STEP 1: Refuse locked accounts BEFORE touching the password. ----
        // This is the core of brute-force defence: once locked, every attempt
        // is rejected cheaply without giving the attacker another password guess.
        $lockedUntil = new DateTime($user['locked_until']);
        $remaining   = $now->diff($lockedUntil);           // DateInterval
        $minutes     = ($remaining->days * 24 * 60) + ($remaining->h * 60) + $remaining->i + 1;

        $error = "Account locked. Try again in about {$minutes} minute(s).";
        logAction($pdo, 'LOGIN_LOCKED', "Login blocked for '$username' (still locked)");

    } elseif ($password === $user['password']) {
        // ---- STEP 2 (success): correct password. Reset the counter. ----
        // NOTE: plaintext comparison by request (demo only — not for production).
        // A successful login clears the failure streak and any expired lock so
        // legitimate users never carry penalties forward.
        $reset = $pdo->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?");
        $reset->execute([$user['id']]);

        // If a prior anomaly already flagged this account, it stays gated until
        // OTP verification clears it — a correct password alone isn't enough.
        if ($user['security_status'] === 'otp_required') {
            logAction($pdo, 'LOGIN_BLOCKED_OTP', "User '{$user['username']}' must clear OTP after a security alert");
            $_SESSION = [];
            session_regenerate_id(true);
            $_SESSION['otp_pending_user'] = $user['id'];   // remember who, nothing else
            header('Location: security-alert.php');
            exit;
        }

        // ---- GEOLOCATION / IMPOSSIBLE-TRAVEL CHECK ----
        $ip      = $_SERVER['REMOTE_ADDR'] ?? '';
        $geo     = geoLookup($ip);                                  // graceful on API failure
        $anomaly = detectImpossibleTravel($pdo, (int) $user['id'], $geo);

        if (!empty($anomaly['anomaly'])) {
            // Impossible travel: do NOT grant access. Record the suspicious
            // location for forensics, flag the account for OTP, and tear the
            // session down so no half-authenticated state survives.
            recordLogin($pdo, (int) $user['id'], $ip, $geo);

            $flag = $pdo->prepare("UPDATE users SET security_status = 'otp_required' WHERE id = ?");
            $flag->execute([$user['id']]);

            logAction($pdo, 'IMPOSSIBLE_TRAVEL',
                "Anomaly for '{$user['username']}': {$anomaly['from']} -> {$anomaly['to']}, "
                . "{$anomaly['distance_km']}km in {$anomaly['hours']}h = {$anomaly['speed_kmh']} km/h");

            $_SESSION = [];
            session_destroy();
            session_start();                          // fresh, anonymous session
            session_regenerate_id(true);
            $_SESSION['otp_pending_user'] = $user['id'];

            header('Location: security-alert.php');
            exit;
        }

        // No anomaly: record this location, then log the user in normally.
        recordLogin($pdo, (int) $user['id'], $ip, $geo);

        // Prevent session fixation: issue a fresh session ID on privilege change.
        session_regenerate_id(true);
        $_SESSION['user_id']  = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role']     = $user['role'];

        logAction($pdo, 'LOGIN', "User '{$user['username']}' logged in from {$geo['city']}, {$geo['country']}");
        header('Location: dashboard.php');
        exit;

    } else {
        // ---- STEP 3 (failure): wrong password. Increment + adaptive backoff. ----
        $attempts = (int) $user['failed_attempts'] + 1;

        // Exponential-style backoff. We use switch(true) so the thresholds also
        // cover the "in-between" counts (e.g. 4 still gets the 3-failure penalty,
        // 6 gets the 5-failure penalty) instead of leaving gaps.
        $lockMinutes = 0;
        switch (true) {
            case $attempts > 7:        // 8+ failures  -> 24 hours
                $lockMinutes = 24 * 60;
                break;
            case $attempts === 7:      // 7 failures   -> 2 hours
                $lockMinutes = 2 * 60;
                break;
            case $attempts >= 5:       // 5-6 failures -> 15 minutes
                $lockMinutes = 15;
                break;
            case $attempts >= 3:       // 3-4 failures -> 1 minute
                $lockMinutes = 1;
                break;
            default:                   // 1-2 failures -> no lock yet
                $lockMinutes = 0;
        }

        // Build the lockout expiry as a real DateTime, then format for storage.
        $lockedUntil = null;
        if ($lockMinutes > 0) {
            $lockedUntil = (clone $now)
                ->add(new DateInterval("PT{$lockMinutes}M"))
                ->format('Y-m-d H:i:s');
        }

        $update = $pdo->prepare("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?");
        $update->execute([$attempts, $lockedUntil, $user['id']]);

        $error = 'Invalid username or password';
        if ($lockMinutes > 0) {
            $error .= " — account locked for {$lockMinutes} minute(s) after {$attempts} failed attempts.";
        }
        logAction($pdo, 'LOGIN_FAILED', "Failed login for '$username' (attempt #$attempts)");
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<h3>Login</h3>

<?php if ($error): ?>
    <p><?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<form method="POST">
    Username: <input type="text" name="username" required><br><br>
    Password: <input type="password" name="password" required><br><br>

    <?php if (isGeoMockMode()): ?>
        <!-- DEMO ONLY: lets you simulate where you're "logging in from" so the
             impossible-travel detector can be tested on localhost. Hidden
             automatically once GEO_MOCK_MODE is off. -->
        Simulate location:
        <select name="mock_loc">
            <?php $picked = $_REQUEST['mock_loc'] ?? 'lagos'; ?>
            <?php foreach (geoMockLocations() as $key => $loc): ?>
                <option value="<?= htmlspecialchars($key) ?>"
                    <?= $key === $picked ? 'selected' : '' ?>>
                    <?= htmlspecialchars($loc['city'] . ', ' . $loc['country']) ?>
                </option>
            <?php endforeach; ?>
        </select><br><br>
    <?php endif; ?>

    <button type="submit">Login</button>
</form>

<p><a href="register.php">Create an account</a></p>

</body>
</html>
