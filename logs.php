<?php
session_start();
require 'db.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit;
}

$logs = $pdo->query("SELECT * FROM audit_logs ORDER BY created_at DESC")->fetchAll();
?>
<!DOCTYPE html>
<html>
<head><title>Audit Logs</title></head>
<body>

<p>
    <a href="dashboard.php">Dashboard</a> |
    <a href="logout.php">Logout</a>
</p>

<h3>Audit Logs</h3>

<p><a href="export_logs.php">Export as CSV</a></p>

<table border="1" cellpadding="5">
    <tr>
        <th>ID</th>
        <th>User</th>
        <th>Action</th>
        <th>Details</th>
        <th>Time</th>
    </tr>
    <?php if (empty($logs)): ?>
        <tr><td colspan="5">No logs found.</td></tr>
    <?php else: ?>
        <?php foreach ($logs as $log): ?>
            <tr>
                <td><?= $log['id'] ?></td>
                <td><?= htmlspecialchars($log['username'] ?? 'guest') ?></td>
                <td><?= htmlspecialchars($log['action']) ?></td>
                <td><?= htmlspecialchars($log['details']) ?></td>
                <td><?= $log['created_at'] ?></td>
            </tr>
        <?php endforeach; ?>
    <?php endif; ?>
</table>

</body>
</html>