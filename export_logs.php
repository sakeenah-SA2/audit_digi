<?php
session_start();
require 'db.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit;
}

$logs = $pdo->query("SELECT * FROM audit_logs ORDER BY created_at DESC")->fetchAll();

// Send CSV headers
$filename = 'audit_logs_' . date('Y-m-d_His') . '.csv';
header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="' . $filename . '"');

$output = fopen('php://output', 'w');

// Column headings
fputcsv($output, ['ID', 'User', 'Action', 'Details', 'Time']);

// Rows
foreach ($logs as $log) {
    fputcsv($output, [
        $log['id'],
        $log['username'] ?? 'guest',
        $log['action'],
        $log['details'],
        $log['created_at']
    ]);
}

fclose($output);
exit;
?>