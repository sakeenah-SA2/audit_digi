<?php
function logAction($pdo, $action, $details = '') {
    $userId   = $_SESSION['user_id']  ?? null;
    $username = $_SESSION['username'] ?? 'guest';
    $ip       = $_SERVER['REMOTE_ADDR'] ?? '';

    $stmt = $pdo->prepare("
        INSERT INTO audit_logs (user_id, username, action, details, ip_address)
        VALUES (?, ?, ?, ?, ?)
    ");
    $stmt->execute([$userId, $username, $action, $details, $ip]);
}
?>