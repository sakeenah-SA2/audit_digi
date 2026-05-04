<?php
session_start();
require 'db.php';
require 'logger.php';

if (isset($_SESSION['user_id'])) {
    logAction($pdo, 'LOGOUT', "User '{$_SESSION['username']}' logged out");
}

session_destroy();
header('Location: login.php');
exit;
?>