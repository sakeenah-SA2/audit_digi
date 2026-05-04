<?php
session_start();
require 'db.php';
require 'logger.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = $_SESSION['user_id'];

// Handle CREATE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create'])) {
    $title   = trim($_POST['title']);
    $content = trim($_POST['content']);

    $stmt = $pdo->prepare("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)");
    $stmt->execute([$userId, $title, $content]);
    $newId = $pdo->lastInsertId();

    logAction($pdo, 'CREATE_NOTE', "Created note #$newId: $title");
    header('Location: dashboard.php');
    exit;
}

// Handle UPDATE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update'])) {
    $id      = (int)$_POST['id'];
    $title   = trim($_POST['title']);
    $content = trim($_POST['content']);

    $stmt = $pdo->prepare("UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?");
    $stmt->execute([$title, $content, $id, $userId]);

    logAction($pdo, 'UPDATE_NOTE', "Updated note #$id: $title");
    header('Location: dashboard.php');
    exit;
}

// Handle DELETE
if (isset($_GET['delete'])) {
    $id = (int)$_GET['delete'];

    $stmt = $pdo->prepare("DELETE FROM notes WHERE id = ? AND user_id = ?");
    $stmt->execute([$id, $userId]);

    logAction($pdo, 'DELETE_NOTE', "Deleted note #$id");
    header('Location: dashboard.php');
    exit;
}

$stmt = $pdo->prepare("SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC");
$stmt->execute([$userId]);
$notes = $stmt->fetchAll();

$editNote = null;
if (isset($_GET['edit'])) {
    $stmt = $pdo->prepare("SELECT * FROM notes WHERE id = ? AND user_id = ?");
    $stmt->execute([(int)$_GET['edit'], $userId]);
    $editNote = $stmt->fetch();
}
?>
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>

<p>
    Logged in as: <?= htmlspecialchars($_SESSION['username']) ?>
    <?php if ($_SESSION['role'] === 'admin'): ?>
        | <a href="logs.php">View Logs</a>
    <?php endif; ?>
    | <a href="logout.php">Logout</a>
</p>

<hr>

<h3><?= $editNote ? 'Edit Note' : 'New Note' ?></h3>
<form method="POST">
    <?php if ($editNote): ?>
        <input type="hidden" name="id" value="<?= $editNote['id'] ?>">
    <?php endif; ?>
    Title: <input type="text" name="title" required
        value="<?= $editNote ? htmlspecialchars($editNote['title']) : '' ?>"><br><br>
    Content:<br>
    <textarea name="content" rows="3" cols="40"><?= $editNote ? htmlspecialchars($editNote['content']) : '' ?></textarea><br><br>
    <button type="submit" name="<?= $editNote ? 'update' : 'create' ?>">
        <?= $editNote ? 'Update' : 'Create' ?>
    </button>
    <?php if ($editNote): ?>
        <a href="dashboard.php">Cancel</a>
    <?php endif; ?>
</form>

<hr>

<h3>Your Notes</h3>
<?php if (empty($notes)): ?>
    <p>No notes yet.</p>
<?php else: ?>
    <?php foreach ($notes as $n): ?>
        <p>
            <strong><?= htmlspecialchars($n['title']) ?></strong><br>
            <?= nl2br(htmlspecialchars($n['content'])) ?><br>
            <small><?= $n['created_at'] ?></small><br>
            <a href="?edit=<?= $n['id'] ?>">Edit</a> |
            <a href="?delete=<?= $n['id'] ?>" onclick="return confirm('Delete?')">Delete</a>
        </p>
    <?php endforeach; ?>
<?php endif; ?>

</body>
</html>