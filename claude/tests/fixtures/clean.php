<?php
// Clean file: uses parameterized queries and proper sanitization

$id = (int) $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

$name = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');
echo $name;

$db_host = getenv('DB_HOST');
$db_pass = getenv('DB_PASSWORD');
