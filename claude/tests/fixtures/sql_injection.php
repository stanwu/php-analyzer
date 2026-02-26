<?php
// TEST FIXTURE: demonstrates SQL injection vulnerability patterns

$id = $_GET['id'];
$result = $db->query("SELECT * FROM users WHERE id = " . $id);

$name = $_POST['username'];
$result2 = $db->query("SELECT * FROM accounts WHERE name = '" . $name . "'");

// Also raw execute with unsanitized input
$db->execute("DELETE FROM sessions WHERE token = " . $_REQUEST['token']);
