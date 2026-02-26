<?php
$id = $_GET['id'];
$result = $db->query("SELECT * FROM users WHERE id = " . $id);

