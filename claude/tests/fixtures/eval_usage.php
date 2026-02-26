<?php
// TEST FIXTURE: demonstrates eval and shell execution vulnerability patterns

$code = $_POST['code'];
eval($code);

// Shell execution
$output = shell_exec('ls ' . $_GET['dir']);
exec('whoami');

// Dynamic include
$page = $_GET['page'];
include($page . '.php');
require $page;
