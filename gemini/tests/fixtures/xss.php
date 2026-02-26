<?php
echo $_GET['username'];
echo $_POST['comment'];
echo $_REQUEST['redirect_url'];
header('Location: ' . $_GET['return_to']);
