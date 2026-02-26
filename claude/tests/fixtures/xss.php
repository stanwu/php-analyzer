<?php
// TEST FIXTURE: demonstrates XSS vulnerability patterns

// Direct echo of GET/POST/COOKIE without sanitization
echo $_GET['name'];
echo $_POST['message'];
echo $_COOKIE['session_info'];
echo $_REQUEST['data'];

// Slightly more complex but still vulnerable
echo "<p>" . $_GET['title'] . "</p>";
