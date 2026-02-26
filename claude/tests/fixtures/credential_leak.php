<?php
// WARNING: This is a TEST FIXTURE only — credentials are fake placeholders

define('STRIPE_SECRET_KEY', 'sk_test_FAKE_KEY_PLACEHOLDER');
define('MAILGUN_API_KEY', 'FAKE_MAILGUN_KEY_00000000000000000');

$db = new MysqliDb('localhost', 'root', 'FAKE_PASSWORD_FOR_TEST', 'mydb');

$api_key = 'FAKE_KEY_1234567890abcdef';
$secret_token = 'FAKE_SECRET_TOKEN_ABCDEFGH';
